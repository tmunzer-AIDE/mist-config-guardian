"""Guardian's API-neutral contracts: severity bands, evidence, obligations, conclusions and verdicts.

The pure domain functions, the persistence models and the API projections all share these shapes. The module imports
nothing from Beanie, PyMongo or any transport, so tests of the pure core stay fast. Every contract is frozen and
closed, and validates the cross-field invariants the design states rather than leaving them to callers.
"""

import re
from datetime import timedelta
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, JsonValue, StringConstraints, model_validator

# Limits from the design's "Limits" table that persistence and scheduling rely on. Byte budgets for individual
# evidence sources belong to the evidence registry.
LEASE = timedelta(seconds=300)
ATTEMPT_DEADLINE = timedelta(seconds=240)
RECHECK_DELAY = timedelta(minutes=1)
EARLY_CUTOFF = timedelta(minutes=45)
FINAL_MINIMUM = timedelta(minutes=60)
FINAL_FORCED = timedelta(minutes=120)
MAX_ATTEMPTS_PER_KIND = 2
MAX_MODEL_TURNS = 10
MAX_MCP_CALLS = 7
MAX_RULE_READS = 8
MAX_ROOT_IMPACTED_DEVICES = 20
RUN_DOCUMENT_MAX_BYTES = 256_000

MAX_REASON_CHARS = 300
MAX_STATUS_REASON_CHARS = 400
MAX_TEXT_CHARS = 500
MAX_SUMMARY_CHARS = 2_000
MAX_DETAIL_CHARS = 1_000
MAX_IDENTIFIER_CHARS = 128

Band = Literal["none", "info", "warning", "critical"]
BANDS: tuple[Band, ...] = ("none", "info", "warning", "critical")
Coverage = Literal["complete", "partial", "insufficient", "not_applicable"]
Recovery = Literal["none", "recovered", "unrecovered"]
Confidence = Literal["low", "medium"]
RunKind = Literal["early", "final"]
RunState = Literal["running", "succeeded", "failed", "abandoned"]
TERMINAL_RUN_STATES: frozenset[RunState] = frozenset({"succeeded", "failed", "abandoned"})
FAILED_RUN_STATES: frozenset[RunState] = frozenset({"failed", "abandoned"})
RootStatus = Literal["waiting", "done"]

EvidenceKind = Literal["service_health", "deployment", "configuration", "reference"]
EvidenceCollection = Literal["complete", "partial", "error"]
EvidenceRepresentation = Literal["full", "digest"]
ObligationRole = Literal["precondition", "observation"]
ObligationKind = Literal["anchor", "deployment", "monitoring", "rule"]
EmptyPolicy = Literal["not_exercised", "incomplete"]
StatusValue = Literal["satisfied", "not_exercised", "unsatisfied"]
LedgerResolution = Literal["claimed", "excluded", "uncovered"]
AnchorSource = Literal["audit", "device_trigger", "receipt"]
DeviceType = Literal["ap", "switch", "gateway"]

CORE_OWNER = "core"
CORE_OBLIGATION_KINDS: frozenset[ObligationKind] = frozenset({"anchor", "deployment"})

_PLUGIN = r"[a-z][a-z0-9-]{0,39}"
EvidenceId = Annotated[str, StringConstraints(pattern=r"^E[1-9][0-9]{0,5}$")]
ObligationId = Annotated[str, StringConstraints(pattern=r"^O[1-9][0-9]{0,5}$")]
AtomId = Annotated[str, StringConstraints(pattern=r"^A[1-9][0-9]{0,5}$")]
PluginId = Annotated[str, StringConstraints(pattern=rf"^{_PLUGIN}$")]
EvidenceSource = Annotated[
    str, StringConstraints(pattern=rf"^(monitoring|deployment|rule:{_PLUGIN}|mcp:[a-z][a-z0-9_]{{0,63}})$")
]
VerdictSource = Annotated[str, StringConstraints(pattern=rf"^(monitoring|deployment|agent|rule:{_PLUGIN})$")]
GapSource = Annotated[str, StringConstraints(pattern=rf"^(core|monitoring|deployment|agent|rule:{_PLUGIN})$")]
DeviceMac = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{12}$")]
Identifier = Annotated[str, StringConstraints(min_length=1, max_length=MAX_IDENTIFIER_CHARS)]
PathSegment = Annotated[str, StringConstraints(min_length=1, max_length=MAX_IDENTIFIER_CHARS)]
ConfigPath = Annotated[tuple[PathSegment, ...], Field(min_length=1)]
Text = Annotated[str, StringConstraints(min_length=1, max_length=MAX_TEXT_CHARS)]
Summary = Annotated[str, StringConstraints(max_length=MAX_SUMMARY_CHARS)]
# A stored failure reason is one bounded line: no control characters, so it renders and logs safely.
SafeReason = Annotated[
    str, StringConstraints(min_length=1, max_length=MAX_REASON_CHARS, pattern=r"^[^\x00-\x1f\x7f]+$")
]
StatusReason = Annotated[
    str, StringConstraints(min_length=1, max_length=MAX_STATUS_REASON_CHARS, pattern=r"^[^\x00-\x1f\x7f]+$")
]

_UNSAFE_RUN = re.compile(r"[\x00-\x1f\x7f\s]+")


def band_rank(band: Band) -> int:
    """Position in the severity order ``none < info < warning < critical``."""
    return BANDS.index(band)


def recovery_for(peak: Band, current: Band) -> Recovery:
    """Recovery follows from the published peak and current alone."""
    if band_rank(current) >= band_rank("warning"):
        return "unrecovered"
    if band_rank(peak) >= band_rank("warning"):
        return "recovered"
    return "none"


def bound_reason(text: str) -> str:
    """Collapse control characters and whitespace, and truncate, so any failure text fits a stored reason."""
    collapsed = _UNSAFE_RUN.sub(" ", text).strip()
    if len(collapsed) > MAX_REASON_CHARS:
        collapsed = collapsed[: MAX_REASON_CHARS - 1].rstrip() + "…"
    return collapsed or "Unspecified failure"


def _require_ordered(peak: Band, current: Band) -> None:
    if band_rank(current) > band_rank(peak):
        msg = f"current ({current}) cannot exceed peak ({peak})"
        raise ValueError(msg)


def validate_published_verdict(peak: Band, current: Band, recovery: Recovery, coverage: Coverage) -> None:
    """Invariants shared by a run's verdict and the root's published result."""
    _require_ordered(peak, current)
    if recovery != recovery_for(peak, current):
        msg = f"Recovery must be {recovery_for(peak, current)} for peak {peak} and current {current}"
        raise ValueError(msg)
    # Composition's base is info unless deterministic coverage is complete, so none needs complete coverage.
    if current == "none" and coverage != "complete":
        msg = "Only complete deterministic coverage can publish none"
        raise ValueError(msg)


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Target(Contract):
    device_mac: DeviceMac | None = None
    site_id: Identifier | None = None
    port_id: Identifier | None = None
    wlan_id: Identifier | None = None


class ExpectedDevice(Contract):
    """A device with an audit-linked deployment trigger: an applicable target of every org- and site-level atom.

    ``device_type`` is the family the provider's own trigger event named (``AP_``/``SW_``/``GW_``), so a plug-in whose
    mapping applies to one family can target that family alone. It is ``None`` when no trigger established it, and a
    family-scoped plug-in then leaves that device's rows uncovered rather than guessing.
    """

    mac: DeviceMac
    site_id: Identifier
    device_type: DeviceType | None = None


class Obligation(Contract):
    """Something coverage needs resolved. Anchor and deployment preconditions are core-owned."""

    id: ObligationId
    owner: PluginId
    change_ref: AtomId | None = None
    paths: tuple[ConfigPath, ...] = ()
    role: ObligationRole
    kind: ObligationKind
    target: Target
    metric: Identifier | None = None
    empty_policy: EmptyPolicy | None = None

    @model_validator(mode="after")
    def role_follows_kind(self) -> "Obligation":
        if self.kind in CORE_OBLIGATION_KINDS:
            if self.owner != CORE_OWNER or self.role != "precondition":
                msg = f"{self.kind} obligations are core-owned preconditions"
                raise ValueError(msg)
        else:
            if self.role != "observation":
                msg = f"{self.kind} obligations are observations"
                raise ValueError(msg)
            if self.change_ref is None or not self.paths:
                msg = f"{self.kind} obligations name the change atom and paths they claim"
                raise ValueError(msg)
        if self.kind == "monitoring" and (self.metric is None or self.empty_policy is None):
            msg = "Monitoring obligations name a metric and an empty policy"
            raise ValueError(msg)
        if self.kind != "monitoring" and self.empty_policy is not None:
            msg = "Only monitoring observations carry an empty policy"
            raise ValueError(msg)
        return self


class Exclusion(Contract):
    """Applies only to its atom, paths and target, never to a whole device."""

    owner: PluginId
    change_ref: AtomId
    paths: tuple[ConfigPath, ...] = Field(min_length=1)
    target: Target
    reason: Text


class ObligationStatus(Contract):
    status: StatusValue
    reason: Text | None = None
    evidence_ids: tuple[EvidenceId, ...] = ()

    @model_validator(mode="after")
    def reason_explains_unsatisfied(self) -> "ObligationStatus":
        if (self.status == "unsatisfied") != (self.reason is not None):
            msg = "An unsatisfied status needs a reason, and only an unsatisfied status carries one"
            raise ValueError(msg)
        return self


class RulePlan(Contract):
    obligations: tuple[Obligation, ...] = ()
    exclusions: tuple[Exclusion, ...] = ()
    incident_types: tuple[Identifier, ...] = ()
    finding_kinds: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def plugin_observations_only(self) -> "RulePlan":
        if any(obligation.kind in CORE_OBLIGATION_KINDS for obligation in self.obligations):
            msg = "A rule plan holds rule and monitoring observations only"
            raise ValueError(msg)
        ids = [obligation.id for obligation in self.obligations]
        if len(ids) != len(set(ids)):
            msg = "Obligation ids must be unique within a plan"
            raise ValueError(msg)
        return self


class EvidenceWindow(Contract):
    start: AwareDatetime
    end: AwareDatetime

    @model_validator(mode="after")
    def ordered(self) -> "EvidenceWindow":
        if self.end < self.start:
            msg = "An evidence window cannot end before it starts"
            raise ValueError(msg)
        return self


class EvidenceScope(Contract):
    site_ids: tuple[Identifier, ...] = ()
    device_macs: tuple[DeviceMac, ...] = ()


class Evidence(Contract):
    """One E-id envelope. The server owns ``kind``; payloads are validated per source before they get here."""

    id: EvidenceId
    source: EvidenceSource
    kind: EvidenceKind
    title: Text
    captured_at: AwareDatetime
    window: EvidenceWindow | None = None
    scope: EvidenceScope = EvidenceScope()
    collection: EvidenceCollection
    representation: EvidenceRepresentation
    payload: dict[str, JsonValue] = Field(default_factory=dict)
    detail: Annotated[str, StringConstraints(max_length=MAX_DETAIL_CHARS)] = ""

    @property
    def citable(self) -> bool:
        return self.collection != "error"

    @model_validator(mode="after")
    def server_owned_kind(self) -> "Evidence":
        if self.source == "monitoring" and self.kind != "service_health":
            msg = "Monitoring evidence is service_health"
            raise ValueError(msg)
        if (self.source == "deployment") != (self.kind == "deployment"):
            msg = "Deployment evidence, and only deployment evidence, is kind deployment"
            raise ValueError(msg)
        if self.collection == "error" and not self.detail:
            msg = "Error evidence carries its error text"
            raise ValueError(msg)
        return self


class Finding(Contract):
    text: Text
    severity: Band
    evidence_ids: tuple[EvidenceId, ...] = ()


class DeviceImpact(Contract):
    mac: DeviceMac
    severity: Band
    evidence_ids: tuple[EvidenceId, ...] = ()


class Conclusion(Contract):
    """A deterministic source's conclusion: monitoring replay, deployment pairing or one rule plug-in."""

    statuses: dict[ObligationId, ObligationStatus] = Field(default_factory=dict)
    peak: Band = "none"
    current: Band = "none"
    findings: tuple[Finding, ...] = ()
    impacted_devices: tuple[DeviceImpact, ...] = ()
    gaps: tuple[Text, ...] = ()

    @model_validator(mode="after")
    def bands_within_peak(self) -> "Conclusion":
        _require_ordered(self.peak, self.current)
        if any(band_rank(device.severity) > band_rank(self.peak) for device in self.impacted_devices):
            msg = "No impacted device can exceed the conclusion's peak"
            raise ValueError(msg)
        return self


# The design's RuleConclusion; monitoring and deployment conclusions share its shape.
RuleConclusion = Conclusion


class AgentConclusion(Contract):
    """An accepted agent report, or the reason the agent did not conclude or was skipped."""

    concluded: bool
    reason: SafeReason | None = None
    peak: Band | None = None
    current: Band | None = None
    confidence: Confidence | None = None
    summary: Summary = ""
    evidence_ids: tuple[EvidenceId, ...] = ()
    findings: tuple[Finding, ...] = ()
    impacted_devices: tuple[DeviceImpact, ...] = ()
    gaps: tuple[Text, ...] = ()

    @model_validator(mode="after")
    def report_or_reason(self) -> "AgentConclusion":
        if not self.concluded:
            if self.reason is None or any(v is not None for v in (self.peak, self.current, self.confidence)):
                msg = "An agent that did not conclude has a reason and no assessment"
                raise ValueError(msg)
            if self.findings or self.impacted_devices:
                msg = "An agent that did not conclude reports no findings and no impacted devices"
                raise ValueError(msg)
            return self
        if self.reason is not None or self.peak is None or self.current is None or self.confidence is None:
            msg = "An accepted agent report has peak, current and confidence and no failure reason"
            raise ValueError(msg)
        _require_ordered(self.peak, self.current)
        if any(band_rank(device.severity) > band_rank(self.peak) for device in self.impacted_devices):
            msg = "No impacted device can exceed the report's peak"
            raise ValueError(msg)
        return self


class LedgerRow(Contract):
    """One change atom on one applicable target."""

    atom_id: AtomId
    target: Target
    resolution: LedgerResolution
    obligation_ids: tuple[ObligationId, ...] = ()
    uncovered_paths: tuple[ConfigPath, ...] = ()

    @model_validator(mode="after")
    def resolution_matches_claims(self) -> "LedgerRow":
        if self.resolution != "uncovered" and self.uncovered_paths:
            msg = "Only an uncovered row lists uncovered paths"
            raise ValueError(msg)
        if self.resolution == "claimed" and not self.obligation_ids:
            msg = "A claimed row names the obligations that claim it"
            raise ValueError(msg)
        if self.resolution == "excluded" and self.obligation_ids:
            msg = "An excluded row is covered by exclusions alone"
            raise ValueError(msg)
        return self


class ObligationOutcome(Contract):
    obligation: Obligation
    status: ObligationStatus


class ChangeAtom(Contract):
    """``A<n>``: one logical object version's top-level functional attribute, as changed paths only."""

    id: AtomId
    logical_object_id: Identifier
    version: int = Field(ge=1)
    attribute: Identifier
    paths: tuple[ConfigPath, ...]
    paths_complete: bool


class RunAnchor(Contract):
    changed_at: AwareDatetime
    source: AnchorSource


class RunBudget(Contract):
    """External calls an attempt used, each capped by its per-attempt limit."""

    model_turns: int = Field(default=0, ge=0, le=MAX_MODEL_TURNS)
    mcp_calls: int = Field(default=0, ge=0, le=MAX_MCP_CALLS)
    rule_reads: int = Field(default=0, ge=0, le=MAX_RULE_READS)


class CompactImpactedDevice(Contract):
    mac: DeviceMac
    site_id: Identifier
    name: Annotated[str, StringConstraints(max_length=128)] = ""
    peak: Band
    current: Band

    @model_validator(mode="after")
    def current_within_peak(self) -> "CompactImpactedDevice":
        _require_ordered(self.peak, self.current)
        return self


class Gap(Contract):
    source: GapSource
    text: Text


class Verdict(Contract):
    """The composed result of one attempt."""

    peak: Band
    current: Band
    recovery: Recovery
    confidence: Confidence
    coverage: Coverage
    sources: tuple[VerdictSource, ...] = ()
    summary: Summary
    gaps: tuple[Gap, ...] = ()
    impacted_devices: tuple[CompactImpactedDevice, ...] = ()
    impacted_devices_omitted: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def consistent_bands(self) -> "Verdict":
        validate_published_verdict(self.peak, self.current, self.recovery, self.coverage)
        return self
