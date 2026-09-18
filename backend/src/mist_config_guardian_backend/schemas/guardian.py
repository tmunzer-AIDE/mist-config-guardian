"""API projections of Guardian roots and runs.

A summary carries status and the published result, never evidence. A run carries what the immutable run document
holds, plus the report rendered from it on read: nothing here stores a report, and nothing re-derives a verdict.
Whether a run is published is derived from the root's pointers, so it is reported rather than stored.
"""

from datetime import datetime
from typing import Literal

from pydantic import AwareDatetime, BaseModel, Field, JsonValue, model_validator

from mist_config_guardian_backend.guardian.contracts import (
    AgentConclusion,
    ChangeAtom,
    CompactImpactedDevice,
    Conclusion,
    Evidence,
    LedgerRow,
    ObligationOutcome,
    PluginId,
    RootStatus,
    RunAnchor,
    RunBudget,
    RunKind,
    RunState,
    Verdict,
)
from mist_config_guardian_backend.guardian.report import Report, render_report
from mist_config_guardian_backend.models.guardian import (
    AttemptCounts,
    GuardianInvestigation,
    GuardianResult,
    GuardianRun,
)

# A summary says whether it could be read at all. A projection that failed is ``unavailable`` and carries no status
# and no result, so a failed read can never be mistaken for a clean one.
GuardianAvailability = Literal["projected", "unavailable"]
# The one bucket a feed row falls in: no root, an unreadable projection, a pending root, or the published peak.
GuardianFeedBucket = Literal["not_recorded", "unavailable", "pending", "none", "info", "warning", "critical"]
# The run-document fields :class:`GuardianRunResponse` carries verbatim, pinned rather than derived from the
# document: a new field on a run is a decision here, never a silent addition or omission. Identity, tenancy and
# retention stay out - the organization is the caller's, and the rest is bookkeeping no reader acts on.
CARRIED_RUN_FIELDS = frozenset(
    {
        "audit_id",
        "kind",
        "attempt",
        "state",
        "started_at",
        "finished_at",
        "deadline_at",
        "failure_reason",
        "anchor",
        "as_of",
        "change",
        "evidence",
        "ledger",
        "obligations",
        "monitoring",
        "deployment",
        "rules",
        "agent",
        "verdict",
        "steps",
        "budget",
    }
)


class GuardianImpactedDevices(BaseModel):
    """A published run's compact impacted-device rows, and how many the run itself could not keep.

    The site overlay filters ``devices`` by site. ``omitted`` counts devices the run never recorded, whose site is
    therefore unknown, so filtering by site leaves it unchanged.
    """

    devices: tuple[CompactImpactedDevice, ...] = ()
    omitted: int = Field(default=0, ge=0)


class GuardianSummary(BaseModel):
    """An audit's Guardian status as change groups, the overview and site impact show it."""

    availability: GuardianAvailability = "projected"
    status: RootStatus | None = None
    status_reason: str | None = None
    result: GuardianResult | None = None
    # Present only when the caller asked for device rows and the root points at a run that recorded them.
    impacted: GuardianImpactedDevices | None = None

    @model_validator(mode="after")
    def unavailable_claims_nothing_else(self) -> "GuardianSummary":
        empty = (self.status, self.status_reason, self.result, self.impacted) == (None, None, None, None)
        if self.availability == "unavailable" and not empty:
            msg = "An unavailable projection reports no status, result or devices"
            raise ValueError(msg)
        if self.availability == "projected" and self.status is None:
            msg = "A projected summary carries the root's status"
            raise ValueError(msg)
        return self

    @classmethod
    def from_root(cls, root: GuardianInvestigation) -> "GuardianSummary":
        return cls(status=root.status, status_reason=root.status_reason, result=root.result)

    @classmethod
    def unavailable(cls) -> "GuardianSummary":
        """What a failed projection reports, in place of a result it could not read."""
        return cls(availability="unavailable")


class GuardianFeedCounts(BaseModel):
    """Mutually exclusive Guardian states over the returned feed rows, not the whole time window."""

    scope: Literal["returned_feed"] = "returned_feed"
    total: int = 0
    not_recorded: int = 0
    unavailable: int = 0
    pending: int = 0
    none: int = 0
    info: int = 0
    warning: int = 0
    critical: int = 0


class GuardianAttemptSummary(BaseModel):
    """One attempt, collapsed, with the publication state derived from the root. The full run is loaded separately."""

    id: str
    kind: RunKind
    attempt: int
    state: RunState
    failure_reason: str | None
    budget: RunBudget
    published: bool = False

    @classmethod
    def from_run(cls, run: GuardianRun, *, published: bool = False) -> "GuardianAttemptSummary":
        return cls(
            id=str(run.id),
            kind=run.kind,
            attempt=run.attempt,
            state=run.state,
            failure_reason=run.failure_reason,
            budget=run.budget,
            published=published,
        )


class GuardianRunReport(BaseModel):
    """One run as a panel tab renders it: its identity and the report built from the stored run on read."""

    id: str
    kind: RunKind
    attempt: int
    state: RunState
    published: bool = False
    report: Report

    @classmethod
    def from_run(cls, run: GuardianRun, *, published: bool = False) -> "GuardianRunReport":
        return cls(
            id=str(run.id),
            kind=run.kind,
            attempt=run.attempt,
            state=run.state,
            published=published,
            report=render_report(run),
        )


class GuardianRunResponse(GuardianRunReport):
    """One full run document, bounded by construction, with its rendered report.

    Everything below the identity is passed through as the run recorded it, including evidence payloads and the
    agent's steps, which the report's attempts section expands.
    """

    investigation_id: str
    audit_id: str
    started_at: AwareDatetime
    finished_at: AwareDatetime | None = None
    deadline_at: AwareDatetime | None = None
    failure_reason: str | None = None
    anchor: RunAnchor | None = None
    as_of: AwareDatetime | None = None
    change: tuple[ChangeAtom, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    ledger: tuple[LedgerRow, ...] = ()
    obligations: tuple[ObligationOutcome, ...] = ()
    monitoring: Conclusion | None = None
    deployment: Conclusion | None = None
    rules: dict[PluginId, Conclusion] = Field(default_factory=dict)
    agent: AgentConclusion | None = None
    verdict: Verdict | None = None
    steps: tuple[dict[str, JsonValue], ...] = ()
    budget: RunBudget

    @classmethod
    def from_run(cls, run: GuardianRun, *, published: bool = False) -> "GuardianRunResponse":
        return cls(
            id=str(run.id),
            investigation_id=str(run.investigation_id),
            published=published,
            report=render_report(run),
            **run.model_dump(include=set(CARRIED_RUN_FIELDS)),
        )


class GuardianRootResponse(BaseModel):
    """The small root itself: identity, trigger timing, attempt counters, run pointers and the published result."""

    id: str
    audit_id: str
    changed_at: datetime
    anchor_known: bool
    status: RootStatus
    status_reason: str | None = None
    next_check_at: datetime | None = None
    attempts: AttemptCounts
    early_run_id: str | None = None
    final_run_id: str | None = None
    result: GuardianResult | None = None

    @classmethod
    def from_root(cls, root: GuardianInvestigation) -> "GuardianRootResponse":
        return cls(
            id=str(root.id),
            audit_id=root.audit_id,
            changed_at=root.changed_at,
            anchor_known=root.anchor_known,
            status=root.status,
            status_reason=root.status_reason,
            next_check_at=root.next_check_at,
            attempts=root.attempts,
            early_run_id=None if root.early_run_id is None else str(root.early_run_id),
            final_run_id=None if root.final_run_id is None else str(root.final_run_id),
            result=root.result,
        )


class GuardianInvestigationResponse(BaseModel):
    """One audit's investigation: the root, the runs it published, and every attempt it consumed."""

    root: GuardianRootResponse
    runs: list[GuardianRunReport] = Field(default_factory=list)
    attempts: list[GuardianAttemptSummary] = Field(default_factory=list)
    # Attempts whose stored run this build could not read, and which are therefore absent from both lists above.
    # Counted rather than dropped in silence, so the panel can say an attempt exists that it cannot show.
    unreadable_attempts: int = Field(default=0, ge=0)
