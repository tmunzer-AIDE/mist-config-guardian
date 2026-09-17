"""Guardian monitoring replay: required checks and severity from each device's recorded monitoring session.

Monitoring already recorded a baseline, periodic SLE observations, incidents and before/after device comparisons.
The replay reads them as recorded, up to the attempt's fixed ``as_of``; the equal before/after windows govern only
Guardian's own rule and MCP queries. Stored severities and assessment transitions are never inputs.

The metric helpers restate, over plain recorded values, how ``services.impact_evidence`` derives each metric's
state and delta and how ``services.impact_analysis.assess_impact`` rates selected metrics with no incidents or
findings. The pure core cannot import that service layer, and a parity test holds the two to identical results.
"""

from collections import Counter, defaultdict
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, StringConstraints, model_validator

from mist_config_guardian_backend.guardian.contracts import (
    CORE_OWNER,
    MAX_TEXT_CHARS,
    Band,
    Conclusion,
    Contract,
    DeviceImpact,
    DeviceMac,
    EmptyPolicy,
    Evidence,
    EvidenceScope,
    EvidenceWindow,
    ExpectedDevice,
    Identifier,
    ObligationId,
    ObligationStatus,
    RulePlan,
    StatusValue,
    Target,
    Text,
    band_rank,
)
from mist_config_guardian_backend.guardian.deployment import (
    DeploymentReplay,
    DeploymentState,
    DeviceGaps,
    Precondition,
    ReplayFrame,
    provider_second,
)
from mist_config_guardian_backend.guardian.evidence import (
    MONITORING_EVIDENCE_BUDGET,
    WIDEST_EVIDENCE_ID,
    EvidenceRegistry,
    bounded,
)
from mist_config_guardian_backend.guardian.ledger import Ledger

# assess_impact's default thresholds on a metric's success-rate delta.
WARNING_DELTA = 10.0
CRITICAL_DELTA = 25.0

NO_EXPECTED_DEVICES_GAP = "No audit-linked device deployment events were observed."
NO_SESSION_REASON = "No monitoring session is linked to this audit"
SHARED_SESSION_REASON = "shared session"
ACTIVE_REASON = "monitoring still active"
NO_DEVICE_REASON = "No monitored device matches the obligation's target"
NO_DATA_REASON = "No data in either window"
DISAPPEARED_REASON = "Data disappeared after the change"
NO_BASELINE_DATA_REASON = "No before/after comparison: the baseline had no data"
NOT_COMPARABLE_REASON = "The baseline and the observation cover different scopes"

EvidenceState = Literal["measured", "no_data", "pending", "missing", "error", "unsupported", "disabled"]
DeviceStatus = Literal["satisfied", "not_exercised", "unsatisfied", "no_checks"]

_OBSERVED: frozenset[EvidenceState] = frozenset({"measured", "no_data"})
_SHARED_GAP = "Monitoring sessions shared with other audits are evidence only and set no severity floor"
_SEVERAL_GAP = "Several monitoring sessions are linked to this audit; the latest was used"
_GAP_ORDER = (_SHARED_GAP, _SEVERAL_GAP)
_SATISFIED = ObligationStatus(status="satisfied")
_NOT_EXERCISED = ObligationStatus(status="not_exercised")


# Inputs: a monitoring session as recorded ---------------------------------------------------------------------------


class SleSample(Contract):
    """One recorded SLE baseline or observation, with the fields monitoring stored for it."""

    captured_at: AwareDatetime
    scope: Literal["site", "device"] = "site"
    scope_id: str | None = None
    values: dict[str, float] = Field(default_factory=dict)
    no_data: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    requested_metrics: tuple[str, ...] = ()
    metric_errors: dict[str, str] = Field(default_factory=dict)
    metric_states: dict[str, EvidenceState] = Field(default_factory=dict)


class IncidentRecord(Contract):
    """A recorded incident. It is active until its ``resolved_at``."""

    event_type: Identifier
    occurred_at: AwareDatetime
    severity: Band
    resolved_at: AwareDatetime | None = None


class FindingRecord(Contract):
    kind: Identifier
    severity: Band


class ComparisonRecord(Contract):
    """One trigger's device comparison: initial findings from its first follow-up, current ones from its latest."""

    followup_at: AwareDatetime | None = None
    findings: tuple[FindingRecord, ...] = ()
    latest_at: AwareDatetime | None = None
    current_findings: tuple[FindingRecord, ...] | None = None


class MonitoringRecord(Contract):
    """A monitoring session as recorded; stored severities and assessment transitions are deliberately absent."""

    session_id: Identifier
    device_mac: DeviceMac
    site_id: Identifier
    device_name: Annotated[str, StringConstraints(max_length=128)] = ""
    audit_ids: tuple[Identifier, ...] = ()
    created_at: AwareDatetime
    active: bool
    completed_at: AwareDatetime | None = None
    baseline: SleSample | None = None
    observations: tuple[SleSample, ...] = ()
    incidents: tuple[IncidentRecord, ...] = ()
    comparisons: tuple[ComparisonRecord, ...] = ()


# Metric checks, as monitoring evaluates them ------------------------------------------------------------------------


class MetricCheck(Contract):
    """One metric's baseline and latest state and values, and their delta when both are measured on one scope."""

    metric: Identifier
    before: EvidenceState
    after: EvidenceState
    value_before: float | None = None
    value_after: float | None = None
    delta: float | None = None
    comparable: bool = False


def metric_check(baseline: SleSample | None, latest: SleSample | None, metric: str) -> MetricCheck:
    """A metric's states and values exactly as monitoring's evidence rows derive them."""
    before, after = _state(baseline, metric), _state(latest, metric)
    old = baseline.values.get(metric) if baseline is not None and before == "measured" else None
    new = latest.values.get(metric) if latest is not None and after == "measured" else None
    comparable = _same_scope(baseline, latest) and old is not None and new is not None
    return MetricCheck(
        metric=metric,
        before=before,
        after=after,
        value_before=old,
        value_after=new,
        delta=round(new - old, 2) if comparable and new is not None and old is not None else None,
        comparable=comparable,
    )


def check_status(check: MetricCheck, empty_policy: EmptyPolicy) -> ObligationStatus:
    """The required-check treatment table."""
    if check.before not in _OBSERVED:
        return _unsatisfied(f"The baseline is {check.before}")
    if check.after not in _OBSERVED:
        return _unsatisfied(f"The latest observation is {check.after}")
    if check.before == check.after == "measured":
        return _SATISFIED if check.comparable else _unsatisfied(NOT_COMPARABLE_REASON)
    if check.before == check.after == "no_data":
        return _NOT_EXERCISED if empty_policy == "not_exercised" else _unsatisfied(NO_DATA_REASON)
    return _unsatisfied(DISAPPEARED_REASON if check.before == "measured" else NO_BASELINE_DATA_REASON)


def metric_severity(baseline: SleSample | None, observation: SleSample | None, metrics: Collection[str]) -> Band:
    """``assess_impact(baseline, observation, [], relevance_plan=RelevancePlan(mode="selected", metrics=…))``."""
    selected = frozenset(metrics)
    checks = [metric_check(baseline, observation, metric) for metric in sorted(selected)]
    deltas = [check.delta for check in checks if check.delta is not None]
    if any(delta <= -CRITICAL_DELTA for delta in deltas):
        return "critical"
    if any(delta <= -WARNING_DELTA for delta in deltas):
        return "warning"
    # A delta exists only for a measured pair on one scope, so coverage is complete unless a selected metric or a
    # collection error failed.
    failed = any(check.before not in _OBSERVED or check.after not in _OBSERVED for check in checks)
    for sample in (baseline, observation):
        if sample is not None:
            excluded = {error for name, error in _metric_errors(sample).items() if name not in selected}
            failed = failed or any(error not in excluded for error in sample.errors)
    return "none" if deltas and not failed else "info"


def _metric_errors(sample: SleSample) -> dict[str, str]:
    # Older collectors reported '<metric>: <error>'; discovery and general errors name no metric.
    errors = {}
    for error in sample.errors:
        name, separator, _ = error.partition(": ")
        if separator and name != "metric discovery" and name and not any(c.isspace() for c in name):
            errors[name] = error
    return errors | sample.metric_errors


def _state(sample: SleSample | None, metric: str) -> EvidenceState:
    if sample is None:
        return "pending"
    if metric in _metric_errors(sample):
        return "error"
    if metric in sample.metric_states:
        state = sample.metric_states[metric]
        return "missing" if state == "measured" and metric not in sample.values else state
    if metric in sample.values:
        return "measured"
    if metric in sample.no_data:
        return "no_data"
    return "missing"


def _same_scope(baseline: SleSample | None, latest: SleSample | None) -> bool:
    return (
        baseline is not None
        and latest is not None
        and (baseline.scope, baseline.scope_id) == (latest.scope, latest.scope_id)
    )


# The replay ---------------------------------------------------------------------------------------------------------


class ComponentSeverity(Contract):
    peak: Band
    current: Band

    @model_validator(mode="after")
    def current_within_peak(self) -> "ComponentSeverity":
        if band_rank(self.current) > band_rank(self.peak):
            msg = "A component's current severity cannot exceed its peak"
            raise ValueError(msg)
        return self


class CheckView(MetricCheck):
    """A required check with its treatment; exclusivity and terminal state are reported beside it, not in it."""

    treatment: StatusValue
    reason: Text | None = None


class DeviceMonitoring(Contract):
    """One targeted device's replay. Severity exists only for an exclusive session."""

    mac: DeviceMac
    site_id: Identifier | None = None
    name: Annotated[str, StringConstraints(max_length=128)] = ""
    session_id: Identifier | None = None
    exclusive: bool | None = None
    terminal: bool | None = None
    status: DeviceStatus
    checks: tuple[CheckView, ...] = ()
    metrics: ComponentSeverity | None = None
    incidents: ComponentSeverity | None = None
    device_state: ComponentSeverity | None = None
    peak: Band | None = None
    current: Band | None = None
    deployment: DeploymentState | None = None
    deployment_precondition: Precondition | None = None


class MonitoringReplay(Contract):
    """Every targeted device, each monitoring obligation's status and the devices it reached, and the peak/current
    over exclusive devices."""

    devices: tuple[DeviceMonitoring, ...] = ()
    statuses: dict[ObligationId, ObligationStatus] = Field(default_factory=dict)
    reach: dict[ObligationId, tuple[DeviceMac, ...]] = Field(default_factory=dict)
    peak: Band = "none"
    current: Band = "none"
    gaps: tuple[Text, ...] = ()


def replay_monitoring(  # noqa: PLR0913 - the attempt's frame, coverage inputs and recorded evidence
    sessions: Iterable[MonitoringRecord],
    *,
    frame: ReplayFrame,
    ledger: Ledger,
    plans: Mapping[str, RulePlan],
    expected: Sequence[ExpectedDevice],
    deployment: DeploymentReplay,
) -> MonitoringReplay:
    """Replay every device a plug-in obligation targets and resolve each monitoring obligation over them.

    A device's metrics come from the monitoring obligations reaching it; its incident types and finding kinds from
    the plans of every plug-in with an obligation reaching it. Sessions are this audit's, created by ``as_of``; the
    latest per device is used.
    """
    selections, reach = _selections(ledger, plans)
    linked: defaultdict[str, list[MonitoringRecord]] = defaultdict(list)
    for record in sessions:
        if frame.audit_id in record.audit_ids and record.created_at <= frame.as_of and record.device_mac in selections:
            linked[record.device_mac].append(record)
    deployed = {device.mac: device for device in deployment.devices}
    gaps = DeviceGaps(_GAP_ORDER)
    devices: list[DeviceMonitoring] = []
    per_device: dict[tuple[str, str], ObligationStatus] = {}
    for mac in sorted(selections):
        records = sorted(linked[mac], key=lambda record: (record.created_at, record.session_id))
        device, statuses = _replay_device(mac, selections[mac], records, frame, gaps)
        if (deployment_device := deployed.get(mac)) is not None:
            device = device.model_copy(
                update={
                    "deployment": deployment_device.state,
                    "deployment_precondition": deployment_device.precondition,
                }
            )
        devices.append(device)
        per_device.update({(obligation_id, mac): status for obligation_id, status in statuses.items()})

    monitoring_ids = [o.id for o in ledger.obligations if o.kind == "monitoring"]
    return MonitoringReplay(
        devices=tuple(devices),
        statuses={oid: _aggregate([(mac, per_device[oid, mac]) for mac in reach[oid]]) for oid in monitoring_ids},
        reach={oid: reach[oid] for oid in monitoring_ids},
        # Only exclusive devices carry severity, so no shared session can set a floor.
        peak=_worst(device.peak for device in devices if device.peak is not None),
        current=_worst(device.current for device in devices if device.current is not None),
        gaps=(() if expected else (NO_EXPECTED_DEVICES_GAP,)) + gaps.texts(),
    )


@dataclass
class _Selection:
    """What a device's obligations select: metric checks with their obligations' policies, incidents and findings."""

    site_id: str | None = None
    checks: defaultdict[str, list[tuple[str, EmptyPolicy]]] = field(default_factory=lambda: defaultdict(list))
    incident_types: set[str] = field(default_factory=set)
    finding_kinds: set[str] = field(default_factory=set)


def _selections(
    ledger: Ledger, plans: Mapping[str, RulePlan]
) -> tuple[defaultdict[str, _Selection], dict[str, tuple[str, ...]]]:
    """Each targeted device's selection, and the devices each plug-in obligation reaches."""
    sites: dict[str, str | None] = {}
    for row in ledger.rows:
        if row.target.device_mac is not None:
            sites.setdefault(row.target.device_mac, row.target.site_id)
    owners: defaultdict[str, set[str]] = defaultdict(set)
    for plugin, ids in ledger.plan_ids.items():
        for global_id in ids.values():
            owners[global_id].add(plugin)
    selections: defaultdict[str, _Selection] = defaultdict(_Selection)
    reach: dict[str, tuple[str, ...]] = {}
    for obligation in (o for o in ledger.obligations if o.owner != CORE_OWNER):
        reach[obligation.id] = _reach(obligation.target, sites)
        for mac in reach[obligation.id]:
            selection = selections[mac]
            selection.site_id = selection.site_id or sites.get(mac) or obligation.target.site_id
            for plugin in owners[obligation.id]:
                selection.incident_types.update(plans[plugin].incident_types if plugin in plans else ())
                selection.finding_kinds.update(plans[plugin].finding_kinds if plugin in plans else ())
            if obligation.kind == "monitoring" and obligation.metric and obligation.empty_policy:
                selection.checks[obligation.metric].append((obligation.id, obligation.empty_policy))
    return selections, reach


def _reach(target: Target, sites: Mapping[str, str | None]) -> tuple[str, ...]:
    """The ledger's targeting rule: a device target reaches its device unless it names another site of that row; a
    site target with no device reaches every row device at that site."""
    if target.device_mac is not None:
        elsewhere = (
            target.device_mac in sites and target.site_id is not None and sites[target.device_mac] != target.site_id
        )
        return () if elsewhere else (target.device_mac,)
    if target.site_id is not None:
        return tuple(mac for mac, site in sorted(sites.items()) if site == target.site_id)
    return ()


def _replay_device(
    mac: str, selection: _Selection, records: list[MonitoringRecord], frame: ReplayFrame, gaps: DeviceGaps
) -> tuple[DeviceMonitoring, dict[str, ObligationStatus]]:
    record = records[-1] if records else None
    if len(records) > 1:
        gaps.add(_SEVERAL_GAP, mac)
    observations = [o for o in record.observations if o.captured_at <= frame.as_of] if record is not None else []
    baseline = record.baseline if record is not None else None
    latest = observations[-1] if observations else None
    exclusive = record is not None and record.audit_ids == (frame.audit_id,)
    terminal = (
        record is not None and not record.active and (record.completed_at is None or record.completed_at <= frame.as_of)
    )
    if record is None:
        session_reason: str | None = NO_SESSION_REASON
    elif not exclusive:
        gaps.add(_SHARED_GAP, mac)
        session_reason = SHARED_SESSION_REASON
    else:
        session_reason = None if terminal else ACTIVE_REASON

    statuses: dict[str, ObligationStatus] = {}
    views = []
    for metric, requirements in sorted(selection.checks.items()):
        check = metric_check(baseline, latest, metric)
        for obligation_id, policy in requirements:
            statuses[obligation_id] = (
                _unsatisfied(session_reason) if session_reason is not None else check_status(check, policy)
            )
        strictest: EmptyPolicy = "incomplete" if any(p == "incomplete" for _, p in requirements) else "not_exercised"
        treatment = check_status(check, strictest)
        views.append(CheckView(**check.model_dump(), treatment=treatment.status, reason=treatment.reason))

    device = DeviceMonitoring(
        mac=mac,
        site_id=selection.site_id or (record.site_id if record is not None else None),
        name=record.device_name if record is not None else "",
        session_id=record.session_id if record is not None else None,
        exclusive=None if record is None else exclusive,
        terminal=None if record is None else terminal,
        status=_device_status(statuses.values()),
        checks=tuple(views),
    )
    if record is None or not exclusive:
        return device, statuses
    components = {
        "metrics": _metric_component(baseline, observations, selection),
        "incidents": _incident_component(record, selection, frame),
        "device_state": _device_state_component(record, selection, frame),
    }
    present = [component for component in components.values() if component is not None]
    return device.model_copy(
        update={
            **components,
            "peak": _worst(component.peak for component in present),
            "current": _worst(component.current for component in present),
        }
    ), statuses


def _metric_component(
    baseline: SleSample | None, observations: list[SleSample], selection: _Selection
) -> ComponentSeverity | None:
    """Peak over every observation through ``as_of``; current from the final one."""
    if not selection.checks or not observations:
        return None
    bands = [metric_severity(baseline, observation, selection.checks) for observation in observations]
    return ComponentSeverity(peak=max(bands, key=band_rank), current=bands[-1])


def _incident_component(
    record: MonitoringRecord, selection: _Selection, frame: ReplayFrame
) -> ComponentSeverity | None:
    """Peak over relevant incidents since the change; current over those still unresolved at ``as_of``."""
    if not selection.incident_types:
        return None
    start = provider_second(frame.anchor.changed_at)
    relevant = [
        incident
        for incident in record.incidents
        if incident.event_type in selection.incident_types and start <= incident.occurred_at <= frame.as_of
    ]
    active = [incident for incident in relevant if incident.resolved_at is None or incident.resolved_at > frame.as_of]
    return ComponentSeverity(peak=_worst(i.severity for i in relevant), current=_worst(i.severity for i in active))


def _device_state_component(
    record: MonitoringRecord, selection: _Selection, frame: ReplayFrame
) -> ComponentSeverity | None:
    """Peak from each comparison's initial findings; current from its current findings, both as of ``as_of``.

    A comparison counts once its first follow-up is recorded. When its latest follow-up came after ``as_of``, the
    current findings at ``as_of`` were overwritten, so its initial findings stand for them. A finding that appeared
    only later still raises the peak, which is never below the current.
    """
    if not selection.finding_kinds:
        return None
    peaks: list[Band] = []
    currents: list[Band] = []
    completed = False
    for comparison in record.comparisons:
        if comparison.followup_at is None or comparison.followup_at > frame.as_of:
            continue
        completed = True
        initial = [f.severity for f in comparison.findings if f.kind in selection.finding_kinds]
        recorded = comparison.current_findings
        if comparison.latest_at is None or comparison.latest_at > frame.as_of or recorded is None:
            current = initial
        else:
            current = [f.severity for f in recorded if f.kind in selection.finding_kinds]
        peaks += [*initial, *current]
        currents += current
    return ComponentSeverity(peak=_worst(peaks), current=_worst(currents)) if completed else None


def _worst(bands: Iterable[Band]) -> Band:
    return max(bands, key=band_rank, default="none")


def _unsatisfied(reason: str) -> ObligationStatus:
    bounded_reason = reason if len(reason) <= MAX_TEXT_CHARS else f"{reason[: MAX_TEXT_CHARS - 1]}…"
    return ObligationStatus(status="unsatisfied", reason=bounded_reason)


def _device_status(statuses: Iterable[ObligationStatus]) -> DeviceStatus:
    values = [status.status for status in statuses]
    if not values:
        return "no_checks"
    if "unsatisfied" in values:
        return "unsatisfied"
    return "not_exercised" if all(value == "not_exercised" for value in values) else "satisfied"


def _aggregate(results: Sequence[tuple[str, ObligationStatus]]) -> ObligationStatus:
    """An obligation over the devices it reaches: unsatisfied if any is, not exercised only if all are."""
    if not results:
        return _unsatisfied(NO_DEVICE_REASON)
    if len(results) == 1:
        return results[0][1]
    failing = [(mac, status) for mac, status in results if status.status == "unsatisfied"]
    if failing:
        mac, first = failing[0]
        more = len(failing) - 1
        return _unsatisfied(f"{first.reason} on {mac}" + (f" and {more} more device(s)" if more else ""))
    if all(status.status == "not_exercised" for _, status in results):
        return _NOT_EXERCISED
    return _SATISFIED


# Evidence -----------------------------------------------------------------------------------------------------------


class MonitoringEvidence(Contract):
    """The monitoring source's evidence: full device items and, when some devices did not fit, one digest."""

    items: tuple[Evidence, ...] = ()
    digest: Evidence | None = None


def record_monitoring(replay: MonitoringReplay, *, frame: ReplayFrame, registry: EvidenceRegistry) -> Conclusion:
    """Record full device items in priority order within the monitoring budget, then one digest counting the rest,
    and conclude with every status and impacted device citing its devices' items.

    Priority: severity of warning or above (worst first), then devices with an unsatisfied obligation, then the
    rest. Statuses are the replay's own: the budget decides what is shown, never coverage.
    """
    view = bounded(
        replay.devices,
        budget=MONITORING_EVIDENCE_BUDGET,
        priority=_priority,
        category=_category,
        build=lambda kept, omitted: MonitoringEvidence(
            items=tuple(_device_item(device, frame) for device in kept),
            digest=_digest(omitted, frame) if omitted else None,
        ),
    )
    cited: dict[str, str] = {}
    for item in view.items:
        cited[item.scope.device_macs[0]] = registry.record(
            item.model_copy(update={"id": registry.reserve("monitoring")})
        ).id
    if view.digest is not None:
        digest_id = registry.record(view.digest.model_copy(update={"id": registry.reserve("monitoring")})).id
        cited.update({device.mac: digest_id for device in replay.devices if device.mac not in cited})

    def evidence_ids(macs: Iterable[str]) -> tuple[str, ...]:
        return tuple(sorted({cited[mac] for mac in macs if mac in cited}, key=lambda eid: int(eid[1:])))

    impacted = sorted(
        (d for d in replay.devices if d.peak is not None and band_rank(d.peak) >= band_rank("warning")),
        key=lambda d: (-band_rank(d.peak or "none"), d.mac),
    )
    return Conclusion(
        statuses={
            oid: status.model_copy(update={"evidence_ids": evidence_ids(replay.reach.get(oid, ()))})
            for oid, status in replay.statuses.items()
        },
        peak=replay.peak,
        current=replay.current,
        impacted_devices=tuple(
            DeviceImpact(mac=d.mac, severity=d.peak or "none", evidence_ids=evidence_ids((d.mac,))) for d in impacted
        ),
        gaps=replay.gaps,
    )


def _priority(device: DeviceMonitoring) -> tuple[int, bool, str]:
    """Warning or above (worst first), then an unsatisfied obligation, then the rest; below warning, bands tie."""
    rank = band_rank(device.peak or "none")
    return (-rank if rank >= band_rank("warning") else 0, device.status != "unsatisfied", device.mac)


def _category(device: DeviceMonitoring) -> str:
    return f"{device.status}:{device.peak or 'unassessed'}"


def _device_item(device: DeviceMonitoring, frame: ReplayFrame) -> Evidence:
    return Evidence(
        id=WIDEST_EVIDENCE_ID,
        source="monitoring",
        kind="service_health",
        title=f"Monitoring {device.name or device.mac}",
        captured_at=frame.as_of,
        window=_window(frame),
        scope=EvidenceScope(site_ids=() if device.site_id is None else (device.site_id,), device_macs=(device.mac,)),
        collection="complete",
        representation="full",
        payload=device.model_dump(mode="json"),
    )


def _digest(counts: Mapping[str, int], frame: ReplayFrame) -> Evidence:
    return Evidence(
        id=WIDEST_EVIDENCE_ID,
        source="monitoring",
        kind="service_health",
        title="Monitoring digest",
        captured_at=frame.as_of,
        window=_window(frame),
        collection="complete",
        representation="digest",
        payload={"devices": dict(Counter(counts))},
        detail="Devices beyond the monitoring evidence budget, counted by obligation status and peak severity",
    )


def _window(frame: ReplayFrame) -> EvidenceWindow | None:
    start = frame.anchor.changed_at
    return EvidenceWindow(start=start, end=frame.as_of) if start <= frame.as_of else None
