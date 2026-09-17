"""The switch port rule: a port that was administratively disabled or lost PoE, and what was attached to it.

Ported from ``impact/port_scope.py``, the port half of ``impact/domain_evaluation.py`` and the port, neighbour and
access-point evidence clients. The ported judgements are unchanged: only an exact, concrete port is resolved; an
empty or truncated event history never establishes health; contradictory events in one second cannot be ordered;
link loss needs a prior up event and PoE loss needs measured power before the change, because an enable event is
administrative state, not delivered power; and enabling PoE again never establishes restored delivery.

The neighbour is resolved the other way round from the deleted engine: instead of reading the MAC the port's LLDP
claims and then asking whether it is managed, this reads the organization's own access points and keeps the one
whose own LLDP names this switch and port. A MAC belonging to no managed access point is therefore never read,
stored or shown, and the port snapshot drops the neighbour fields before they can reach evidence.
"""

import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from mist_config_guardian_backend.guardian.change import ChangeSet
from mist_config_guardian_backend.guardian.contracts import (
    Band,
    Conclusion,
    ConfigPath,
    DeviceImpact,
    Evidence,
    ExpectedDevice,
    Finding,
    Identifier,
    Obligation,
    ObligationStatus,
    RuleConclusion,
    RulePlan,
    Target,
    band_rank,
)
from mist_config_guardian_backend.guardian.plugins import base
from mist_config_guardian_backend.guardian.reader import Reader, RuleRead

ID = "switch-port"
VERSION = "1"
MAX_READS = 3
EVENT_LIMIT = "1000"
AP_LIMIT = "50"
AP_FIELDS = "mac,type,org_id,site_id,status,last_seen,lldp_stat,lldp_stats,port_stat"
POWER_BASELINE = timedelta(minutes=5)
PORT_PATH_SEGMENTS = 3

CONTAINERS = ("port_config", "port_config_overwrite")
PORT = re.compile(r"^(ge|xe|et)-[0-9]{1,3}/[0-9]{1,3}/[0-9]{1,3}$")
# Each handled attribute with the events that describe its service and the severity losing it carries.
ATTRIBUTES: Mapping[str, tuple[str, str, Band]] = {
    "disabled": ("SW_PORT_DOWN", "SW_PORT_UP", "warning"),
    "poe_disabled": ("SW_POE_PORT_DISABLED", "SW_POE_PORT_ENABLED", "critical"),
}
EVENT_TYPES = frozenset(event for down, up, _ in ATTRIBUTES.values() for event in (down, up))
# Fields naming a device Guardian does not manage: they never reach evidence, so nothing can keep them.
NEIGHBOUR_FIELDS = ("neighbor_mac", "neighbor_chassis_id", "neighbor_port_id", "neighbor_system_name")

# Both ported playbooks, kept whole because one plug-in now answers for the link and for the power on that link.
AGENT_HINT = (
    "Investigate the exact changed port: its ordered up/down events, and its power delivery separately. Require "
    "prior active service; an empty event list cannot establish current health, and simultaneous contradictory "
    "events cannot be ordered by position. A later up event supports link recovery. Alternate paths and planned "
    "removal are counterevidence only when evidenced; do not invent VLAN, routing or forwarding dependencies. PoE "
    "enabled/disabled events describe administrative state, not a powered client: require comparable measured "
    "power, and never infer restored delivery from enablement. Inventory membership does not verify an LLDP claim, "
    "a historical physical relationship or a sole power source. Do not dismiss confirmed port-power loss because no "
    "wireless client was present, and keep port service loss separate from access-point failure."
)

UNKNOWN_DEVICE_GAP = (
    "A changed device had no audit-linked configuration change, so its device type is unknown and its ports were "
    "not resolved."
)
SELECTOR_GAP = "Port ranges, aggregates and dynamic selectors require additional resolution."
CONTRADICTION_REASON = "Contradictory same-time port events prevent state ordering"
OUT_OF_WINDOW_REASON = "A port event fell outside the window it was read for"
FOREIGN_EVENT_REASON = "A port event named another device or carried no time"
NO_LOSS_REASON = "No scoped loss event was observed; absence of events does not establish service health"
NO_BASELINE_LINK_REASON = "A scoped down event occurred, but prior active service is not established"
NO_BASELINE_POWER_REASON = "A scoped PoE disable occurred, but measured power before the change is not established"
LINK_TEXT = "Previously active port went down after the change; alternate paths and causes remain unresolved."
POWER_TEXT = "Previously powered port was disabled after the change; AP failure is not established."
ATTACHED_TEXT = "Past dependency, sole power path and impact remain unproven."
UNATTACHED_TEXT = "No managed access point reports this port as its uplink."


class SwitchPortPlan(base.PluginPlan):
    """The one port this attempt can read, and the switch it belongs to."""

    site_id: Identifier | None = None
    device_mac: Identifier | None = None
    port_id: Identifier | None = None


@dataclass(frozen=True, slots=True)
class PortEvent:
    at: datetime
    kind: str


@dataclass(frozen=True, slots=True)
class PortHistory:
    """The exact-port events of the combined window, or the one reason they cannot be relied on."""

    reason: str = ""
    events: tuple[PortEvent, ...] = ()
    changed_at: datetime | None = None
    end: datetime | None = None
    cited: tuple[str, ...] = ()

    def losses(self, kind: str) -> tuple[PortEvent, ...]:
        """The events of one kind at or after the change, which are the only ones this rule attributes."""
        if self.changed_at is None or self.end is None:
            return ()
        return tuple(event for event in self.events if event.kind == kind and self.changed_at <= event.at <= self.end)


@dataclass(frozen=True, slots=True)
class PortSnapshot:
    """The port's most recent reported state. Its observation time may precede the change."""

    cited: tuple[str, ...] = ()
    poe_on: bool = False
    power_draw: float | None = None
    observed_at: datetime | None = None

    def powered(self, changed_at: datetime | None) -> bool:
        """Measured power delivery in the five minutes before the change, never an administrative enable."""
        return bool(
            changed_at is not None
            and self.poe_on
            and self.power_draw is not None
            and self.power_draw > 0
            and self.observed_at is not None
            and changed_at - POWER_BASELINE <= self.observed_at < changed_at
        )


@dataclass(frozen=True, slots=True)
class Neighbour:
    """What the organization's own access points say about this port, when they were read."""

    cited: tuple[str, ...] = ()
    text: str = ""


@dataclass(frozen=True, slots=True)
class _Outcome:
    status: ObligationStatus
    finding: Finding | None = None
    peak: Band = "none"
    current: Band = "none"


class SwitchPortPlugin:
    """``port_config``/``port_config_overwrite`` ``disabled`` and ``poe_disabled`` on one concrete switch port."""

    id = ID
    version = VERSION
    max_reads = MAX_READS
    agent_hint = AGENT_HINT

    def plan(self, change: ChangeSet, devices: Sequence[ExpectedDevice]) -> RulePlan | None:
        gaps: list[str] = []
        claims = _claims(change, base.cohort(devices, device_type="switch"), gaps)
        if not claims:
            return SwitchPortPlan(gaps=base.gaps_within(gaps)) if gaps else None
        port = min(claims)
        if len(claims) > 1:
            gaps.append(f"{len(claims) - 1} further changed port(s) were not checked; this attempt reads one port.")
        site_id, device_mac, port_id = port
        return SwitchPortPlan(
            obligations=base.numbered(
                [
                    Obligation(
                        id="O1",
                        owner=ID,
                        change_ref=atom_id,
                        paths=paths,
                        role="observation",
                        kind="rule",
                        target=Target(device_mac=device_mac, site_id=site_id, port_id=port_id),
                    )
                    for (atom_id, _attribute), paths in sorted(claims[port].items())
                ]
            ),
            finding_kinds=("port_down", "occupied_port_down", "poe_power_lost"),
            gaps=base.gaps_within(gaps),
            site_id=site_id,
            device_mac=device_mac,
            port_id=port_id,
        )

    async def collect(self, plan: RulePlan, reader: Reader) -> list[Evidence]:
        target = _plan(plan)
        if target.port_id is None or not target.obligations:
            return []
        evidence = [await reader.read(_events_read(target)), await reader.read(_snapshot_read(target))]
        history = _history(target, evidence)
        # The managed neighbour only ever qualifies a loss, so it costs a read only when there is one to qualify.
        if any(history.losses(ATTRIBUTES[attribute][0]) for attribute in _attributes(target)):
            evidence.append(await reader.read(_neighbour_read(target, reader.org_id)))
        return evidence

    def evaluate(self, plan: RulePlan, evidence: Sequence[Evidence]) -> RuleConclusion:
        target = _plan(plan)
        history = _history(target, evidence)
        snapshot = _snapshot(evidence)
        neighbour = _neighbour(target, evidence)
        statuses: dict[str, ObligationStatus] = {}
        findings: list[Finding] = []
        peak: Band = "none"
        current: Band = "none"
        for obligation in target.obligations:
            outcome = _outcome(obligation.paths[0][-1], history, snapshot, neighbour)
            statuses[obligation.id] = outcome.status
            if outcome.finding is not None:
                findings.append(outcome.finding)
                peak = max(peak, outcome.peak, key=band_rank)
                current = max(current, outcome.current, key=band_rank)
        return Conclusion(
            statuses=statuses,
            peak=peak,
            current=current,
            findings=tuple(findings),
            impacted_devices=(
                (DeviceImpact(mac=str(target.device_mac), severity=peak, evidence_ids=history.cited),)
                if findings and target.device_mac
                else ()
            ),
            gaps=target.gaps,
        )


def _outcome(attribute: str, history: PortHistory, snapshot: PortSnapshot, neighbour: Neighbour) -> _Outcome:
    """One attribute's judgement, exactly as the ported domain rule reached it."""
    down, up, severity = ATTRIBUTES[attribute]
    if history.reason:
        return _Outcome(status=ObligationStatus(status="unsatisfied", reason=base.text(history.reason)))
    losses = history.losses(down)
    if not losses:
        return _Outcome(
            status=ObligationStatus(status="unsatisfied", reason=NO_LOSS_REASON, evidence_ids=history.cited)
        )
    if attribute == "poe_disabled":
        cited = (*history.cited, *snapshot.cited)
        if not snapshot.powered(history.changed_at):
            return _Outcome(
                status=ObligationStatus(status="unsatisfied", reason=NO_BASELINE_POWER_REASON, evidence_ids=cited)
            )
        recovered = False  # Enabling PoE alone never establishes restored delivery.
        text = POWER_TEXT
    else:
        cited = history.cited
        earlier = [event for event in history.events if history.changed_at and event.at < history.changed_at]
        if not earlier or earlier[-1].kind != up:
            return _Outcome(
                status=ObligationStatus(status="unsatisfied", reason=NO_BASELINE_LINK_REASON, evidence_ids=cited)
            )
        later = [event for event in history.events if event.at > losses[0].at]
        recovered = bool(later) and later[-1].kind == up
        text = LINK_TEXT
    cited = (*cited, *neighbour.cited)
    return _Outcome(
        status=ObligationStatus(status="satisfied", evidence_ids=cited),
        finding=Finding(text=base.text(f"{text} {neighbour.text}".strip()), severity=severity, evidence_ids=cited),
        peak=severity,
        current="none" if recovered else severity,
    )


def _claims(
    change: ChangeSet, switches: Sequence[str], gaps: list[str]
) -> dict[tuple[str, str, str], dict[tuple[str, str], tuple[ConfigPath, ...]]]:
    """Every concrete port whose ``disabled`` or ``poe_disabled`` a switch's own configuration changed."""
    claims: defaultdict[tuple[str, str, str], defaultdict[tuple[str, str], tuple[ConfigPath, ...]]] = defaultdict(
        lambda: defaultdict(tuple)
    )
    found: set[str] = set()
    for changed in change.objects:
        atoms = [atom for atom in base.atoms_of(change, changed) if atom.attribute in CONTAINERS]
        if changed.device_mac is None or not changed.site_id or not atoms:
            continue
        if changed.device_mac not in switches:
            found.add(UNKNOWN_DEVICE_GAP)
            continue
        for atom in atoms:
            for path in atom.paths:
                if len(path) != PORT_PATH_SEGMENTS or path[2] not in ATTRIBUTES:
                    continue
                if PORT.fullmatch(path[1]) is None:
                    found.add(SELECTOR_GAP)
                    continue
                port = (changed.site_id, changed.device_mac, path[1])
                claims[port][atom.id, path[2]] += (path,)
    gaps.extend(sorted(found))
    return {port: dict(attributes) for port, attributes in claims.items()}


def _attributes(plan: SwitchPortPlan) -> tuple[str, ...]:
    return tuple(obligation.paths[0][-1] for obligation in plan.obligations)


def _history(plan: SwitchPortPlan, evidence: Sequence[Evidence]) -> PortHistory:
    """The exact-port events of the combined window, rejecting anything that cannot be ordered."""
    item = evidence[0] if evidence else None
    reading = base.read_rows(item)
    # A read that answered something unusable is still worth citing beside the reason it could not be relied on.
    cited = (item.id,) if item is not None and item.citable else ()
    if item is None or item.window is None or not reading.complete:
        return PortHistory(reason=reading.reason or base.NOT_READ_REASON, cited=cited)
    events: list[PortEvent] = []
    for row in reading.rows:
        kind = base.string(row.get("type"))
        if kind not in EVENT_TYPES or base.string(row.get("port_id")) != plan.port_id:
            continue
        at = base.number(row.get("timestamp"))
        if base.string(row.get("mac")) != plan.device_mac or at is None:
            return PortHistory(reason=FOREIGN_EVENT_REASON, cited=cited)
        moment = datetime.fromtimestamp(at, tz=UTC)
        if not item.window.start <= moment <= item.window.end:
            return PortHistory(reason=OUT_OF_WINDOW_REASON, cited=cited)
        events.append(PortEvent(at=moment, kind=str(kind)))
    ordered = tuple(sorted(set(events), key=lambda event: (event.at, event.kind)))
    if any(len({event.kind for event in ordered if event.at == other.at}) > 1 for other in ordered):
        return PortHistory(reason=CONTRADICTION_REASON, cited=cited)
    return PortHistory(events=ordered, changed_at=base.changed_at(item.window), end=item.window.end, cited=cited)


def _snapshot(evidence: Sequence[Evidence]) -> PortSnapshot:
    """The one unique port row; anything else is not a state this rule may rely on."""
    item = evidence[1] if len(evidence) > 1 else None
    reading = base.read_rows(item)
    if item is None or not reading.complete or len(reading.rows) != 1:
        return PortSnapshot()
    row = reading.rows[0]
    observed = base.number(row.get("timestamp"))
    return PortSnapshot(
        cited=(item.id,) if item.citable else (),
        poe_on=row.get("poe_on") is True,
        power_draw=base.number(row.get("power_draw")),
        observed_at=datetime.fromtimestamp(observed, tz=UTC) if observed and observed > 0 else None,
    )


def _neighbour(plan: SwitchPortPlan, evidence: Sequence[Evidence]) -> Neighbour:
    """The managed access point whose own LLDP names this switch and port, when the access points were read."""
    item = evidence[2] if len(evidence) > 2 else None  # noqa: PLR2004 - the third read is the access points
    if item is None:
        return Neighbour()
    reading = base.read_rows(item, key="result")
    if not reading.complete:
        return Neighbour(cited=(item.id,) if item.citable else (), text=base.text(reading.reason))
    attached = sorted(
        {mac for row in reading.rows if _attached(row, plan) and (mac := base.mac(row.get("mac"))) is not None}
    )
    return Neighbour(
        cited=(item.id,),
        text=(
            f"Managed access point {', '.join(attached)} reports this port as its uplink. {ATTACHED_TEXT}"
            if attached
            else UNATTACHED_TEXT
        ),
    )


def _attached(row: Mapping[str, object], plan: SwitchPortPlan) -> bool:
    """Whether this access point's own LLDP names the changed switch and port."""
    stats = row.get("lldp_stats")
    links = list(stats.values()) if isinstance(stats, Mapping) else [row.get("lldp_stat")]
    return any(
        isinstance(link, Mapping)
        and base.mac(link.get("chassis_id")) == plan.device_mac
        and base.string(link.get("port_id")) == plan.port_id
        for link in links
    )


def _events_read(plan: SwitchPortPlan) -> RuleRead:
    return RuleRead(
        plugin=ID,
        title=base.text(f"Port events of {plan.device_mac} around the change"),
        kind="service_health",
        path=f"/api/v1/sites/{plan.site_id}/devices/events/search",
        params={"mac": str(plan.device_mac), "limit": EVENT_LIMIT, "sort": "timestamp"},
        site_id=plan.site_id,
        device_macs=(str(plan.device_mac),),
        window="combined",
    )


def _snapshot_read(plan: SwitchPortPlan) -> RuleRead:
    return RuleRead(
        plugin=ID,
        title=base.text(f"Current state of port {plan.port_id} on {plan.device_mac}"),
        kind="service_health",
        path=f"/api/v1/sites/{plan.site_id}/stats/ports/search",
        params={"device_type": "switch", "mac": str(plan.device_mac), "port_id": str(plan.port_id), "limit": "2"},
        site_id=plan.site_id,
        device_macs=(str(plan.device_mac),),
        omit_fields=NEIGHBOUR_FIELDS,
    )


def _neighbour_read(plan: SwitchPortPlan, org_id: str) -> RuleRead:
    return RuleRead(
        plugin=ID,
        title=base.text(f"Managed access points at the site of {plan.device_mac}"),
        kind="service_health",
        path=f"/api/v1/orgs/{org_id}/stats/devices",
        params={"type": "ap", "status": "all", "site_id": str(plan.site_id), "limit": AP_LIMIT, "fields": AP_FIELDS},
        site_id=plan.site_id,
    )


def _plan(plan: RulePlan) -> SwitchPortPlan:
    if not isinstance(plan, SwitchPortPlan):
        msg = f"{ID} was given another plug-in's plan"
        raise base.PluginError(msg)
    return plan
