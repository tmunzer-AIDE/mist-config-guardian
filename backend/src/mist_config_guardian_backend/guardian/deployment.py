"""Guardian deployment pairing: which devices an audit reached, when it changed, and whether each device applied it.

Inputs are device-event receipts already normalized by the caller. Provider occurrence times have whole-second
precision and carry no sequence field (the ``device_event_ordering`` verification decision), so every comparison
truncates to the second and same-second conflicts stay ambiguous. A receipt without a provider time is ordered by
its receipt time, which adds a gap and never confirms a deployment.

Each outcome is assigned to at most one trigger: an outcome carrying an ``audit_id`` only to the latest trigger of
that audit on its device that is not after it, an outcome without one to the latest trigger at or before it within
30 minutes. A trigger and an outcome in the same second have no known order, so a trigger of another change in the
outcome's second, or in the latest earlier second, leaves the outcome ambiguous.

The state of this audit's trigger then projects to an obligation status and, separately, to severity. Outcomes
assigned to it keep their warning even when their order is unknown. An outcome that may be this trigger's but cannot
be assigned to it unsettles the state only when it may also be the latest; it never projects severity itself.
"""

from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Literal

from pydantic import AwareDatetime, Field, JsonValue

from mist_config_guardian_backend.guardian.contracts import (
    Band,
    Conclusion,
    Contract,
    DeviceImpact,
    DeviceMac,
    Evidence,
    EvidenceScope,
    EvidenceWindow,
    ExpectedDevice,
    Identifier,
    ObligationId,
    ObligationStatus,
    RunAnchor,
    Text,
    band_rank,
)
from mist_config_guardian_backend.guardian.evidence import (
    DEPLOYMENT_EVIDENCE_BUDGET,
    WIDEST_EVIDENCE_ID,
    EvidenceRegistry,
    bounded,
)
from mist_config_guardian_backend.guardian.ledger import Ledger, RowDevices

PAIRING_BOUND = timedelta(minutes=30)
USER_TRIGGER_EVENTS = frozenset({"AP_CONFIG_CHANGED_BY_USER", "SW_CONFIG_CHANGED_BY_USER", "GW_CONFIG_CHANGED_BY_USER"})
TRIGGER_EVENTS = USER_TRIGGER_EVENTS | {"AP_CONFIG_CHANGED_BY_RRM"}
DEVICE_EVENT_PREFIXES = ("AP", "SW", "GW")
SHOWN_OUTCOMES = 3
LISTED_DEVICES = 3

NO_TRIGGER_REASON = "No audit-linked deployment trigger was observed"
NO_OUTCOME_REASON = "No deployment outcome was observed"
FAILED_REASON = "The latest deployment outcome is failed"
REVERTED_REASON = "The latest deployment outcome is reverted"
CONFLICT_REASON = "Conflicting deployment outcomes were reported in the same second"
AMBIGUOUS_TRIGGERS_REASON = "The latest deployment outcome could belong to another change's trigger"
RECEIPT_TIME_REASON = "Deployment ordering relies on receipt time only"

OutcomeKind = Literal["configured", "failed", "reverted"]
DeploymentState = Literal["unknown", "configured", "failed", "reverted", "ambiguous"]
Correlation = Literal["none", "audit_id", "time", "ambiguous"]
Precondition = Literal["satisfied", "unsatisfied"]

_OUTCOME_SUFFIXES: Mapping[str, OutcomeKind] = {
    "_CONFIGURED": "configured",
    "_CONFIG_FAILED": "failed",
    "_CONFIG_REVERTED": "reverted",
}
_TROUBLE: frozenset[OutcomeKind] = frozenset({"failed", "reverted"})
_UNSATISFIED_REASONS: Mapping[OutcomeKind, str] = {"failed": FAILED_REASON, "reverted": REVERTED_REASON}

# Gaps name the devices they concern; each kind is reported once, in this order.
_DELAY_GAP = "Audit-linked deployment outcomes arrived more than 30 minutes after their trigger and were accepted"
_UNMATCHED_GAP = "Audit-linked deployment outcomes with no matching earlier trigger were ignored"
_RECEIPT_TIME_GAP = "Deployment ordering relies on receipt time only, which cannot confirm a deployment"
_AMBIGUOUS_GAP = "Deployment outcomes could not be attributed unambiguously"
_OUT_OF_BOUND_GAP = (
    "Unlinked deployment outcomes arrived more than 30 minutes after every earlier trigger and were not paired"
)
_GAP_ORDER = (_RECEIPT_TIME_GAP, _AMBIGUOUS_GAP, _OUT_OF_BOUND_GAP, _UNMATCHED_GAP, _DELAY_GAP)


def outcome_kind(event_type: str) -> OutcomeKind | None:
    """``*_CONFIGURED``, ``*_CONFIG_FAILED`` and ``*_CONFIG_REVERTED`` for access points, switches and gateways."""
    prefix, _, _ = event_type.partition("_")
    if prefix not in DEVICE_EVENT_PREFIXES:
        return None
    return _OUTCOME_SUFFIXES.get(event_type[len(prefix) :])


def provider_second(value: datetime) -> datetime:
    """A time at the provider's precision: UTC, truncated to the whole second."""
    return value.astimezone(UTC).replace(microsecond=0)


class DeviceGaps:
    """Gaps that name the devices they concern: each kind is reported once, with a device count and a few MACs."""

    def __init__(self, order: tuple[str, ...]) -> None:
        self._order = order
        self._devices: defaultdict[str, set[str]] = defaultdict(set)

    def add(self, gap: str, mac: str) -> None:
        if gap not in self._order:
            msg = f"Unknown gap kind: {gap}"
            raise ValueError(msg)
        self._devices[gap].add(mac)

    def texts(self) -> tuple[str, ...]:
        texts = []
        for gap in self._order:
            macs = sorted(self._devices[gap])
            if macs:
                more = len(macs) - LISTED_DEVICES
                listed = ", ".join(macs[:LISTED_DEVICES]) + (f" and {more} more" if more > 0 else "")
                texts.append(f"{gap} on {len(macs)} device(s): {listed}")
        return tuple(texts)


class DeviceEventReceipt(Contract):
    """One device-event receipt as normalized for pairing. ``occurred_at`` is the provider's time, when it had one."""

    receipt_id: Identifier
    received_at: AwareDatetime
    event_type: Identifier
    device_mac: DeviceMac
    site_id: Identifier
    occurred_at: AwareDatetime | None = None
    audit_id: Identifier | None = None


class ReplayFrame(Contract):
    """The audit, its anchor and the fixed evidence instant that bound every replay of one attempt."""

    audit_id: Identifier
    anchor: RunAnchor
    as_of: AwareDatetime

    @property
    def pairing_start(self) -> datetime:
        """``changed_at - 30 min``, at the provider's precision."""
        return provider_second(self.anchor.changed_at) - PAIRING_BOUND


def expected_devices(
    receipts: Iterable[DeviceEventReceipt], *, audit_id: str, as_of: datetime
) -> tuple[ExpectedDevice, ...]:
    """Devices with a ``*_CONFIG_CHANGED_BY_USER`` receipt carrying this audit, by MAC, each at its latest site."""
    latest: dict[str, tuple[tuple[datetime, datetime, str], str]] = {}
    for item in receipts:
        if item.event_type not in USER_TRIGGER_EVENTS or item.audit_id != audit_id or item.received_at > as_of:
            continue
        key = (_Event.of(item).second, item.received_at, item.receipt_id)
        if item.device_mac not in latest or key > latest[item.device_mac][0]:
            latest[item.device_mac] = (key, item.site_id)
    return tuple(ExpectedDevice(mac=mac, site_id=site) for mac, (_, site) in sorted(latest.items()))


def resolve_anchor(
    receipts: Iterable[DeviceEventReceipt],
    *,
    audit_id: str,
    audit_time: datetime | None,
    received_at: datetime,
    as_of: datetime,
) -> RunAnchor:
    """The change time every window uses: the audit's event time, else the earliest provider time of an audit-linked
    user trigger, else the audit's receipt time."""
    if audit_time is not None:
        return RunAnchor(changed_at=audit_time, source="audit")
    triggered = [
        provider_second(item.occurred_at)
        for item in receipts
        if item.event_type in USER_TRIGGER_EVENTS
        and item.audit_id == audit_id
        and item.occurred_at is not None
        and item.received_at <= as_of
    ]
    if triggered:
        return RunAnchor(changed_at=min(triggered), source="device_trigger")
    return RunAnchor(changed_at=received_at, source="receipt")


class PairedOutcome(Contract):
    """Outcomes of one kind in one second assigned to this audit's trigger; duplicates are idempotent."""

    kind: OutcomeKind
    event_type: Identifier
    occurred_at: AwareDatetime
    correlation: Literal["audit_id", "time"]
    count: int = Field(default=1, ge=1)


class DeviceDeployment(Contract):
    """This audit's trigger on one device, the outcomes paired with it, its state and both projections.

    The defaults describe a trigger with no outcome yet: unknown, no floor, and an unsatisfied precondition.
    """

    mac: DeviceMac
    site_id: Identifier | None = None
    trigger: Identifier | None = None
    triggered_at: AwareDatetime | None = None
    outcomes: tuple[PairedOutcome, ...] = ()
    correlation: Correlation = "none"
    state: DeploymentState = "unknown"
    recovered: bool = False
    peak: Band = "none"
    current: Band = "none"
    precondition: Precondition = "unsatisfied"
    reason: Text | None = NO_OUTCOME_REASON


class DeploymentReplay(Contract):
    """Every row device's deployment, and which device each deployment precondition names."""

    devices: tuple[DeviceDeployment, ...] = ()
    preconditions: dict[ObligationId, DeviceMac] = Field(default_factory=dict)
    peak: Band = "none"
    current: Band = "none"
    gaps: tuple[Text, ...] = ()

    def device(self, mac: str) -> DeviceDeployment | None:
        return next((device for device in self.devices if device.mac == mac), None)

    @property
    def statuses(self) -> dict[ObligationId, ObligationStatus]:
        """A precondition is satisfied only when this audit's trigger is unambiguously configured."""
        devices = {device.mac: device for device in self.devices}
        return {
            obligation_id: ObligationStatus(status=device.precondition, reason=device.reason)
            for obligation_id, mac in self.preconditions.items()
            if (device := devices.get(mac)) is not None
        }


def pair_deployments(receipts: Iterable[DeviceEventReceipt], *, frame: ReplayFrame, ledger: Ledger) -> DeploymentReplay:
    """Pair device events over ``[changed_at - 30 min, as_of]`` for every device a ledger row targets.

    Every row device projects severity. Statuses exist only for the ledger's deployment preconditions, which name
    the devices at least one obligation targets.
    """
    sites = {mac: target.site_id for mac, target in RowDevices.of(ledger).targets.items()}
    events: defaultdict[str, list[_Event]] = defaultdict(list)
    for item in receipts:
        if item.device_mac not in sites or item.received_at > frame.as_of:
            continue
        if item.event_type not in TRIGGER_EVENTS and outcome_kind(item.event_type) is None:
            continue
        event = _Event.of(item)
        if frame.pairing_start <= event.second <= frame.as_of:
            events[item.device_mac].append(event)
    gaps = DeviceGaps(_GAP_ORDER)
    devices = tuple(
        _pair_device(mac, sites[mac], sorted(events[mac], key=_Event.order), frame.audit_id, gaps)
        for mac in sorted(sites)
    )
    return DeploymentReplay(
        devices=devices,
        preconditions={
            o.id: o.target.device_mac
            for o in ledger.obligations
            if o.kind == "deployment" and o.target.device_mac is not None
        },
        peak=max((device.peak for device in devices), key=band_rank, default="none"),
        current=max((device.current for device in devices), key=band_rank, default="none"),
        gaps=gaps.texts(),
    )


class DeploymentRow(Contract):
    """A device's deployment for display, with its last few outcomes and their total."""

    mac: DeviceMac
    site_id: Identifier | None = None
    trigger: Identifier | None = None
    triggered_at: AwareDatetime | None = None
    outcomes: tuple[PairedOutcome, ...] = Field(default=(), max_length=SHOWN_OUTCOMES)
    outcome_count: int = Field(default=0, ge=0)
    correlation: Correlation
    state: DeploymentState
    recovered: bool
    peak: Band
    current: Band
    precondition: Precondition
    reason: Text | None = None


def record_deployment(replay: DeploymentReplay, *, frame: ReplayFrame, registry: EvidenceRegistry) -> Conclusion:
    """Record the one deployment evidence item and conclude, citing it from every status and impacted device.

    Devices whose precondition is unsatisfied or that carry a deployment warning get full rows, unsatisfied first,
    while the budget allows; every other device is counted by precondition and peak in the same item.
    """
    cited: tuple[str, ...] = ()
    if replay.devices:
        rows = [_row(device) for device in replay.devices]
        rest = Counter(_category(row) for row in rows if not _notable(row))
        item = bounded(
            [row for row in rows if _notable(row)],
            budget=DEPLOYMENT_EVIDENCE_BUDGET,
            priority=lambda row: (row.precondition == "satisfied", -band_rank(row.peak), row.mac),
            category=_category,
            build=lambda kept, omitted: _deployment_item(kept, Counter(omitted) + rest, frame),
        )
        cited = (registry.record(item.model_copy(update={"id": registry.reserve("deployment")})).id,)
    return Conclusion(
        statuses={key: status.model_copy(update={"evidence_ids": cited}) for key, status in replay.statuses.items()},
        peak=replay.peak,
        current=replay.current,
        impacted_devices=tuple(
            DeviceImpact(mac=device.mac, severity=device.peak, evidence_ids=cited)
            for device in replay.devices
            if device.peak != "none"
        ),
        gaps=replay.gaps,
    )


@dataclass(frozen=True, slots=True)
class _Event:
    """A deployment receipt placed in time.

    ``second`` is its provider second or, with receipt time only, its receipt second: the latest it can have
    occurred. Only a provider time also bounds how early it occurred.
    """

    receipt: DeviceEventReceipt
    second: datetime
    timed: bool
    kind: OutcomeKind | None

    @classmethod
    def of(cls, receipt: DeviceEventReceipt) -> "_Event":
        timed = receipt.occurred_at is not None
        moment = receipt.occurred_at if receipt.occurred_at is not None else receipt.received_at
        return cls(receipt, provider_second(moment), timed, outcome_kind(receipt.event_type))

    def order(self) -> tuple[datetime, str]:
        return (self.second, self.receipt.receipt_id)

    @property
    def audit_id(self) -> str | None:
        return self.receipt.audit_id

    @property
    def identity(self) -> tuple[str, ...]:
        """Which change a trigger belongs to: its audit, RRM, or an unlinked user change."""
        if self.audit_id is not None:
            return ("audit", self.audit_id)
        return ("rrm",) if self.receipt.event_type == "AP_CONFIG_CHANGED_BY_RRM" else ("unlinked",)

    def may_precede(self, other: "_Event") -> bool:
        """Whether this event can be at or before ``other`` at second precision."""
        return not self.timed or self.second <= other.second

    def surely_between(self, first: "_Event", last: "_Event") -> bool:
        """Whether this event is certainly after ``first`` and before ``last``: in a later second than ``first`` can
        have and an earlier second than ``last`` can have."""
        return self.timed and last.timed and first.second < self.second < last.second


@dataclass(frozen=True, slots=True)
class _Assigned:
    event: _Event
    kind: OutcomeKind
    link: Literal["audit_id", "time"]


@dataclass(frozen=True, slots=True)
class _Uncertain:
    """An outcome that may be this audit's but cannot be assigned to it, and why."""

    event: _Event
    reason: str


def _pair_device(
    mac: str, site_id: str | None, events: list[_Event], audit_id: str, gaps: DeviceGaps
) -> DeviceDeployment:
    own = [event for event in events if event.kind is None and event.audit_id == audit_id]
    assigned, uncertain = _assign(mac, events, audit_id, gaps)
    shown = max((t for t in own if t.timed), key=_Event.order, default=own[-1] if own else None)
    base = DeviceDeployment(
        mac=mac,
        site_id=site_id,
        trigger=None if shown is None else shown.receipt.event_type,
        triggered_at=shown.second if shown is not None and shown.timed else None,
        outcomes=_paired(assigned),
    )
    if not own:
        return base.model_copy(update={"reason": NO_TRIGGER_REASON})
    for item in uncertain:
        gaps.add(_RECEIPT_TIME_GAP if item.reason == RECEIPT_TIME_REASON else _AMBIGUOUS_GAP, mac)
    last = max((item.event.second for item in assigned), default=None)
    # Assigned failed or reverted outcomes warn whatever else is uncertain.
    peak: Band = "warning" if any(item.kind in _TROUBLE for item in assigned) else "none"
    # An uncertain outcome unsettles the state only if it may be the latest; otherwise it is only a gap.
    unsettling = {item.reason for item in uncertain if last is None or item.event.second >= last}
    if unsettling:
        reason = RECEIPT_TIME_REASON if RECEIPT_TIME_REASON in unsettling else AMBIGUOUS_TRIGGERS_REASON
        return _ambiguous(base, reason).model_copy(update={"peak": peak})
    if last is None:
        return base
    final = {item.kind for item in assigned if item.event.second == last}
    if len(final) > 1:
        # This trigger's own outcomes in an unknown order: the latest is unknown, but failed or reverted still warns,
        # and stays current when every outcome that may be the latest is failed or reverted.
        gaps.add(_AMBIGUOUS_GAP, mac)
        return base.model_copy(
            update={
                "correlation": _correlation(assigned),
                "state": "ambiguous",
                "peak": peak,
                "current": "warning" if final <= _TROUBLE else "none",
                "reason": CONFLICT_REASON,
            }
        )
    return _settle(base, assigned)


def _assign(
    mac: str, events: list[_Event], audit_id: str, gaps: DeviceGaps
) -> tuple[list[_Assigned], list[_Uncertain]]:
    """This audit's assigned outcomes, and the outcomes that may be this audit's but cannot be assigned to it."""
    triggers = [event for event in events if event.kind is None]
    note = partial(gaps.add, mac=mac)
    assigned: list[_Assigned] = []
    uncertain: list[_Uncertain] = []
    for outcome in events:
        kind = outcome.kind
        if kind is None:
            continue
        pair = _exact_link if outcome.audit_id is not None else _time_fallback
        result = pair(outcome, kind, triggers, audit_id, note)
        if isinstance(result, _Assigned):
            assigned.append(result)
        elif isinstance(result, _Uncertain):
            uncertain.append(result)
    return assigned, uncertain


def _exact_link(
    outcome: _Event, kind: OutcomeKind, triggers: list[_Event], audit_id: str, gap: Callable[[str], None]
) -> _Assigned | _Uncertain | None:
    """Only a trigger of the outcome's audit on this device that is not after the outcome."""
    linked = [t for t in triggers if t.audit_id == outcome.audit_id and t.may_precede(outcome)]
    if not linked:
        gap(_UNMATCHED_GAP)
        return None
    if outcome.audit_id != audit_id:
        return None
    confirmed = [t.second for t in linked if t.timed and outcome.timed]
    if not confirmed:
        return _Uncertain(outcome, RECEIPT_TIME_REASON)
    if outcome.second - max(confirmed) > PAIRING_BOUND:
        gap(_DELAY_GAP)
    return _Assigned(outcome, kind, "audit_id")


def _time_fallback(
    outcome: _Event, kind: OutcomeKind, triggers: list[_Event], audit_id: str, gap: Callable[[str], None]
) -> _Assigned | _Uncertain | None:
    """The latest triggers of any change at or before an unlinked outcome, within the bound."""
    found = _fallback_triggers(outcome, triggers)
    identities = {t.identity for t in found}
    if not found:
        if any(t.audit_id == audit_id and t.may_precede(outcome) for t in triggers):
            gap(_OUT_OF_BOUND_GAP)
        return None
    if ("audit", audit_id) not in identities:
        return None
    if not outcome.timed or not all(t.timed for t in found):
        return _Uncertain(outcome, RECEIPT_TIME_REASON)
    if len(identities) > 1:
        return _Uncertain(outcome, AMBIGUOUS_TRIGGERS_REASON)
    return _Assigned(outcome, kind, "time")


def _fallback_triggers(outcome: _Event, triggers: list[_Event]) -> list[_Event]:
    """Every trigger that may be the latest at or before an unlinked outcome, within the bound.

    With provider times these are the triggers in the outcome's own second (their order with it is unknown) and those
    in the latest earlier second. Receipt time widens that to any trigger no provider time proves superseded.
    """
    possible = [
        t
        for t in triggers
        if t.may_precede(outcome)
        and (not outcome.timed or outcome.second - min(t.second, outcome.second) <= PAIRING_BOUND)
    ]
    return [t for t in possible if not any(u.surely_between(t, outcome) for u in triggers)]


def _settle(base: DeviceDeployment, assigned: list[_Assigned]) -> DeviceDeployment:
    """The state machine once the latest assigned outcome is known: it decides, and failed or reverted anywhere
    warns."""
    last = max(assigned, key=lambda item: item.event.second).kind
    troubled = any(item.kind in _TROUBLE for item in assigned)
    if last == "configured":
        update: dict[str, object] = {
            "state": last,
            "recovered": troubled,
            "peak": "warning" if troubled else "none",
            "precondition": "satisfied",
            "reason": None,
        }
    else:
        update = {"state": last, "peak": "warning", "current": "warning", "reason": _UNSATISFIED_REASONS[last]}
    return base.model_copy(update={"correlation": _correlation(assigned), **update})


def _correlation(assigned: list[_Assigned]) -> Correlation:
    return "audit_id" if any(item.link == "audit_id" for item in assigned) else "time"


def _ambiguous(device: DeviceDeployment, reason: str) -> DeviceDeployment:
    """Ambiguity never satisfies a precondition and never projects severity."""
    return device.model_copy(update={"correlation": "ambiguous", "state": "ambiguous", "reason": reason})


def _paired(assigned: list[_Assigned]) -> tuple[PairedOutcome, ...]:
    grouped: defaultdict[tuple[datetime, OutcomeKind], list[_Assigned]] = defaultdict(list)
    for item in assigned:
        grouped[(item.event.second, item.kind)].append(item)
    return tuple(
        PairedOutcome(
            kind=kind,
            event_type=min((item.event for item in members), key=_Event.order).receipt.event_type,
            occurred_at=second,
            correlation="audit_id" if any(item.link == "audit_id" for item in members) else "time",
            count=len(members),
        )
        for (second, kind), members in sorted(grouped.items())
    )


def _row(device: DeviceDeployment) -> DeploymentRow:
    return DeploymentRow(
        mac=device.mac,
        site_id=device.site_id,
        trigger=device.trigger,
        triggered_at=device.triggered_at,
        outcomes=device.outcomes[-SHOWN_OUTCOMES:],
        outcome_count=len(device.outcomes),
        correlation=device.correlation,
        state=device.state,
        recovered=device.recovered,
        peak=device.peak,
        current=device.current,
        precondition=device.precondition,
        reason=device.reason,
    )


def _notable(row: DeploymentRow) -> bool:
    return row.precondition == "unsatisfied" or row.peak != "none"


def _category(row: DeploymentRow) -> str:
    return f"{row.precondition}:{row.peak}"


def _deployment_item(kept: tuple[DeploymentRow, ...], counts: Mapping[str, int], frame: ReplayFrame) -> Evidence:
    counted: dict[str, JsonValue] = {name: counts[name] for name in sorted(counts) if counts[name]}
    return Evidence(
        id=WIDEST_EVIDENCE_ID,
        source="deployment",
        kind="deployment",
        title="Deployment pairing",
        captured_at=frame.as_of,
        window=_window(frame.pairing_start, frame.as_of),
        scope=EvidenceScope(
            site_ids=tuple(sorted({row.site_id for row in kept if row.site_id is not None})),
            device_macs=tuple(row.mac for row in kept),
        ),
        collection="complete",
        representation="digest" if counted else "full",
        payload={"rows": [row.model_dump(mode="json") for row in kept], "omitted": counted},
        detail="Other devices are counted by precondition and deployment peak" if counted else "",
    )


def _window(start: datetime, end: datetime) -> EvidenceWindow | None:
    return EvidenceWindow(start=start, end=end) if start <= end else None
