"""Guardian deployment pairing: expected devices, the anchor, outcome assignment, the state machine and projection."""

import itertools
import random
from datetime import UTC, datetime, timedelta, timezone

import pytest

from guardian_verification import load_fixture
from mist_config_guardian_backend.guardian.change import ChangedObject, ChangeSet
from mist_config_guardian_backend.guardian.contracts import (
    ChangeAtom,
    ExpectedDevice,
    Obligation,
    RulePlan,
    RunAnchor,
    Target,
)
from mist_config_guardian_backend.guardian.deployment import (
    AMBIGUOUS_TRIGGERS_REASON,
    CONFLICT_REASON,
    FAILED_REASON,
    NO_OUTCOME_REASON,
    NO_TRIGGER_REASON,
    RECEIPT_TIME_REASON,
    REVERTED_REASON,
    TRIGGER_EVENTS,
    DeviceEventReceipt,
    DeviceGaps,
    ReplayFrame,
    expected_devices,
    outcome_kind,
    pair_deployments,
    provider_second,
    record_deployment,
    resolve_anchor,
)
from mist_config_guardian_backend.guardian.evidence import DEPLOYMENT_EVIDENCE_BUDGET, EvidenceRegistry, json_size
from mist_config_guardian_backend.guardian.ledger import Ledger, build_ledger

AUDIT = "30000000-0000-4000-8000-000000000001"
OTHER = "30000000-0000-4000-8000-000000000002"
SITE = "20000000-0000-4000-8000-000000000001"
X = "020000000021"
Y = "020000000022"
Z = "020000000031"
T0 = datetime(2026, 9, 16, 4, 41, 35, tzinfo=UTC)
AUDIT_TIME = T0 + timedelta(milliseconds=242)
AS_OF = T0 + timedelta(hours=2)
MINUTE = 60

_ids = itertools.count(1)
_OUTCOME_EVENTS = {"configured": "AP_CONFIGURED", "failed": "AP_CONFIG_FAILED", "reverted": "AP_CONFIG_REVERTED"}


def receipt(  # noqa: PLR0913 - one argument per receipt field a case varies
    event: str,
    at: int | None,
    audit: str | None = None,
    *,
    mac: str = X,
    received: datetime | None = None,
    site: str = SITE,
) -> DeviceEventReceipt:
    """A receipt ``at`` seconds after T0, or without a provider time when ``at`` is None."""
    occurred = None if at is None else T0 + timedelta(seconds=at)
    return DeviceEventReceipt(
        receipt_id=f"r{next(_ids)}",
        received_at=received or (occurred or T0) + timedelta(seconds=5),
        event_type=event,
        device_mac=mac,
        site_id=site,
        occurred_at=occurred,
        audit_id=audit,
    )


def trig(at: int | None, audit: str | None = AUDIT, *, mac: str = X, **fields) -> DeviceEventReceipt:
    return receipt("AP_CONFIG_CHANGED_BY_USER", at, audit, mac=mac, **fields)


def rrm(at: int | None, *, mac: str = X) -> DeviceEventReceipt:
    return receipt("AP_CONFIG_CHANGED_BY_RRM", at, None, mac=mac)


def out(kind: str, at: int | None, audit: str | None = None, *, mac: str = X, **fields) -> DeviceEventReceipt:
    return receipt(_OUTCOME_EVENTS[kind], at, audit, mac=mac, **fields)


def frame(*, anchor: datetime = AUDIT_TIME, as_of: datetime = AS_OF, source: str = "audit") -> ReplayFrame:
    return ReplayFrame(audit_id=AUDIT, anchor=RunAnchor(changed_at=anchor, source=source), as_of=as_of)


def ledger_for(*macs: str, targeted: tuple[str, ...] | None = None) -> Ledger:
    """One org template atom applying to ``macs``; a monitoring obligation on each targeted device."""
    template = ChangedObject(logical_object_id="template", scope="org", object_type="networktemplates", version=1)
    atom = ChangeAtom(
        id="A1",
        logical_object_id="template",
        version=1,
        attribute="dns_servers",
        paths=(("dns_servers",),),
        paths_complete=True,
    )
    obligations = tuple(
        Obligation(
            id=f"O{number}",
            owner="dns",
            change_ref="A1",
            paths=(("dns_servers",),),
            role="observation",
            kind="monitoring",
            target=Target(device_mac=mac, site_id=SITE),
            metric="switch-health",
            empty_policy="incomplete",
        )
        for number, mac in enumerate(macs if targeted is None else targeted, start=1)
    )
    return build_ledger(
        ChangeSet(objects=(template,), atoms=(atom,)),
        [ExpectedDevice(mac=mac, site_id=SITE) for mac in macs],
        {"dns": RulePlan(obligations=obligations)} if obligations else {},
        "audit",
    )


def precondition_of(ledger: Ledger, mac: str) -> str:
    [found] = [o.id for o in ledger.obligations if o.kind == "deployment" and o.target.device_mac == mac]
    return found


def pair(receipts, *, macs: tuple[str, ...] = (X,), **frame_fields):
    ledger = ledger_for(*macs)
    return ledger, pair_deployments(receipts, frame=frame(**frame_fields), ledger=ledger)


# Event classification ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("event", "trigger", "kind"),
    [
        ("AP_CONFIG_CHANGED_BY_USER", True, None),
        ("SW_CONFIG_CHANGED_BY_USER", True, None),
        ("GW_CONFIG_CHANGED_BY_USER", True, None),
        ("AP_CONFIG_CHANGED_BY_RRM", True, None),
        ("SW_CONFIG_CHANGED_BY_RRM", False, None),
        ("AP_CONFIGURED", False, "configured"),
        ("SW_CONFIGURED", False, "configured"),
        ("GW_CONFIGURED", False, "configured"),
        ("AP_CONFIG_FAILED", False, "failed"),
        ("SW_CONFIG_FAILED", False, "failed"),
        ("GW_CONFIG_FAILED", False, "failed"),
        ("AP_CONFIG_REVERTED", False, "reverted"),
        ("SW_CONFIG_REVERTED", False, "reverted"),
        ("GW_CONFIG_REVERTED", False, "reverted"),
        ("AP_DISCONNECTED", False, None),
        ("ME_CONFIGURED", False, None),
        ("AP_RECONFIGURED", False, None),
    ],
)
def test_triggers_and_outcomes_are_the_listed_event_types_only(event, trigger, kind):
    assert (event in TRIGGER_EVENTS) is trigger
    assert outcome_kind(event) == kind


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (datetime(2026, 9, 16, 4, 41, 35, 242_000, tzinfo=UTC), datetime(2026, 9, 16, 4, 41, 35, tzinfo=UTC)),
        (datetime(2026, 9, 16, 4, 41, 35, 999_999, tzinfo=UTC), datetime(2026, 9, 16, 4, 41, 35, tzinfo=UTC)),
    ],
)
def test_provider_times_compare_at_whole_seconds(value, expected):
    assert provider_second(value) == expected


def test_provider_seconds_are_normalized_to_utc():
    local = datetime(2026, 9, 16, 6, 41, 35, 900_000, tzinfo=timezone(timedelta(hours=2)))
    assert provider_second(local) == T0
    assert provider_second(local).tzinfo == UTC


def test_device_gaps_list_a_few_devices_and_refuse_an_unordered_kind():
    gaps = DeviceGaps(("first", "second"))
    for mac in ("020000000004", "020000000001", "020000000003", "020000000002"):
        gaps.add("second", mac)
    gaps.add("first", X)

    assert gaps.texts() == (
        f"first on 1 device(s): {X}",
        "second on 4 device(s): 020000000001, 020000000002, 020000000003 and 1 more",
    )
    with pytest.raises(ValueError, match="Unknown gap kind"):
        gaps.add("third", X)


# Expected devices and the anchor -----------------------------------------------------------------------------------


def test_expected_devices_come_only_from_user_triggers_carrying_this_audit():
    receipts = [
        trig(0, mac=X),
        trig(1, mac=X),
        receipt("SW_CONFIG_CHANGED_BY_USER", 0, AUDIT, mac=Z, site="site-b"),
        rrm(0, mac=Y),
        receipt("AP_CONFIG_CHANGED_BY_RRM", 0, AUDIT, mac=Y),
        trig(0, OTHER, mac=Y),
        trig(0, None, mac=Y),
        out("configured", 2, AUDIT, mac=Y),
        trig(None, mac="020000000099"),
        trig(3, mac="0200000000aa", received=AS_OF + timedelta(seconds=1)),
    ]

    # The trigger's own prefix names each device's family, which is all Guardian ever observes it from.
    assert expected_devices(receipts, audit_id=AUDIT, as_of=AS_OF) == (
        ExpectedDevice(mac=X, site_id=SITE, device_type="ap"),
        ExpectedDevice(mac=Z, site_id="site-b", device_type="switch"),
        ExpectedDevice(mac="020000000099", site_id=SITE, device_type="ap"),
    )


def test_a_device_reported_at_two_sites_is_expected_once_at_its_latest_site():
    receipts = [trig(0, site="site-old"), trig(60, site="site-new")]
    assert expected_devices(reversed(receipts), audit_id=AUDIT, as_of=AS_OF) == (
        ExpectedDevice(mac=X, site_id="site-new", device_type="ap"),
    )


@pytest.mark.parametrize(
    ("audit_time", "receipts", "expected"),
    [
        pytest.param(AUDIT_TIME, [trig(-5)], RunAnchor(changed_at=AUDIT_TIME, source="audit"), id="audit time first"),
        pytest.param(
            None,
            [trig(9, mac=Y), trig(3), rrm(1), trig(0, OTHER), out("configured", 2, AUDIT), trig(None)],
            RunAnchor(changed_at=T0 + timedelta(seconds=3), source="device_trigger"),
            id="earliest audit-linked user trigger",
        ),
        pytest.param(
            None,
            [trig(None), rrm(1), trig(0, OTHER), trig(4, received=AS_OF + timedelta(seconds=1))],
            RunAnchor(changed_at=T0 - timedelta(minutes=1), source="receipt"),
            id="receipt time when no trigger has a provider time",
        ),
    ],
)
def test_the_anchor_resolves_audit_then_device_trigger_then_receipt(audit_time, receipts, expected):
    anchor = resolve_anchor(
        receipts, audit_id=AUDIT, audit_time=audit_time, received_at=T0 - timedelta(minutes=1), as_of=AS_OF
    )
    assert anchor == expected


# Assignment rules --------------------------------------------------------------------------------------------------

ASSIGNMENT_CASES = [
    # Exact link
    pytest.param([trig(0), out("configured", 2, AUDIT)], "configured", "audit_id", None, id="exact link"),
    pytest.param([trig(0), out("configured", 0, AUDIT)], "configured", "audit_id", None, id="exact link same second"),
    pytest.param(
        [trig(0), trig(-60), out("configured", 90, AUDIT)], "configured", "audit_id", None, id="latest own trigger"
    ),
    pytest.param(
        [trig(0), trig(1, OTHER), out("configured", 2, OTHER)],
        "unknown",
        "none",
        None,
        id="an outcome linked to another audit never confirms this audit",
    ),
    pytest.param(
        [trig(10), trig(0, OTHER), out("failed", 12, OTHER)],
        "unknown",
        "none",
        None,
        id="a linked outcome never falls back to the latest trigger",
    ),
    pytest.param(
        [out("configured", 0, AUDIT), trig(5)],
        "unknown",
        "none",
        "no matching earlier trigger",
        id="a linked outcome before its trigger is ignored with a gap",
    ),
    pytest.param(
        [trig(0), out("configured", 2, OTHER)],
        "unknown",
        "none",
        "no matching earlier trigger",
        id="a linked outcome whose audit has no trigger is ignored with a gap",
    ),
    pytest.param(
        [trig(0), out("configured", 31 * MINUTE, AUDIT)],
        "configured",
        "audit_id",
        "more than 30 minutes",
        id="an exact link beyond 30 minutes is accepted with a delay gap",
    ),
    # Time fallback
    pytest.param([trig(0), out("configured", 2)], "configured", "time", None, id="time fallback"),
    pytest.param([trig(0), out("configured", 30 * MINUTE)], "configured", "time", None, id="fallback at the bound"),
    pytest.param(
        [trig(0), out("configured", 30 * MINUTE + 1)],
        "unknown",
        "none",
        "more than 30 minutes after every earlier trigger",
        id="an unlinked outcome outside the bound is not paired, with a gap",
    ),
    pytest.param(
        [trig(0), out("configured", 2), out("configured", 45 * MINUTE)],
        "configured",
        "time",
        "more than 30 minutes after every earlier trigger",
        id="a reconnect beyond the bound leaves a confirmed trigger confirmed",
    ),
    pytest.param(
        [trig(0), trig(10, OTHER), out("failed", 12)],
        "unknown",
        "none",
        None,
        id="the latest trigger belongs to another audit",
    ),
    pytest.param([trig(0), rrm(10), out("failed", 12)], "unknown", "none", None, id="the latest trigger is RRM"),
    pytest.param(
        [trig(0), trig(10, None), out("failed", 12)],
        "unknown",
        "none",
        None,
        id="the latest trigger carries no audit",
    ),
    pytest.param([out("configured", 0), trig(5)], "unknown", "none", None, id="never assigned backward"),
    pytest.param(
        [trig(0), receipt("AP_DISCONNECTED", 2, AUDIT), receipt("AP_RESTARTED", 3)],
        "unknown",
        "none",
        None,
        id="non-deployment events are neither triggers nor outcomes",
    ),
    pytest.param([trig(0), out("configured", 2, mac=Y)], "unknown", "none", None, id="another device's outcome"),
    # Same-second triggers
    pytest.param(
        [trig(0), trig(0, OTHER), out("configured", 2)],
        "ambiguous",
        "ambiguous",
        "could not be attributed",
        id="same-second triggers from different audits",
    ),
    pytest.param(
        [trig(0), rrm(0), out("configured", 2)],
        "ambiguous",
        "ambiguous",
        "could not be attributed",
        id="same-second RRM trigger",
    ),
    pytest.param([trig(0), trig(0), out("configured", 2)], "configured", "time", None, id="duplicate own triggers"),
    pytest.param(
        [trig(0), out("configured", 2), rrm(60), out("failed", 60)],
        "ambiguous",
        "ambiguous",
        "could not be attributed",
        id="a foreign trigger in the outcome's own second",
    ),
    pytest.param(
        [trig(0), out("configured", 2), trig(60, OTHER), out("failed", 60)],
        "ambiguous",
        "ambiguous",
        "could not be attributed",
        id="another audit's trigger in the outcome's own second",
    ),
    pytest.param(
        [rrm(-10), trig(0), out("configured", 0)],
        "ambiguous",
        "ambiguous",
        "could not be attributed",
        id="this trigger in the outcome's own second after a foreign trigger",
    ),
    pytest.param([trig(0), out("configured", 0)], "configured", "time", None, id="this trigger alone in its second"),
    pytest.param(
        [trig(0), rrm(0), out("failed", 2), out("configured", 5, AUDIT)],
        "configured",
        "audit_id",
        "could not be attributed",
        id="an ambiguous outcome before the latest assigned outcome is only a gap",
    ),
    pytest.param(
        [trig(0), rrm(0), out("configured", 5, AUDIT), out("failed", 5)],
        "ambiguous",
        "ambiguous",
        "could not be attributed",
        id="an ambiguous outcome in the latest assigned outcome's second",
    ),
    pytest.param(
        [trig(0), trig(0, OTHER), out("configured", 2, AUDIT)],
        "configured",
        "audit_id",
        None,
        id="an exact link beside another audit's same-second trigger",
    ),
    pytest.param(
        [trig(0), trig(0, OTHER), out("configured", 2, AUDIT), out("configured", 3)],
        "ambiguous",
        "ambiguous",
        "could not be attributed",
        id="an ambiguous unlinked outcome beside a confirming exact link",
    ),
    # Receipt-time-only ordering
    pytest.param(
        [trig(0), out("configured", None, AUDIT)],
        "ambiguous",
        "ambiguous",
        "receipt time only",
        id="an outcome without a provider time",
    ),
    pytest.param(
        [trig(None), out("configured", 2, AUDIT)],
        "ambiguous",
        "ambiguous",
        "receipt time only",
        id="an own trigger without a provider time",
    ),
    pytest.param(
        [trig(0), trig(None, OTHER), out("configured", 2, AUDIT)],
        "configured",
        "audit_id",
        None,
        id="another audit's untimed trigger never unsettles an exact link",
    ),
    pytest.param(
        [trig(0), trig(None, OTHER), out("configured", 2)],
        "ambiguous",
        "ambiguous",
        "receipt time only",
        id="another audit's untimed trigger unsettles the time fallback",
    ),
    pytest.param(
        [trig(None, OTHER, received=T0 - timedelta(minutes=1)), trig(0), out("configured", 2)],
        "configured",
        "time",
        None,
        id="an untimed trigger received before this trigger cannot intervene",
    ),
    pytest.param(
        [trig(0), out("configured", 60, AUDIT), out("failed", None, received=T0 + timedelta(seconds=10))],
        "configured",
        "audit_id",
        "receipt time only",
        id="a receipt-time outcome before the latest assigned outcome is only a gap",
    ),
    pytest.param(
        [trig(0), out("configured", 60, AUDIT), out("failed", None, received=T0 + timedelta(minutes=2))],
        "ambiguous",
        "ambiguous",
        "receipt time only",
        id="a receipt-time outcome that may be the latest",
    ),
    pytest.param(
        [
            trig(0),
            out("configured", 2),
            trig(30, OTHER),
            out("failed", None, received=T0 + timedelta(seconds=60)),
        ],
        "ambiguous",
        "ambiguous",
        "receipt time only",
        id="a receipt-time outcome may precede another audit's later trigger",
    ),
    pytest.param(
        [trig(0), out("configured", 60, AUDIT), out("failed", None, AUDIT, received=T0 + timedelta(seconds=10))],
        "configured",
        "audit_id",
        "receipt time only",
        id="a linked receipt-time outcome before the latest assigned outcome is only a gap",
    ),
    pytest.param(
        [trig(0), trig(0, OTHER), out("configured", 2, AUDIT), out("failed", None, OTHER)],
        "configured",
        "audit_id",
        None,
        id="another audit's untimed outcome is irrelevant",
    ),
    pytest.param([trig(None)], "unknown", "none", None, id="an untimed trigger without outcomes stays unknown"),
    # Window
    pytest.param(
        [trig(-30 * MINUTE), out("configured", -30 * MINUTE + 5)],
        "configured",
        "time",
        None,
        id="a trigger at the start of the window, at second precision",
    ),
    pytest.param(
        [trig(-30 * MINUTE - 1), out("configured", -30 * MINUTE + 5)],
        "unknown",
        "none",
        None,
        id="a trigger before the window",
    ),
    pytest.param(
        [trig(0), out("configured", 2, AUDIT, received=AS_OF + timedelta(seconds=1))],
        "unknown",
        "none",
        None,
        id="an outcome received after as_of",
    ),
]


@pytest.mark.parametrize(("receipts", "state", "correlation", "gap"), ASSIGNMENT_CASES)
def test_each_outcome_is_assigned_by_the_pairing_rules(receipts, state, correlation, gap):
    ledger, replay = pair(receipts)
    device = replay.device(X)

    assert device is not None
    assert (device.state, device.correlation) == (state, correlation)
    status = replay.statuses[precondition_of(ledger, X)]
    assert status.status == ("satisfied" if state == "configured" else "unsatisfied")
    if gap is None:
        assert replay.gaps == ()
    else:
        [text] = replay.gaps
        assert gap in text
        assert X in text


def test_an_exact_link_pairs_with_the_latest_own_trigger_not_after_it():
    _, replay = pair([trig(0), trig(60), trig(120), out("configured", 90, AUDIT)])
    device = replay.device(X)
    assert device is not None
    assert device.triggered_at == T0 + timedelta(seconds=120)
    assert device.state == "configured"


def test_an_outcome_occurring_after_as_of_is_not_yet_known():
    _, replay = pair([trig(0), out("configured", 11 * MINUTE)], as_of=T0 + timedelta(minutes=10))
    device = replay.device(X)
    assert device is not None
    assert device.state == "unknown"


@pytest.mark.parametrize(
    ("receipts", "reason"),
    [
        ([trig(0, OTHER), out("configured", 2)], NO_TRIGGER_REASON),
        ([trig(0)], NO_OUTCOME_REASON),
        ([trig(0), out("failed", 2, AUDIT)], FAILED_REASON),
        ([trig(0), out("reverted", 2, AUDIT)], REVERTED_REASON),
        ([trig(0), out("configured", 2, AUDIT), out("failed", 2, AUDIT)], CONFLICT_REASON),
        ([trig(0), rrm(0), out("configured", 2)], AMBIGUOUS_TRIGGERS_REASON),
        ([trig(0), out("configured", 2), rrm(60), out("failed", 60)], AMBIGUOUS_TRIGGERS_REASON),
        ([trig(0), out("configured", 30 * MINUTE + 1)], NO_OUTCOME_REASON),
        (
            [trig(0), rrm(0), out("configured", 2), out("failed", None, received=T0 + timedelta(seconds=60))],
            RECEIPT_TIME_REASON,
        ),
        ([trig(0), out("configured", None)], RECEIPT_TIME_REASON),
    ],
)
def test_an_unsatisfied_precondition_says_why(receipts, reason):
    ledger, replay = pair(receipts)
    assert replay.statuses[precondition_of(ledger, X)].reason == reason


# The per-trigger state machine and its severity projection ---------------------------------------------------------


def linked(*steps: tuple[str, int]) -> list[DeviceEventReceipt]:
    return [trig(0), *(out(kind, at, AUDIT) for kind, at in steps)]


STATE_MACHINE = [
    # outcomes, state, recovered, peak, current, precondition
    pytest.param([], "unknown", False, "none", "none", "unsatisfied", id="none"),
    pytest.param([("configured", 2)], "configured", False, "none", "none", "satisfied", id="configured"),
    pytest.param([("failed", 2)], "failed", False, "warning", "warning", "unsatisfied", id="failed"),
    pytest.param([("reverted", 2)], "reverted", False, "warning", "warning", "unsatisfied", id="reverted"),
    pytest.param(
        [("configured", 2), ("reverted", 60)],
        "reverted",
        False,
        "warning",
        "warning",
        "unsatisfied",
        id="configured then reverted",
    ),
    pytest.param(
        [("failed", 2), ("configured", 60)],
        "configured",
        True,
        "warning",
        "none",
        "satisfied",
        id="failed then configured",
    ),
    pytest.param(
        [("reverted", 2), ("configured", 60)],
        "configured",
        True,
        "warning",
        "none",
        "satisfied",
        id="reverted then configured",
    ),
    pytest.param(
        [("configured", 2), ("failed", 30), ("configured", 60)],
        "configured",
        True,
        "warning",
        "none",
        "satisfied",
        id="failed anywhere then configured",
    ),
    pytest.param(
        [("failed", 2), ("configured", 30), ("failed", 60)],
        "failed",
        False,
        "warning",
        "warning",
        "unsatisfied",
        id="failed again last",
    ),
    pytest.param(
        [("configured", 2), ("configured", 2)],
        "configured",
        False,
        "none",
        "none",
        "satisfied",
        id="duplicate configured in one second",
    ),
    pytest.param(
        [("failed", 2), ("failed", 2)], "failed", False, "warning", "warning", "unsatisfied", id="duplicate failed"
    ),
    pytest.param(
        [("configured", 2), ("failed", 2)],
        "ambiguous",
        False,
        "warning",
        "none",
        "unsatisfied",
        id="conflicting outcomes in one second",
    ),
    pytest.param(
        [("failed", 2), ("reverted", 2)],
        "ambiguous",
        False,
        "warning",
        "warning",
        "unsatisfied",
        id="failed and reverted in one second",
    ),
]


@pytest.mark.parametrize(("steps", "state", "recovered", "peak", "current", "precondition"), STATE_MACHINE)
def test_the_per_trigger_state_machine(steps, state, recovered, peak, current, precondition):  # noqa: PLR0913, PLR0917
    ledger, replay = pair(linked(*steps))
    device = replay.device(X)

    assert device is not None
    assert (device.state, device.recovered) == (state, recovered)
    assert (device.peak, device.current, device.precondition) == (peak, current, precondition)
    assert replay.statuses[precondition_of(ledger, X)].status == precondition
    assert (replay.peak, replay.current) == (peak, current)


def test_duplicate_outcomes_of_one_kind_in_one_second_are_idempotent():
    _, once = pair(linked(("configured", 2)))
    _, twice = pair([*linked(("configured", 2), ("configured", 2)), out("configured", 2)])
    first, second = once.device(X), twice.device(X)

    assert first is not None
    assert second is not None
    assert [(o.kind, o.occurred_at) for o in second.outcomes] == [(o.kind, o.occurred_at) for o in first.outcomes]
    assert second.outcomes[0].count == 3
    assert second.model_dump(exclude={"outcomes"}) == first.model_dump(exclude={"outcomes"})


# The four rows of the severity projection, each reached by exact links and by the time fallback.
PROJECTION = [
    pytest.param([("configured", 2)], "none", "none", "satisfied", id="only configured"),
    pytest.param(
        [("failed", 2), ("configured", 9)], "warning", "none", "satisfied", id="failed or reverted, later configured"
    ),
    pytest.param(
        [("configured", 2), ("reverted", 9)], "warning", "warning", "unsatisfied", id="latest failed or reverted"
    ),
    pytest.param([], "none", "none", "unsatisfied", id="none"),
    pytest.param(
        [("configured", 2), ("reverted", 2)], "warning", "none", "unsatisfied", id="assigned in an unknown order"
    ),
]


@pytest.mark.parametrize("audit", [AUDIT, None], ids=["exact link", "time fallback"])
@pytest.mark.parametrize(("steps", "peak", "current", "precondition"), PROJECTION)
def test_deployment_state_projects_to_severity(steps, peak, current, precondition, audit):
    ledger, replay = pair([trig(0), *(out(kind, at, audit) for kind, at in steps)])
    assert (replay.peak, replay.current) == (peak, current)
    assert replay.statuses[precondition_of(ledger, X)].status == precondition


@pytest.mark.parametrize(
    ("receipts", "state"),
    [
        pytest.param([trig(0), rrm(0), out("failed", 2)], "ambiguous", id="same-second foreign trigger"),
        pytest.param([trig(0), out("failed", 2), rrm(2), out("reverted", 2)], "ambiguous", id="own-second foreign"),
        pytest.param([trig(0), out("failed", 31 * MINUTE)], "unknown", id="outside the bound"),
        pytest.param([trig(0), out("failed", None)], "ambiguous", id="receipt time only"),
    ],
)
def test_outcomes_that_cannot_be_assigned_never_project_severity(receipts, state):
    ledger, replay = pair(receipts)
    device = replay.device(X)
    assert device is not None
    assert (device.state, device.peak, device.current, device.precondition) == (state, "none", "none", "unsatisfied")
    assert replay.statuses[precondition_of(ledger, X)].status == "unsatisfied"


@pytest.mark.parametrize(
    ("receipts", "expected"),
    [
        pytest.param(
            [trig(0), rrm(0), out("failed", 2, AUDIT), out("configured", 3)],
            ("ambiguous", "warning", "none", "unsatisfied"),
            id="an exact failed beside an RRM-tied outcome that may be the latest",
        ),
        pytest.param(
            [trig(0), out("failed", 2, AUDIT), rrm(60), out("configured", 60)],
            ("ambiguous", "warning", "none", "unsatisfied"),
            id="an exact failed beside an outcome in a foreign trigger's second",
        ),
        pytest.param(
            [trig(0), out("reverted", 2, AUDIT), out("configured", None, received=T0 + timedelta(minutes=1))],
            ("ambiguous", "warning", "none", "unsatisfied"),
            id="an exact reverted beside a receipt-time outcome that may be the latest",
        ),
        pytest.param(
            [trig(0), out("failed", 2), out("configured", 2)],
            ("ambiguous", "warning", "none", "unsatisfied"),
            id="a conflicting set paired by time",
        ),
        pytest.param(
            [trig(0), rrm(0), out("configured", 2), out("failed", 5, AUDIT)],
            ("failed", "warning", "warning", "unsatisfied"),
            id="an ambiguous outcome before the latest assigned one changes nothing",
        ),
    ],
)
def test_ambiguity_never_erases_a_warning_from_outcomes_assigned_to_this_trigger(receipts, expected):
    _, replay = pair(receipts)
    device = replay.device(X)
    assert device is not None
    assert (device.state, device.peak, device.current, device.precondition) == expected
    assert (replay.peak, replay.current) == expected[1:3]


# The same-second conflict matrix -----------------------------------------------------------------------------------

# Two outcomes in second 60, optionally an earlier one at 10 and a later one at 120, all linked to this audit:
# first, second, earlier, later -> state, peak, current, precondition.
SAME_SECOND = [
    ("configured", "configured", None, None, "configured", "none", "none", "satisfied"),
    ("configured", "configured", None, "configured", "configured", "none", "none", "satisfied"),
    ("configured", "configured", None, "failed", "failed", "warning", "warning", "unsatisfied"),
    ("configured", "configured", None, "reverted", "reverted", "warning", "warning", "unsatisfied"),
    ("configured", "configured", "failed", None, "configured", "warning", "none", "satisfied"),
    ("configured", "configured", "failed", "configured", "configured", "warning", "none", "satisfied"),
    ("configured", "configured", "failed", "failed", "failed", "warning", "warning", "unsatisfied"),
    ("configured", "configured", "failed", "reverted", "reverted", "warning", "warning", "unsatisfied"),
    ("configured", "failed", None, None, "ambiguous", "warning", "none", "unsatisfied"),
    ("configured", "failed", None, "configured", "configured", "warning", "none", "satisfied"),
    ("configured", "failed", None, "failed", "failed", "warning", "warning", "unsatisfied"),
    ("configured", "failed", None, "reverted", "reverted", "warning", "warning", "unsatisfied"),
    ("configured", "failed", "failed", None, "ambiguous", "warning", "none", "unsatisfied"),
    ("configured", "failed", "failed", "configured", "configured", "warning", "none", "satisfied"),
    ("configured", "failed", "failed", "failed", "failed", "warning", "warning", "unsatisfied"),
    ("configured", "failed", "failed", "reverted", "reverted", "warning", "warning", "unsatisfied"),
    ("configured", "reverted", None, None, "ambiguous", "warning", "none", "unsatisfied"),
    ("configured", "reverted", None, "configured", "configured", "warning", "none", "satisfied"),
    ("configured", "reverted", None, "failed", "failed", "warning", "warning", "unsatisfied"),
    ("configured", "reverted", None, "reverted", "reverted", "warning", "warning", "unsatisfied"),
    ("configured", "reverted", "failed", None, "ambiguous", "warning", "none", "unsatisfied"),
    ("configured", "reverted", "failed", "configured", "configured", "warning", "none", "satisfied"),
    ("configured", "reverted", "failed", "failed", "failed", "warning", "warning", "unsatisfied"),
    ("configured", "reverted", "failed", "reverted", "reverted", "warning", "warning", "unsatisfied"),
    ("failed", "failed", None, None, "failed", "warning", "warning", "unsatisfied"),
    ("failed", "failed", None, "configured", "configured", "warning", "none", "satisfied"),
    ("failed", "failed", None, "failed", "failed", "warning", "warning", "unsatisfied"),
    ("failed", "failed", None, "reverted", "reverted", "warning", "warning", "unsatisfied"),
    ("failed", "failed", "failed", None, "failed", "warning", "warning", "unsatisfied"),
    ("failed", "failed", "failed", "configured", "configured", "warning", "none", "satisfied"),
    ("failed", "failed", "failed", "failed", "failed", "warning", "warning", "unsatisfied"),
    ("failed", "failed", "failed", "reverted", "reverted", "warning", "warning", "unsatisfied"),
    ("failed", "reverted", None, None, "ambiguous", "warning", "warning", "unsatisfied"),
    ("failed", "reverted", None, "configured", "configured", "warning", "none", "satisfied"),
    ("failed", "reverted", None, "failed", "failed", "warning", "warning", "unsatisfied"),
    ("failed", "reverted", None, "reverted", "reverted", "warning", "warning", "unsatisfied"),
    ("failed", "reverted", "failed", None, "ambiguous", "warning", "warning", "unsatisfied"),
    ("failed", "reverted", "failed", "configured", "configured", "warning", "none", "satisfied"),
    ("failed", "reverted", "failed", "failed", "failed", "warning", "warning", "unsatisfied"),
    ("failed", "reverted", "failed", "reverted", "reverted", "warning", "warning", "unsatisfied"),
    ("reverted", "reverted", None, None, "reverted", "warning", "warning", "unsatisfied"),
    ("reverted", "reverted", None, "configured", "configured", "warning", "none", "satisfied"),
    ("reverted", "reverted", None, "failed", "failed", "warning", "warning", "unsatisfied"),
    ("reverted", "reverted", None, "reverted", "reverted", "warning", "warning", "unsatisfied"),
    ("reverted", "reverted", "failed", None, "reverted", "warning", "warning", "unsatisfied"),
    ("reverted", "reverted", "failed", "configured", "configured", "warning", "none", "satisfied"),
    ("reverted", "reverted", "failed", "failed", "failed", "warning", "warning", "unsatisfied"),
    ("reverted", "reverted", "failed", "reverted", "reverted", "warning", "warning", "unsatisfied"),
]


@pytest.mark.parametrize(
    ("first", "second", "earlier", "later", "state", "peak", "current", "precondition"), SAME_SECOND
)
def test_same_second_outcome_matrix(first, second, earlier, later, state, peak, current, precondition):  # noqa: PLR0913, PLR0917
    steps = [(first, 60), (second, 60)]
    if earlier is not None:
        steps.insert(0, (earlier, 10))
    if later is not None:
        steps.append((later, 120))
    ledger, replay = pair(linked(*steps))
    device = replay.device(X)
    assert device is not None

    assert (device.state, device.peak, device.current, device.precondition) == (state, peak, current, precondition)
    assert replay.statuses[precondition_of(ledger, X)].status == precondition


def test_the_same_second_matrix_covers_every_pair_before_and_after():
    pairs = {(row[0], row[1]) for row in SAME_SECOND}
    assert pairs == set(itertools.combinations_with_replacement(("configured", "failed", "reverted"), 2))
    assert {(row[2], row[3]) for row in SAME_SECOND} == set(
        itertools.product((None, "failed"), (None, "configured", "failed", "reverted"))
    )
    assert len(SAME_SECOND) == len(pairs) * 8


# Same-second triggers from each identity, against an outcome linked to this audit, to another audit or to none.
COMPANIONS = {
    "this audit": lambda: trig(0),
    "another audit": lambda: trig(0, OTHER),
    "RRM": lambda: rrm(0),
    "no audit": lambda: trig(0, None),
}


@pytest.mark.parametrize("companion", list(COMPANIONS))
@pytest.mark.parametrize("link", ["this audit", "another audit", "none"])
def test_same_second_trigger_matrix(companion, link):
    audit = {"this audit": AUDIT, "another audit": OTHER, "none": None}[link]
    ledger, replay = pair([trig(0), COMPANIONS[companion](), out("configured", 2, audit)])
    device = replay.device(X)
    assert device is not None

    if link == "this audit" or (link == "none" and companion == "this audit"):
        expected = "configured"
    elif link == "another audit":
        expected = "unknown"
    else:
        expected = "ambiguous"
    assert device.state == expected
    assert replay.statuses[precondition_of(ledger, X)].status == (
        "satisfied" if expected == "configured" else "unsatisfied"
    )
    # An outcome linked to another audit pairs with that audit's trigger when there is one, never with ours.
    unmatched = [gap for gap in replay.gaps if "no matching earlier trigger" in gap]
    assert bool(unmatched) == (link == "another audit" and companion != "another audit")


# Scope and determinism ---------------------------------------------------------------------------------------------


def test_only_preconditioned_devices_get_statuses_but_every_row_device_projects_severity():
    ledger = ledger_for(X, Y, targeted=(X,))
    replay = pair_deployments(
        [trig(0), out("configured", 2, AUDIT), trig(0, mac=Y), out("failed", 2, AUDIT, mac=Y)],
        frame=frame(),
        ledger=ledger,
    )

    assert set(replay.statuses) == {precondition_of(ledger, X)}
    assert [device.mac for device in replay.devices] == [X, Y]
    assert (replay.peak, replay.current) == ("warning", "warning")


def test_pairing_does_not_depend_on_receipt_order():
    receipts = [
        trig(0),
        trig(0, OTHER, mac=Y),
        out("failed", 2, mac=Y),
        trig(1, mac=Y),
        out("configured", 3, mac=Y),
        out("failed", 2, AUDIT),
        out("configured", 40, AUDIT),
        rrm(90, mac=Z),
        trig(80, mac=Z),
        out("configured", 95, mac=Z),
        out("configured", 30 * MINUTE + 100, mac=Z),
    ]
    ledger = ledger_for(X, Y, Z)
    expected = pair_deployments(receipts, frame=frame(), ledger=ledger)
    shuffled = list(receipts)
    for seed in range(10):
        random.Random(seed).shuffle(shuffled)  # noqa: S311 - a reproducible shuffle, not a secret
        assert pair_deployments(shuffled, frame=frame(), ledger=ledger) == expected


# The DNT-NTR regression: a 242 ms audit time against whole-second device events ------------------------------------


def dnt_ntr_receipts(*, sw_configured: bool = False) -> list[DeviceEventReceipt]:
    recorded = load_fixture("dnt_ntr_device_events.json")
    receipts = [
        DeviceEventReceipt(
            receipt_id=item["receipt_id"],
            received_at=datetime.fromisoformat(item["received_at"]),
            event_type=item["event_type"],
            device_mac=item["device_mac"],
            site_id=recorded["site_id"],
            occurred_at=datetime.fromisoformat(item["occurred_at"]),
            audit_id=item["audit_id"],
        )
        for item in recorded["receipts"]
    ]
    if sw_configured:
        receipts += [
            DeviceEventReceipt(
                receipt_id=f"sw-configured-{mac}",
                received_at=datetime(2026, 9, 16, 4, 41, 49, tzinfo=UTC),
                event_type="SW_CONFIGURED",
                device_mac=mac,
                site_id=recorded["site_id"],
                occurred_at=datetime(2026, 9, 16, 4, 41, 40, tzinfo=UTC),
            )
            for mac in ("020000000011", "020000000012", "020000000013")
        ]
    return receipts


@pytest.mark.parametrize("audit_time", [datetime(2026, 9, 16, 4, 41, 35, 242_000, tzinfo=UTC), None])
def test_the_242_ms_audit_time_never_turns_same_second_triggers_into_unknown(audit_time):
    change = load_fixture("dnt_ntr_change.json")
    audit_id = change["audit"]["audit_id"]
    assert datetime.fromisoformat(change["audit"]["occurred_at"]) == datetime(
        2026, 9, 16, 4, 41, 35, 242_000, tzinfo=UTC
    )
    receipts = dnt_ntr_receipts()
    anchor = resolve_anchor(
        receipts,
        audit_id=audit_id,
        audit_time=audit_time,
        received_at=datetime(2026, 9, 16, 4, 41, 40, tzinfo=UTC),
        as_of=datetime(2026, 9, 16, 5, 42, 30, tzinfo=UTC),
    )
    devices = expected_devices(receipts, audit_id=audit_id, as_of=datetime(2026, 9, 16, 5, 42, 30, tzinfo=UTC))
    assert [device.mac for device in devices] == [item["device_mac"] for item in change["devices"]]
    triggers = [r for r in receipts if r.event_type.endswith("_CONFIG_CHANGED_BY_USER")]
    if audit_time is not None:
        # The regression: every trigger precedes the millisecond anchor, and none precedes it at second precision.
        assert all(r.occurred_at is not None and r.occurred_at < anchor.changed_at for r in triggers)
    assert all(provider_second(anchor.changed_at) <= r.occurred_at for r in triggers if r.occurred_at)

    ledger = ledger_for(*(device.mac for device in devices))
    replay_frame = ReplayFrame(audit_id=audit_id, anchor=anchor, as_of=datetime(2026, 9, 16, 5, 42, 30, tzinfo=UTC))
    replay = pair_deployments(receipts, frame=replay_frame, ledger=ledger)

    states = {device.mac: (device.state, device.precondition) for device in replay.devices}
    assert states == {
        "020000000011": ("unknown", "unsatisfied"),
        "020000000012": ("unknown", "unsatisfied"),
        "020000000013": ("unknown", "unsatisfied"),
        "020000000021": ("configured", "satisfied"),
        "020000000022": ("configured", "satisfied"),
        "020000000023": ("configured", "satisfied"),
        "020000000031": ("configured", "satisfied"),
    }
    for mac in ("020000000011", "020000000012", "020000000013"):
        assert replay.statuses[precondition_of(ledger, mac)].reason == NO_OUTCOME_REASON
    assert replay.gaps == ()
    assert (replay.peak, replay.current) == ("none", "none")

    confirmed = pair_deployments(dnt_ntr_receipts(sw_configured=True), frame=replay_frame, ledger=ledger)
    assert {device.precondition for device in confirmed.devices} == {"satisfied"}


# Evidence ----------------------------------------------------------------------------------------------------------


def test_deployment_evidence_is_one_item_with_full_rows_for_unsatisfied_or_warning_devices():
    ledger = ledger_for(X, Y, Z)
    replay = pair_deployments(
        [
            trig(0),
            out("configured", 2, AUDIT),
            trig(0, mac=Y),
            out("failed", 2, AUDIT, mac=Y),
            out("configured", 9, AUDIT, mac=Y),
            trig(0, mac=Z),
        ],
        frame=frame(),
        ledger=ledger,
    )
    registry = EvidenceRegistry()
    registry.reserve("rule:dns")
    conclusion = record_deployment(replay, frame=frame(), registry=registry)

    [item] = registry.evidence
    assert (item.id, item.source, item.kind, item.representation) == ("E2", "deployment", "deployment", "digest")
    rows = item.payload["rows"]
    assert isinstance(rows, list)
    assert [row["mac"] for row in rows] == [Z, Y]
    assert item.payload["omitted"] == {"satisfied:none": 1}
    assert item.window is not None
    assert (item.window.start, item.window.end) == (T0 - timedelta(minutes=30), AS_OF)
    assert all(status.evidence_ids == ("E2",) for status in conclusion.statuses.values())
    assert {o: s.status for o, s in conclusion.statuses.items()} == {
        precondition_of(ledger, X): "satisfied",
        precondition_of(ledger, Y): "satisfied",
        precondition_of(ledger, Z): "unsatisfied",
    }
    assert (conclusion.peak, conclusion.current) == ("warning", "none")
    assert [(d.mac, d.severity, d.evidence_ids) for d in conclusion.impacted_devices] == [(Y, "warning", ("E2",))]
    assert conclusion.gaps == replay.gaps


def test_deployment_evidence_for_1000_devices_stays_within_its_budget():
    macs = tuple(f"02{number:010x}" for number in range(1_000))
    ledger = ledger_for(*macs)
    receipts = [trig(0, mac=mac) for mac in macs]
    receipts += [out("failed" if number % 3 else "configured", 2, AUDIT, mac=mac) for number, mac in enumerate(macs)]
    replay = pair_deployments(receipts, frame=frame(), ledger=ledger)
    registry = EvidenceRegistry()
    conclusion = record_deployment(replay, frame=frame(), registry=registry)

    [item] = registry.evidence
    assert json_size(item) <= DEPLOYMENT_EVIDENCE_BUDGET
    rows = item.payload["rows"]
    omitted = item.payload["omitted"]
    assert isinstance(rows, list)
    assert isinstance(omitted, dict)
    assert len(rows) + sum(omitted.values()) == 1_000
    assert len(conclusion.statuses) == 1_000


def test_no_row_devices_record_no_deployment_evidence():
    ledger = ledger_for()
    replay = pair_deployments([trig(0), out("configured", 2)], frame=frame(), ledger=ledger)
    registry = EvidenceRegistry()
    conclusion = record_deployment(replay, frame=frame(), registry=registry)

    assert registry.evidence == ()
    assert conclusion.statuses == {}
    assert (conclusion.peak, conclusion.current) == ("none", "none")
