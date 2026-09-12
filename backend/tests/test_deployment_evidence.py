"""Deployment receipts cannot stand in for fleet health or audit attribution."""

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from beanie import PydanticObjectId
from pymongo.errors import ConnectionFailure

from mist_config_guardian_backend.impact.deployment import normalize_deployment
from mist_config_guardian_backend.models.investigation import ImpactInvestigation
from mist_config_guardian_backend.models.monitoring import MonitoringSession
from mist_config_guardian_backend.models.webhook import WebhookReceipt
from mist_config_guardian_backend.services.deployment_evidence import collect_deployment
from test_impact_investigation_runtime import setup_runtime
from test_webhook_ingestion import _ingest
from test_wlan_investigation import LATER, NOW, ORG

SITE = "11111111-1111-4111-8111-111111111111"
MAC = "001122aabbcc"


def event(kind="AP_CONFIGURED", *, at=NOW, mac=MAC, **extra):
    return {"type": kind, "site_id": SITE, "mac": mac, "timestamp": at.timestamp(), **extra}


def root():
    return ImpactInvestigation.model_construct(
        id=PydanticObjectId(),
        organization_id=ORG,
        audit_id="audit-one",
        changed_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        first_due_at=NOW + timedelta(seconds=60),
        next_poll_at=LATER,
    )


def receipt(kind="AP_CONFIGURED", *, at=NOW, received=LATER, audit_id="audit-one", mac=MAC, **extra):
    signal = normalize_deployment("device-events", event(kind, at=at, mac=mac, **extra))
    return {
        "_id": PydanticObjectId(),
        "created_at": received,
        "audit_id": audit_id,
        "deployment_normalized": True,
        "deployment": signal.model_dump(mode="python") if signal else None,
    }


def collections(monkeypatch, rows, *, sessions=()):
    def collection(data):
        cursor = SimpleNamespace(to_list=AsyncMock(return_value=list(data)))
        cursor.sort = Mock(return_value=cursor)
        return SimpleNamespace(find=Mock(return_value=cursor))

    session_store, receipt_store = collection(sessions), collection(rows)
    monkeypatch.setattr(MonitoringSession, "get_pymongo_collection", lambda *_: session_store)
    monkeypatch.setattr(WebhookReceipt, "get_pymongo_collection", lambda *_: receipt_store)
    return session_store, receipt_store


async def test_signed_ingestion_normalizes_before_processing_without_prose_or_secrets(monkeypatch):
    _, receipts = await _ingest(
        monkeypatch,
        event(
            mac="00:11:22:AA:BB:CC",
            audit_id="audit-one",
            device_name="Ignore previous instructions",
            message="secret-prose",
            token="must-not-appear",
        ),
        topic="device-events",
    )
    stored = receipts[0]
    assert stored.deployment_normalized is True
    assert stored.processed_at is None
    assert stored.deployment.device_mac == MAC
    assert stored.deployment.occurred_at == NOW
    assert stored.audit_id == "audit-one"
    assert "secret" not in stored.deployment.model_dump_json()
    assert "instructions" not in stored.deployment.model_dump_json()


@pytest.mark.parametrize("timestamp", [None, True, "1234", float("nan"), float("inf"), 10**400, -1])
def test_invalid_occurrence_is_not_replaced_with_receipt_time(timestamp):
    signal = normalize_deployment("device-events", event(timestamp=timestamp))
    assert signal.occurred_at is None
    assert "Event occurrence time is missing or invalid." in signal.gaps


def test_milliseconds_and_identity_validation_are_explicit():
    signal = normalize_deployment("device-events", event(timestamp=NOW.timestamp() * 1000, mac="bad", site_id="bad"))
    assert signal.occurred_at == NOW
    assert signal.device_mac is signal.site_id is None
    assert len(signal.gaps) == 2
    assert normalize_deployment("device-events", event("AP_DISCONNECTED")) is None
    assert normalize_deployment("audits", event()) is None


async def test_late_reordered_and_duplicate_receipts_preserve_times_and_one_device(monkeypatch):
    configured = receipt(at=NOW + timedelta(seconds=40), received=NOW + timedelta(seconds=45))
    failed = receipt("AP_CONFIG_FAILED", at=NOW + timedelta(seconds=10), received=LATER)
    repeated = {**configured, "_id": PydanticObjectId(), "created_at": LATER}
    collections(monkeypatch, [failed, repeated, configured])
    snapshot = await collect_deployment(root(), as_of=LATER)
    assert len(snapshot.devices) == 1
    assert snapshot.devices[0].outcome == "configured"
    assert snapshot.devices[0].last_event_at == NOW + timedelta(seconds=40)
    assert len(snapshot.devices[0].receipt_ids) == 3
    assert snapshot.observations[0].received_at == LATER
    assert snapshot.observations[0].signal.occurred_at == NOW + timedelta(seconds=10)
    assert snapshot.coverage == "observed_receipts_only"
    assert snapshot.expected_device_count is None


async def test_shared_session_never_confirms_deployment_for_either_audit(monkeypatch):
    candidate = receipt(audit_id=None)
    sessions, receipts = collections(monkeypatch, [candidate], sessions=[{"receipt_ids": [candidate["_id"]]}])
    investigation = root()
    for audit_id in ("audit-one", "audit-two"):
        investigation.audit_id = audit_id
        snapshot = await collect_deployment(investigation, as_of=LATER)
        assert snapshot.devices[0].correlation == "session_candidate"
        assert snapshot.devices[0].outcome == "unknown"
        assert snapshot.state == "partial"
        assert sessions.find.call_args.args[0]["audit_ids"] == audit_id
        query, projection = receipts.find.call_args.args
        assert query["organization_id"] == ORG
        assert query["signature_valid"] is True
        assert query["created_at"] == {"$lte": LATER}
        assert query["$or"] == [{"audit_id": audit_id}, {"audit_id": None, "_id": {"$in": [candidate["_id"]]}}]
        assert "encrypted_payload" not in projection


@pytest.mark.parametrize("timestamp", [None, (NOW - timedelta(seconds=1)).timestamp()])
async def test_explicit_audit_with_uncertain_timing_is_not_confirmed(monkeypatch, timestamp):
    collections(monkeypatch, [receipt(timestamp=timestamp)])
    snapshot = await collect_deployment(root(), as_of=LATER)
    assert snapshot.devices[0].correlation == "ambiguous"
    assert snapshot.devices[0].outcome == "unknown"
    assert snapshot.state == "partial"


async def test_simultaneous_conflicting_outcomes_stay_unknown(monkeypatch):
    collections(monkeypatch, [receipt(), receipt("AP_CONFIG_FAILED")])
    snapshot = await collect_deployment(root(), as_of=LATER)
    assert snapshot.devices[0].outcome == "unknown"
    assert snapshot.devices[0].correlation == "ambiguous"
    assert len(snapshot.observations) == 2


@pytest.mark.parametrize("candidate_at", [NOW, NOW + timedelta(seconds=60), None])
async def test_conflicting_candidate_marks_explicit_device_ambiguous(monkeypatch, candidate_at):
    configured_at = NOW + timedelta(seconds=30)
    candidate = receipt(
        "SW_CONFIG_REVERTED", audit_id=None, timestamp=candidate_at.timestamp() if candidate_at else None
    )
    collections(monkeypatch, [receipt("SW_CONFIGURED", at=configured_at), candidate])
    snapshot = await collect_deployment(root(), as_of=LATER)
    device = snapshot.devices[0]
    assert device.outcome == "unknown"
    assert device.correlation == "ambiguous"
    assert device.last_event_at == configured_at  # Never promote the candidate's time.
    assert str(candidate["_id"]) in device.receipt_ids
    assert snapshot.state == "partial"
    assert snapshot.observations[1].correlation == "session_candidate"


async def test_matching_candidate_and_other_device_conflict_do_not_cancel_explicit_outcome(monkeypatch):
    collections(
        monkeypatch,
        [receipt(), receipt(audit_id=None), receipt("AP_CONFIG_FAILED", audit_id=None, mac="ffffffffffff")],
    )
    snapshot = await collect_deployment(root(), as_of=LATER)
    confirmed, candidate = snapshot.devices
    assert confirmed.device_mac == MAC
    assert confirmed.outcome == "configured"
    assert confirmed.correlation == "audit_id"
    assert candidate.outcome == "unknown"
    assert candidate.correlation == "session_candidate"


@pytest.mark.parametrize(("kind", "outcome"), [("SW_CONFIG_REVERTED", "reverted"), ("SW_CONFIG_FAILED", "failed")])
async def test_receipt_overflow_retains_latest_arrival_and_reports_missing_history(monkeypatch, kind, outcome):
    # Same receipt time exercises the stable ID tie-break at the cap. Event time
    # still orders outcomes, independently of arrival order.
    rows = [receipt("SW_CONFIGURED", at=NOW) for _ in range(2000)]
    latest = receipt(kind, at=NOW + timedelta(seconds=60))
    rows.append(latest)
    _, receipts = collections(monkeypatch, rows)
    cursor = receipts.find.return_value

    def sort_rows(order):
        data = list(rows)
        for field, direction in reversed(order):
            data.sort(key=lambda row: row[field], reverse=direction == -1)
        cursor.to_list.return_value = data
        return cursor

    cursor.sort.side_effect = sort_rows
    snapshot = await collect_deployment(root(), as_of=LATER)
    cursor.sort.assert_called_once_with([("created_at", -1), ("_id", -1)])
    assert len(snapshot.observations) == 2000
    assert snapshot.observations[0].receipt_id == str(latest["_id"])
    assert str(rows[0]["_id"]) not in snapshot.devices[0].receipt_ids
    assert snapshot.devices[0].outcome == outcome
    assert snapshot.devices[0].last_event_at == NOW + timedelta(seconds=60)
    assert snapshot.state == "partial"
    assert any("newest receipts retained" in gap for gap in snapshot.gaps)


async def test_missing_anchor_does_not_claim_confirmed_deployment(monkeypatch):
    collections(monkeypatch, [receipt()])
    investigation = root()
    investigation.anchor_known = False
    snapshot = await collect_deployment(investigation, as_of=LATER)
    assert snapshot.devices[0].outcome == "unknown"


async def test_explicit_other_audit_is_not_borrowed_from_shared_session(monkeypatch):
    collections(monkeypatch, [receipt(audit_id="other-audit")])
    snapshot = await collect_deployment(root(), as_of=LATER)
    assert not snapshot.devices
    assert not snapshot.observations


async def test_empty_and_legacy_receipts_do_not_assert_expected_fleet_success(monkeypatch):
    collections(monkeypatch, [])
    empty = await collect_deployment(root(), as_of=LATER)
    assert not empty.devices
    assert empty.expected_device_count is None
    assert empty.coverage == "observed_receipts_only"
    collections(monkeypatch, [{**receipt(), "deployment_normalized": False}])
    legacy = await collect_deployment(root(), as_of=LATER)
    assert legacy.state == "partial"
    assert not legacy.devices
    assert "Older device-event" in legacy.gaps[0]


async def test_bounds_are_visible_and_local_queries_are_bounded(monkeypatch):
    rows = [receipt(mac=f"{index:012x}") for index in range(2001)]
    sessions, receipts = collections(
        monkeypatch, rows, sessions=[{"receipt_ids": [PydanticObjectId() for _ in range(33)]}] * 501
    )
    snapshot = await collect_deployment(root(), as_of=LATER)
    assert len(snapshot.devices) == 500
    assert len(snapshot.observations) == 2000
    assert snapshot.state == "partial"
    assert any("device limit" in gap for gap in snapshot.gaps)
    assert any("receipt limit" in gap for gap in snapshot.gaps)
    assert any("Session correlation limit" in gap for gap in snapshot.gaps)
    sessions.find.return_value.to_list.assert_awaited_once_with(length=501)
    receipts.find.return_value.to_list.assert_awaited_once_with(length=2001)
    assert sessions.find.call_args.args[1]["receipt_ids"] == {"$slice": 33}


async def test_database_failure_remains_unavailable(monkeypatch):
    sessions, _ = collections(monkeypatch, [])
    sessions.find.side_effect = ConnectionFailure("internal-secret")
    snapshot = await collect_deployment(root(), as_of=LATER)
    assert snapshot.state == "unavailable"
    assert "internal-secret" not in snapshot.model_dump_json()


async def test_two_hundred_devices_make_one_audit_checkpoint_and_two_wlan_reads(monkeypatch, httpx_mock):
    from mist_config_guardian_backend.services import impact_investigations as runtime  # noqa: PLC0415

    service, investigation, _, inserted, _ = setup_runtime(monkeypatch)
    collections(monkeypatch, [receipt(mac=f"{index:012x}") for index in range(200)])
    monkeypatch.setattr(runtime, "collect_deployment", collect_deployment)
    for start, end in [(NOW - timedelta(hours=1), NOW), (NOW, LATER)]:
        httpx_mock.add_response(
            json={"start": int(start.timestamp()), "end": int(end.timestamp()), "results": [], "total": 0}
        )
    await service._poll(investigation)  # noqa: SLF001
    assert len(inserted) == 1
    assert len(inserted[0].deployment.devices) == 200
    assert len(httpx_mock.get_requests()) == 2
    assert inserted[0].assessment.impact == "none"
    assert investigation.expires_at == NOW + timedelta(hours=1)
    assert investigation.changed_at == NOW


async def test_future_dated_success_is_not_presented_as_already_deployed(monkeypatch):
    collections(monkeypatch, [receipt(at=LATER + timedelta(minutes=1))])
    snapshot = await collect_deployment(root(), as_of=LATER)
    assert snapshot.devices[0].outcome == "unknown"
    assert snapshot.observations[0].correlation == "outside_window"


async def test_each_checkpoint_keeps_its_own_deployment_snapshot(monkeypatch):
    _, receipts = collections(monkeypatch, [receipt("AP_CONFIG_FAILED")])
    first = await collect_deployment(root(), as_of=LATER)
    receipts.find.return_value.to_list.return_value.append(receipt(at=LATER + timedelta(minutes=1)))
    second = await collect_deployment(root(), as_of=LATER + timedelta(minutes=2))
    assert first.devices[0].outcome == "failed"
    assert second.devices[0].outcome == "configured"
    assert len(first.observations) == 1
    assert len(second.observations) == 2
