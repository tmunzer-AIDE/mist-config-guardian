"""A device event is attributed to the session it actually changed."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest
from beanie import PydanticObjectId
from beanie.odm.fields import ExpressionField
from beanie.odm.utils.pydantic import get_model_fields

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.monitoring import (
    DeviceType,
    ImpactSeverity,
    MonitoringSession,
    MonitoringStatus,
    SleObservation,
)
from mist_config_guardian_backend.models.organization import (
    MistCloudRegion,
    Organization,
    OrganizationStatus,
)
from mist_config_guardian_backend.models.telemetry import DeviceStateObservation
from mist_config_guardian_backend.models.webhook import WebhookProcessingStatus, WebhookReceipt
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services import monitoring
from mist_config_guardian_backend.services.monitoring import MonitoringEventService
from mist_config_guardian_backend.services.webhook_processing import WebhookProcessingService

ORGANIZATION_ID = PydanticObjectId()
NOW = datetime(2026, 9, 7, 14, 22, tzinfo=UTC)
MAC = "5c5b351a2ba1"


def _bind_query_fields(model: type) -> None:
    """Attach the query expression fields Beanie normally installs at init."""
    for name, field in get_model_fields(model).items():
        setattr(model, name, ExpressionField(field.alias or name))


_bind_query_fields(MonitoringSession)


def _session(
    *,
    status: MonitoringStatus,
    audit_ids: list[str],
    active: bool = True,
    created_at: datetime = NOW,
) -> MonitoringSession:
    return MonitoringSession.model_construct(
        id=PydanticObjectId(),
        organization_id=ORGANIZATION_ID,
        audit_ids=audit_ids,
        receipt_ids=[],
        site_id="site-1",
        device_mac=MAC,
        device_name="SEA-AP-101",
        device_type=DeviceType.AP,
        status=status,
        active=active,
        impact_severity=ImpactSeverity.NONE,
        observations=[],
        incidents=[],
        degraded_metrics=[],
        warnings=[],
        created_at=created_at,
        updated_at=created_at,
    )


def _receipt() -> WebhookReceipt:
    return WebhookReceipt.model_construct(
        id=PydanticObjectId(),
        organization_id=ORGANIZATION_ID,
        topic="device-events",
        event_id="event-1",
        audit_id=None,
        payload_hash="hash",
        encrypted_payload="v1:cipher",
        signature_version="v2",
        signature_valid=True,
        status=WebhookProcessingStatus.PROCESSING,
        processing_attempts=1,
        created_at=NOW,
        updated_at=NOW,
    )


def _organization() -> Organization:
    return Organization.model_construct(
        id=ORGANIZATION_ID,
        mist_org_id="org-1",
        name="Lab",
        cloud_region=MistCloudRegion.GLOBAL_01,
        status=OrganizationStatus.VERIFIED,
        encrypted_service_token="v1:encrypted-value",
        service_token_last_four="alue",
    )


def _handler() -> MonitoringEventService:
    return MonitoringEventService(CredentialVault(Settings(environment="test", database_enabled=False)))


class _RecordingProjector:
    def __init__(self) -> None:
        self.rebuilt: list[tuple[PydanticObjectId, str]] = []

    async def rebuild(self, organization_id: PydanticObjectId, audit_id: str) -> None:
        self.rebuilt.append((organization_id, audit_id))


def _install_active_session(monkeypatch: pytest.MonkeyPatch, session: MonitoringSession | None) -> None:
    """Answer the handler's lookup for the device's active session, and swallow saves."""

    async def find_one(*_args: object, **_kwargs: object) -> MonitoringSession | None:
        if len(_args) == 1 and isinstance(_args[0], dict) and "receipt_ids" in _args[0]:
            return session if session and _args[0]["receipt_ids"] in session.receipt_ids else None
        return session if session and session.active else None

    async def save(self: MonitoringSession, *_args: object, **_kwargs: object) -> MonitoringSession:
        return self

    monkeypatch.setattr(MonitoringSession, "find_one", find_one)
    monkeypatch.setattr(MonitoringSession, "save", save)


# ------------------------------------------------------------------- handler


async def test_a_failure_reports_the_session_it_just_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """The closed session is the one to rebuild.

    A configuration failure ends its session, so a lookup for the device's
    active session afterwards finds nothing, and an unordered lookup could find
    an earlier session and attribute the failure to an unrelated change.
    """
    session = _session(status=MonitoringStatus.AWAITING_CONFIG, audit_ids=["audit-7"])
    _install_active_session(monkeypatch, session)

    reported = await _handler().handle(
        _receipt(),
        {"type": "AP_CONFIG_FAILED", "mac": "5c:5b:35:1a:2b:a1", "site_id": "site-1"},
        _organization(),
    )

    assert reported is session
    assert session.active is False
    assert session.status is MonitoringStatus.FAILED


async def test_an_incident_on_an_unknown_device_reports_no_session(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_active_session(monkeypatch, None)

    reported = await _handler().handle(
        _receipt(),
        {"type": "AP_DISCONNECTED", "mac": MAC, "site_id": "site-1"},
        _organization(),
    )

    assert reported is None


async def test_an_event_that_changes_nothing_reports_no_session(monkeypatch: pytest.MonkeyPatch) -> None:
    """A session exists, but this event type is not one monitoring acts on."""
    _install_active_session(monkeypatch, _session(status=MonitoringStatus.MONITORING, audit_ids=["audit-7"]))

    reported = await _handler().handle(
        _receipt(),
        {"type": "AP_RESTARTED", "mac": MAC, "site_id": "site-1"},
        _organization(),
    )

    assert reported is None


# ---------------------------------------------------------------- projection


async def test_projection_trusts_the_handler_over_a_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    def find(*_args: object, **_kwargs: object) -> None:
        msg = "the handler already said which session changed"
        raise AssertionError(msg)

    monkeypatch.setattr(MonitoringSession, "find", find)
    projector = _RecordingProjector()
    session = _session(status=MonitoringStatus.FAILED, audit_ids=["audit-7"], active=False)

    await WebhookProcessingService(vault=None, projector=projector).project(  # type: ignore[arg-type]
        _receipt(),
        {"mac": MAC},
        session=session,
    )

    assert projector.rebuilt == [(ORGANIZATION_ID, "audit-7")]


async def test_projection_without_the_handler_prefers_the_active_then_newest_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Re-projection has no handler answer; it chooses the way the handler would."""
    newest = _session(status=MonitoringStatus.MONITORING, audit_ids=["audit-9"])
    sorts: list[tuple[str, ...]] = []

    class _Query:
        def sort(self, *keys: str) -> "_Query":
            sorts.append(keys)
            return self

        async def first_or_none(self) -> MonitoringSession:
            return newest

    monkeypatch.setattr(MonitoringSession, "find", lambda *_args, **_kwargs: _Query())
    projector = _RecordingProjector()

    await WebhookProcessingService(vault=None, projector=projector).project(  # type: ignore[arg-type]
        _receipt(),
        {"mac": "5C:5B:35:1A:2B:A1"},
    )

    assert sorts == [("-active", "-created_at")]
    assert projector.rebuilt == [(ORGANIZATION_ID, "audit-9")]


async def test_projection_without_a_device_address_rebuilds_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    def find(*_args: object, **_kwargs: object) -> None:
        msg = "no device to look up"
        raise AssertionError(msg)

    monkeypatch.setattr(MonitoringSession, "find", find)
    projector = _RecordingProjector()

    await WebhookProcessingService(vault=None, projector=projector).project(_receipt(), {})  # type: ignore[arg-type]

    assert projector.rebuilt == []


async def test_prechange_captures_immediately_and_monitors_without_a_configured_event(monkeypatch):
    _install_active_session(monkeypatch, None)
    monkeypatch.setattr(MonitoringSession, "get_pymongo_collection", classmethod(lambda _cls: None))
    monkeypatch.setattr(MonitoringSession, "insert", AsyncMock())
    monkeypatch.setattr(monitoring, "utc_now", lambda: NOW)
    initial = DeviceStateObservation(captured_at=NOW)
    handler = _handler()
    baseline = AsyncMock(return_value=SleObservation())
    telemetry = AsyncMock(return_value=initial)
    monkeypatch.setattr(handler, "_capture", baseline)
    monkeypatch.setattr(handler, "_capture_state", telemetry)
    receipt = _receipt()
    session = await handler.handle(
        receipt,
        {
            "type": "AP_CONFIG_CHANGED_BY_USER",
            "mac": MAC,
            "site_id": "site-1",
            "timestamp": NOW.timestamp(),
        },
        _organization(),
    )
    assert session.status is MonitoringStatus.MONITORING
    assert session.monitoring_ends_at == NOW + timedelta(hours=1)
    assert session.next_poll_at == NOW + timedelta(minutes=5)
    assert session.device_comparisons[0].baseline is initial
    assert session.device_comparisons[0].due_at == NOW + timedelta(minutes=5)
    assert baseline.await_args.args[1:] == ("site-1", DeviceType.AP, MAC, NOW)
    telemetry.assert_awaited_once()


async def test_overlapping_triggers_capture_separately_and_receipt_retries_are_idempotent(monkeypatch):
    session = _session(status=MonitoringStatus.MONITORING, audit_ids=["audit-7"])
    _install_active_session(monkeypatch, session)
    monkeypatch.setattr(monitoring, "utc_now", lambda: NOW)
    handler = _handler()
    telemetry = AsyncMock(return_value=DeviceStateObservation(captured_at=NOW))
    monkeypatch.setattr(handler, "_capture_state", telemetry)
    payload = {"type": "AP_CONFIG_CHANGED_BY_USER", "mac": MAC, "site_id": "site-1"}
    receipt = _receipt()
    await handler.handle(receipt, payload, _organization())
    await handler.handle(receipt, payload, _organization())
    await handler.handle(_receipt(), payload, _organization())
    assert len(session.device_comparisons) == 2
    assert telemetry.await_count == 2
    assert len(session.receipt_ids) == 2
    assert session.monitoring_ends_at == NOW + timedelta(hours=1)
    assert len(session.warnings) == 1


@pytest.mark.parametrize("event_type", ["GW_CONFIG_REVERTED", "SW_CONFIG_REVERTED"])
@pytest.mark.parametrize("status", [MonitoringStatus.MONITORING, MonitoringStatus.AWAITING_CONFIG])
async def test_revert_closes_session_and_next_change_gets_a_new_baseline(monkeypatch, event_type, status):
    previous = _session(status=status, audit_ids=["reverted-audit"])
    previous.next_poll_at = NOW
    _install_active_session(monkeypatch, previous)
    monkeypatch.setattr(MonitoringSession, "get_pymongo_collection", classmethod(lambda _cls: None))
    monkeypatch.setattr(MonitoringSession, "insert", AsyncMock())
    monkeypatch.setattr(monitoring, "utc_now", lambda: NOW)
    handler = _handler()
    baseline = AsyncMock(return_value=SleObservation(values={"capacity": 95}))
    monkeypatch.setattr(handler, "_capture", baseline)
    monkeypatch.setattr(handler, "_capture_state", AsyncMock(return_value=DeviceStateObservation(captured_at=NOW)))
    receipt = _receipt()
    payload = {"type": event_type, "mac": MAC, "site_id": "site-1"}

    assert await handler.handle(receipt, payload, _organization()) is previous
    assert previous.status is MonitoringStatus.FAILED
    assert previous.active is False
    assert previous.completed_at == NOW
    assert previous.next_poll_at is None
    assert previous.impact_severity is ImpactSeverity.CRITICAL
    assert "reverted" in previous.deterministic_summary
    # A retry must find the closed session, without duplicating its incident.
    assert await handler.handle(receipt, payload, _organization()) is previous
    assert len(previous.incidents) == 1

    next_receipt = _receipt()
    next_receipt.audit_id = "next-audit"
    next_session = await handler.handle(
        next_receipt,
        {**payload, "type": event_type.replace("REVERTED", "CHANGED_BY_USER")},
        _organization(),
    )
    assert next_session is not previous
    assert next_session.active is True
    assert next_session.status is MonitoringStatus.MONITORING
    assert next_session.baseline is baseline.return_value
    assert next_session.audit_ids == ["next-audit"]
    assert previous.audit_ids == ["reverted-audit"]
    assert next_session.monitoring_ends_at == NOW + timedelta(hours=1)
    baseline.assert_awaited_once()


@pytest.mark.parametrize("value", [0, -1, 1e100, float("nan"), float("inf"), True, "bad", None])
def test_invalid_event_times_fall_back_to_receipt(value):
    event = monitoring.DeviceEvent(
        event_type="AP_CONFIG_CHANGED_BY_USER", device_mac=MAC, site_id="site-1", payload={"timestamp": value}
    )
    assert monitoring.event_time(event, _receipt()) == NOW


@pytest.mark.parametrize("offset", [-86401, -86400, -300, 0, 60, 61])
@pytest.mark.parametrize("key", ["timestamp", "time"])
def test_event_time_bounds_are_relative_to_receipt_even_on_delayed_processing(monkeypatch, offset, key):
    monkeypatch.setattr(monitoring, "utc_now", lambda: NOW + timedelta(days=5))
    reported = NOW + timedelta(seconds=offset)
    event = monitoring.DeviceEvent(
        event_type="AP_CONFIG_CHANGED_BY_USER", device_mac=MAC, site_id="site-1", payload={key: reported.timestamp()}
    )
    expected = reported if -86400 <= offset <= 60 else NOW
    assert monitoring.event_time(event, _receipt()) == expected


async def test_lifecycle_timeline_retains_event_and_receipt_times_without_duplicate_entries(monkeypatch):
    session = _session(status=MonitoringStatus.MONITORING, audit_ids=["audit-7"])
    _install_active_session(monkeypatch, session)
    receipt = _receipt()
    payload = {
        "type": "SW_CONFIG_REQUESTED",
        "mac": MAC,
        "site_id": "site-1",
        "timestamp": receipt.created_at.timestamp() - 30,
    }
    handler = _handler()
    assert await handler.handle(receipt, payload, _organization()) is session
    assert await handler.handle(receipt, payload, _organization()) is session
    assert len(session.timeline) == 1
    assert session.timeline[0].event_type == "SW_CONFIG_REQUESTED"
    assert session.timeline[0].received_at == receipt.created_at
    assert (receipt.created_at - session.timeline[0].occurred_at).total_seconds() == 30
