"""Monitoring polling keeps change-group projections current."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from beanie import PydanticObjectId
from beanie.odm.fields import ExpressionField
from beanie.odm.utils.pydantic import get_model_fields

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.monitoring import (
    DeviceType,
    MonitoringSession,
    MonitoringStatus,
)
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.monitoring import MonitoringPollService

ORGANIZATION_ID = PydanticObjectId()
NOW = datetime(2026, 9, 7, 14, 22, tzinfo=UTC)


def _bind_query_fields(model: type) -> None:
    """Attach the query expression fields Beanie normally installs at init."""
    for name, field in get_model_fields(model).items():
        setattr(model, name, ExpressionField(field.alias or name))


_bind_query_fields(MonitoringSession)


class _RecordingProjector:
    """Stands in for ChangeGroupProjector and records what it was asked to rebuild."""

    def __init__(self, *, failing: bool = False) -> None:
        self.rebuilt: list[tuple[PydanticObjectId, str]] = []
        self._failing = failing

    async def rebuild(self, organization_id: PydanticObjectId, audit_id: str) -> None:
        self.rebuilt.append((organization_id, audit_id))
        if self._failing:
            msg = "the projection store is unavailable"
            raise RuntimeError(msg)


def _session(status: MonitoringStatus, audit_ids: list[str]) -> MonitoringSession:
    return MonitoringSession.model_construct(
        id=PydanticObjectId(),
        organization_id=ORGANIZATION_ID,
        audit_ids=audit_ids,
        receipt_ids=[],
        site_id="Seattle-DC",
        device_mac="5c:5b:35:1a:2b:a1",
        device_name="SEA-AP-101",
        device_type=DeviceType.AP,
        status=status,
        active=status is MonitoringStatus.AWAITING_CONFIG,
        observations=[],
        incidents=[],
        degraded_metrics=[],
        warnings=[],
        created_at=NOW - timedelta(hours=1),
    )


def _service(projector: _RecordingProjector) -> MonitoringPollService:
    settings = Settings(environment="test", database_enabled=False)
    return MonitoringPollService(CredentialVault(settings), _NoAiConfiguration(), projector)  # type: ignore[arg-type]


class _NoAiConfiguration:
    async def impact_ai_runtime(self) -> None:
        return None


class _FakeQuery:
    def __init__(self, items: list[MonitoringSession]) -> None:
        self._items = items
        self.updated: dict[str, Any] | None = None

    async def to_list(self) -> list[MonitoringSession]:
        return list(self._items)

    async def update_many(self, changes: dict[str, Any]) -> None:
        self.updated = changes


def _install_queries(
    monkeypatch: pytest.MonkeyPatch,
    *,
    awaiting: list[MonitoringSession],
    monitoring: list[MonitoringSession],
) -> None:
    """Answer the two find() calls poll_active makes, in order."""
    queries = [_FakeQuery(awaiting), _FakeQuery(awaiting), _FakeQuery(monitoring)]

    def find(*_args: object, **_kwargs: object) -> _FakeQuery:
        return queries.pop(0)

    monkeypatch.setattr(MonitoringSession, "find", find)


async def test_a_session_that_never_configured_still_refreshes_its_change_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bulk timeout update bypasses the document path.

    Without collecting these sessions first, the change group would never learn
    that monitoring was abandoned and would keep reporting it as in progress.
    """
    projector = _RecordingProjector()
    abandoned = _session(MonitoringStatus.AWAITING_CONFIG, ["audit-1", "audit-2"])
    _install_queries(monkeypatch, awaiting=[abandoned], monitoring=[])

    polled = await _service(projector).poll_active()

    assert polled == 0
    assert projector.rebuilt == [
        (ORGANIZATION_ID, "audit-1"),
        (ORGANIZATION_ID, "audit-2"),
    ]


async def test_a_projection_failure_does_not_fail_monitoring(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Monitoring evidence is authoritative; a stale projection must not lose it."""
    projector = _RecordingProjector(failing=True)
    abandoned = _session(MonitoringStatus.AWAITING_CONFIG, ["audit-1"])
    _install_queries(monkeypatch, awaiting=[abandoned], monitoring=[])

    polled = await _service(projector).poll_active()

    assert polled == 0
    assert projector.rebuilt == [(ORGANIZATION_ID, "audit-1")]


async def test_a_session_with_no_audit_correlation_rebuilds_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A device event that never matched an audit has no group to refresh."""
    projector = _RecordingProjector()
    _install_queries(monkeypatch, awaiting=[_session(MonitoringStatus.AWAITING_CONFIG, [])], monitoring=[])

    await _service(projector).poll_active()

    assert projector.rebuilt == []


@pytest.mark.parametrize("scope", ["site", "device"])
async def test_followup_runs_after_five_minutes_and_sle_monitoring_continues_for_an_hour(monkeypatch, scope):
    from unittest.mock import AsyncMock  # noqa: PLC0415

    from mist_config_guardian_backend.models.monitoring import SleObservation  # noqa: PLC0415
    from mist_config_guardian_backend.models.organization import MistCloudRegion, Organization  # noqa: PLC0415
    from mist_config_guardian_backend.models.telemetry import (  # noqa: PLC0415
        DeviceStateComparison,
        DeviceStateObservation,
    )
    from mist_config_guardian_backend.services import monitoring  # noqa: PLC0415

    session = _session(MonitoringStatus.MONITORING, [])
    session.active = True
    session.monitoring_started_at = NOW
    session.monitoring_ends_at = NOW + timedelta(hours=1)
    session.change_triggered_at = NOW
    session.baseline = SleObservation(scope=scope, values={"coverage": 99})
    initial = DeviceStateObservation(
        captured_at=NOW,
        available=["wlans", "clients"],
        wlans=[{"id": "wlan-1", "ssid": "Staff"}],
        clients=[{"mac": "client-1", "wlan_id": "wlan-1"}],
    )
    session.device_comparisons = [
        DeviceStateComparison(triggered_at=NOW, baseline=initial, due_at=NOW + timedelta(minutes=5))
    ]
    captures = []
    windows = []

    class SleClient:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

        async def capture(self, **kwargs):
            windows.append(kwargs)
            return SleObservation(scope=scope, values={"coverage": 99})

    class TelemetryClient(SleClient):
        async def capture(self, **kwargs):
            captures.append(kwargs)
            return DeviceStateObservation(captured_at=NOW + timedelta(minutes=5), available=["wlans", "clients"])

    monkeypatch.setattr(monitoring, "MistSleClient", SleClient)
    monkeypatch.setattr(monitoring, "MistTelemetryClient", TelemetryClient)
    monkeypatch.setattr(monitoring, "service_token", AsyncMock(return_value="read-token"))
    monkeypatch.setattr(
        Organization,
        "get",
        AsyncMock(
            return_value=Organization.model_construct(id=ORGANIZATION_ID, cloud_region=MistCloudRegion.GLOBAL_01)
        ),
    )
    monkeypatch.setattr(MonitoringSession, "save", AsyncMock())
    service = _service(_RecordingProjector())
    await service._poll_session(session, NOW + timedelta(minutes=4))  # noqa: SLF001
    assert not captures
    await service._poll_session(session, NOW + timedelta(minutes=5))  # noqa: SLF001
    assert len(captures) == 1
    assert session.device_comparisons[0].followup is not None
    assert session.device_findings[0].affected_clients == 1
    assert session.status is MonitoringStatus.MONITORING
    await service._poll_session(session, NOW + timedelta(minutes=59))  # noqa: SLF001
    assert session.active is True
    await service._poll_session(session, NOW + timedelta(hours=1))  # noqa: SLF001
    assert session.status is MonitoringStatus.COMPLETED
    assert session.active is False
    assert len(captures) == 1
    assert all(window["start"] == NOW for window in windows)
    assert windows[-1]["end"] == NOW + timedelta(hours=1)
    assert all(window["device_mac"] == (session.device_mac if scope == "device" else None) for window in windows)


async def test_legacy_baseline_keeps_site_scope_and_bucket_mean_across_deployment(monkeypatch, httpx_mock):
    from unittest.mock import AsyncMock  # noqa: PLC0415

    import httpx  # noqa: PLC0415

    from mist_config_guardian_backend.models.monitoring import ImpactSeverity, SleObservation  # noqa: PLC0415
    from mist_config_guardian_backend.models.organization import MistCloudRegion, Organization  # noqa: PLC0415
    from mist_config_guardian_backend.services import monitoring  # noqa: PLC0415

    session = _session(MonitoringStatus.MONITORING, [])
    session.active = True
    session.config_applied_at = NOW
    session.monitoring_ends_at = NOW + timedelta(hours=1)
    # Stored before the release: no scope/window fields; mean([0%, 100%]) = 50%.
    session.baseline = SleObservation.model_validate({"values": {"coverage": 50}})

    def respond(request):
        assert f"/sle/site/{session.site_id}/metric/" in request.url.path
        if request.url.path.endswith("/coverage/summary-trend"):
            return httpx.Response(200, json={"sle": {"samples": {"total": [10, 1000], "degraded": [10, 0]}}})
        return httpx.Response(200, json={"sle": {"samples": {"total": [], "degraded": []}}})

    httpx_mock.add_callback(respond, is_reusable=True)
    monkeypatch.setattr(monitoring, "service_token", AsyncMock(return_value="read-token"))
    monkeypatch.setattr(
        Organization,
        "get",
        AsyncMock(
            return_value=Organization.model_construct(id=ORGANIZATION_ID, cloud_region=MistCloudRegion.GLOBAL_01)
        ),
    )
    monkeypatch.setattr(MonitoringSession, "save", AsyncMock())
    await _service(_RecordingProjector())._poll_session(session, NOW + timedelta(minutes=5))  # noqa: SLF001
    assert session.observations[0].values["coverage"] == 50
    assert session.observations[0].scope == session.baseline.scope == "site"
    assert session.degraded_metrics == []
    # The legacy baseline has no coverage record for the other requested metrics.
    assert session.impact_severity is ImpactSeverity.INFO
