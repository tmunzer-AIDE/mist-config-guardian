"""Monitoring polling keeps change-group projections current."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest
from beanie import PydanticObjectId
from beanie.odm.fields import ExpressionField
from beanie.odm.utils.pydantic import get_model_fields

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.monitoring import (
    DeviceType,
    MonitoringSession,
    MonitoringStatus,
    SleObservation,
)
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services import monitoring
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


@pytest.mark.parametrize("scope", ["site", "device"])
async def test_poll_keeps_known_scope_identity_against_unidentified_legacy_baseline(monkeypatch, scope):
    session = _session(MonitoringStatus.MONITORING, [])
    session.baseline = SleObservation(scope=scope, values={"coverage": 99})
    observation = SleObservation(scope=scope, scope_id="known-entity", values={"coverage": 0})
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.capture.return_value = observation
    monkeypatch.setattr(monitoring.Organization, "get", AsyncMock(return_value=SimpleNamespace(cloud_region="test")))
    monkeypatch.setattr(monitoring, "service_token", AsyncMock(return_value="test-token"))
    monkeypatch.setattr(monitoring, "MistSleClient", lambda **_kwargs: client)
    monkeypatch.setattr(MonitoringSession, "save", AsyncMock())
    service = _service(_RecordingProjector())
    for _ in range(2):
        await service._poll_session(session, NOW)  # noqa: SLF001
    assert session.baseline.scope_id is None
    assert session.observations[-1].scope_id == "known-entity"
    assert session.assessment.coverage == "insufficient"
    metric = session.assessment.metrics[0]
    assert (metric.baseline, metric.latest) == (99, 0)
    assert metric.delta is None
    assert not metric.comparable
    assert session.warnings == [
        "Baseline scope identity is unknown; SLE values are retained without comparable deltas."
    ]


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
    queries = [_FakeQuery(awaiting), *[_FakeQuery([item]) for item in awaiting], _FakeQuery(monitoring)]

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


async def test_timeout_persists_each_sessions_metric_gaps_and_guards_configured_races(monkeypatch):
    from mist_config_guardian_backend.models.monitoring import SleObservation  # noqa: PLC0415

    abandoned = _session(MonitoringStatus.AWAITING_CONFIG, [])
    abandoned.baseline = SleObservation(values={"coverage": 99})
    target = _FakeQuery([abandoned])
    queries = [_FakeQuery([abandoned]), target, _FakeQuery([])]
    filters = []

    def find(*args):
        filters.append(args)
        return queries.pop(0)

    monkeypatch.setattr(MonitoringSession, "find", find)
    await _service(_RecordingProjector()).poll_active()
    assert filters[1] == ({"_id": abandoned.id, "status": MonitoringStatus.AWAITING_CONFIG},)
    stored = target.updated["$set"]
    assert stored["assessment"]["severity"] == stored["impact_severity"]
    assert stored["assessment"]["summary"] == stored["deterministic_summary"]
    assert stored["assessment"]["metrics"][0]["name"] == "coverage"
    assert stored["assessment"]["metrics"][0]["latest"] is None
    assert stored["assessment"]["coverage"] == "insufficient"
    assert stored["next_poll_at"] is None


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
    assert len(captures) == 3
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
        if request.url.path.endswith("/metrics"):
            return httpx.Response(
                200, json={"supported": ["coverage", "capacity"], "enabled": ["coverage", "capacity"]}
            )
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


async def test_operational_polls_preserve_first_outage_and_record_recovery(monkeypatch):
    from unittest.mock import AsyncMock  # noqa: PLC0415

    from mist_config_guardian_backend.models.monitoring import ImpactSeverity, SleObservation  # noqa: PLC0415
    from mist_config_guardian_backend.models.organization import MistCloudRegion, Organization  # noqa: PLC0415
    from mist_config_guardian_backend.models.telemetry import (  # noqa: PLC0415
        DeviceStateComparison,
        DeviceStateObservation,
    )
    from mist_config_guardian_backend.services import monitoring  # noqa: PLC0415

    up = DeviceStateObservation(
        captured_at=NOW, available=["ports"], ports=[{"port_id": "ge-0/0/1", "up": True, "poe_on": True}]
    )
    down = DeviceStateObservation(
        captured_at=NOW + timedelta(minutes=5),
        available=["ports"],
        ports=[{"port_id": "ge-0/0/1", "up": False, "poe_on": False}],
    )
    recovered = up.model_copy(update={"captured_at": NOW + timedelta(minutes=10)})
    captures = iter([down, recovered])

    class Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

        async def capture(self, **_kwargs):
            return SleObservation(values={"coverage": 99})

    class Telemetry(Client):
        async def capture(self, **_kwargs):
            return next(captures)

    monkeypatch.setattr(monitoring, "MistSleClient", Client)
    monkeypatch.setattr(monitoring, "MistTelemetryClient", Telemetry)
    monkeypatch.setattr(monitoring, "service_token", AsyncMock(return_value="read-token"))
    monkeypatch.setattr(
        Organization,
        "get",
        AsyncMock(
            return_value=Organization.model_construct(id=ORGANIZATION_ID, cloud_region=MistCloudRegion.GLOBAL_01)
        ),
    )
    monkeypatch.setattr(MonitoringSession, "save", AsyncMock())
    session = _session(MonitoringStatus.MONITORING, [])
    session.baseline = SleObservation(values={"coverage": 99})
    session.device_comparisons = [DeviceStateComparison(triggered_at=NOW, baseline=up, due_at=down.captured_at)]
    service = _service(_RecordingProjector())
    await service._poll_session(session, down.captured_at)  # noqa: SLF001
    assert session.impact_severity == ImpactSeverity.CRITICAL
    await service._poll_session(session, recovered.captured_at)  # noqa: SLF001
    comparison = session.device_comparisons[0]
    assert comparison.followup == down
    assert comparison.findings[0].severity == "critical"
    assert comparison.latest == recovered
    assert comparison.current_findings == session.device_findings == []
    assert comparison.recovered_at == recovered.captured_at
    assert session.impact_severity == ImpactSeverity.NONE
    assert session.peak_impact_severity == ImpactSeverity.CRITICAL


async def test_baseline_capture_anchors_on_the_final_hour_and_keeps_the_day_trend(monkeypatch, httpx_mock):
    """The stored baseline must be comparable to a post-change window, not a day."""
    from unittest.mock import AsyncMock  # noqa: PLC0415

    import httpx  # noqa: PLC0415

    from mist_config_guardian_backend.models.organization import MistCloudRegion, Organization  # noqa: PLC0415
    from mist_config_guardian_backend.services import monitoring  # noqa: PLC0415

    # A day at 50% that recovers to 90% in the hour before the change.
    recovering = {"sle": {"samples": {"total": [100] * 24, "degraded": [50] * 23 + [10]}}}

    def respond(request):
        if request.url.path.endswith("/metrics"):
            return httpx.Response(200, json={"supported": ["coverage"], "enabled": ["coverage"]})
        return httpx.Response(200, json=recovering)

    httpx_mock.add_callback(respond, is_reusable=True)
    monkeypatch.setattr(monitoring, "service_token", AsyncMock(return_value="read-token"))
    organization = Organization.model_construct(id=ORGANIZATION_ID, cloud_region=MistCloudRegion.GLOBAL_01)

    service = monitoring.MonitoringEventService(CredentialVault(Settings(environment="test", database_enabled=False)))
    baseline = await service._capture(  # noqa: SLF001
        organization, "Seattle-DC", DeviceType.AP, "5c:5b:35:1a:2b:a1", NOW
    )

    assert baseline.values["coverage"] == 90
    assert baseline.baseline_window == "last-hour"
    assert len(baseline.trend["coverage"]) == 24
    assert baseline.window_start == NOW - timedelta(hours=24)
