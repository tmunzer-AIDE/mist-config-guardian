"""A past failed deployment is different from the latest recorded outcome."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

from beanie import PydanticObjectId

from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.monitoring import (
    DeviceType,
    ImpactSeverity,
    MonitoringIncident,
    MonitoringSession,
    MonitoringStatus,
    MonitoringTimelineEvent,
    SleObservation,
)
from mist_config_guardian_backend.models.telemetry import DeviceStateFinding
from mist_config_guardian_backend.models.webhook import WebhookReceipt
from mist_config_guardian_backend.schemas.monitoring import MonitoringSessionResponse
from mist_config_guardian_backend.services.device_impact_projection import impact_from_session
from mist_config_guardian_backend.services.monitoring import DeviceEvent, MonitoringEventService
from mist_config_guardian_backend.services.monitoring_recovery import reconciled_session

START = datetime(2026, 9, 19, 3, 23, tzinfo=UTC)


def event(kind: str, at: datetime) -> MonitoringTimelineEvent:
    return MonitoringTimelineEvent(key=f"{kind}:{at}", event_type=kind, occurred_at=at, received_at=at, audit_id=None)


def session() -> MonitoringSession:
    return MonitoringSession.model_construct(
        id=PydanticObjectId(),
        organization_id=PydanticObjectId(),
        device_mac="aabbccddeeff",
        site_id="site",
        device_type=DeviceType.GATEWAY,
        status=MonitoringStatus.COMPLETED,
        baseline=SleObservation(values={"gateway-health": 99.89}),
        observations=[SleObservation(values={"gateway-health": 100})],
        impact_severity=ImpactSeverity.CRITICAL,
        peak_impact_severity=ImpactSeverity.CRITICAL,
        incidents=[
            MonitoringIncident(event_type="GW_CONFIG_FAILED", occurred_at=START, severity=ImpactSeverity.CRITICAL)
        ],
        timeline=[event("GW_CONFIG_FAILED", START), event("GW_CONFIGURED", START + timedelta(minutes=9))],
    )


def test_success_closes_failure_keeps_peak_and_does_not_mutate_the_read_document():
    original = session()
    clean = reconciled_session(original)
    assert clean is not original
    assert clean.incidents[0].resolved
    assert clean.incidents[0].resolved_at == START + timedelta(minutes=9)
    assert clean.impact_severity == ImpactSeverity.NONE
    assert clean.peak_impact_severity == ImpactSeverity.CRITICAL
    assert not original.incidents[0].resolved
    response = MonitoringSessionResponse.from_document(original)
    assert response.incidents[0].resolved
    assert response.impact_severity == ImpactSeverity.NONE


def test_older_success_or_other_device_kind_does_not_close_a_failure():
    for success in [
        event("GW_CONFIGURED", START - timedelta(minutes=1)),
        event("SW_CONFIGURED", START + timedelta(minutes=9)),
    ]:
        original = session()
        original.timeline = [event("GW_CONFIG_FAILED", START), success]
        assert reconciled_session(original) is original


def test_a_later_failure_remains_open_after_an_earlier_success():
    original = session()
    later = START + timedelta(minutes=10)
    original.incidents.append(
        MonitoringIncident(event_type="GW_CONFIG_FAILED", occurred_at=later, severity=ImpactSeverity.CRITICAL)
    )
    original.timeline.append(event("GW_CONFIG_FAILED", later))
    clean = reconciled_session(original)
    assert clean.incidents[0].resolved
    assert not clean.incidents[1].resolved
    assert clean.impact_severity == ImpactSeverity.CRITICAL


def test_out_of_order_receipts_use_observed_event_times():
    original = session()
    original.incidents[0].occurred_at = START + timedelta(hours=1)
    original.timeline.reverse()
    clean = reconciled_session(original)
    assert clean.incidents[0].occurred_at == START
    assert clean.incidents[0].resolved_at == START + timedelta(minutes=9)


def test_no_success_and_no_traffic_do_not_become_a_healthy_verdict():
    original = session()
    original.timeline = []
    assert reconciled_session(original) is original
    original.timeline = [event("GW_CONFIGURED", START + timedelta(minutes=9))]
    original.baseline = None
    original.observations = []
    clean = reconciled_session(original)
    assert clean.incidents[0].resolved
    assert clean.impact_severity == ImpactSeverity.INFO


async def test_configured_event_persists_recovery_without_erasing_peak(monkeypatch):
    save = AsyncMock()
    monkeypatch.setattr(MonitoringSession, "save", save)
    original = session()
    original.timeline = [event("GW_CONFIG_FAILED", START)]
    receipt = WebhookReceipt.model_construct(
        id=PydanticObjectId(),
        organization_id=original.organization_id,
        created_at=START + timedelta(minutes=10),
        topic="device-events",
    )
    configured = DeviceEvent(
        "GW_CONFIGURED",
        original.device_mac,
        original.site_id,
        {"timestamp": (START + timedelta(minutes=9)).timestamp()},
    )
    service = MonitoringEventService(None)
    await service._mark_configured(receipt, None, configured, original)  # noqa: SLF001
    assert original.incidents[0].resolved_at == START + timedelta(minutes=9)
    assert original.impact_severity == ImpactSeverity.NONE
    assert original.peak_impact_severity == ImpactSeverity.CRITICAL
    save.assert_awaited_once()


async def test_late_failure_delivery_uses_event_time_and_retains_historical_peak(monkeypatch):
    monkeypatch.setattr(MonitoringSession, "save", AsyncMock())
    original = session()
    original.status = MonitoringStatus.MONITORING
    original.incidents = []
    original.peak_impact_severity = ImpactSeverity.NONE
    await MonitoringEventService._record_incident(original, "GW_CONFIG_FAILED", occurred_at=START)  # noqa: SLF001
    assert original.incidents[0].resolved
    assert original.impact_severity == ImpactSeverity.NONE
    assert original.peak_impact_severity == ImpactSeverity.CRITICAL


def test_recovery_projection_preserves_operational_findings_and_legacy_provenance():
    original = session()
    original.device_findings = [
        DeviceStateFinding(
            kind="poe",
            subject="ge-0/0/1",
            severity="critical",
            before="powered",
            after="unpowered",
            detail="Power lost on a linked port.",
        )
    ]
    row = original.model_dump()
    row["_id"] = original.id
    result = impact_from_session(row, utc_now() + timedelta(days=1), historical=False)
    assert result.severity == "critical"
    assert result.assessment_source == "legacy"
    assert "Operational differences" in result.headline
    assert not original.incidents[0].resolved


def test_partial_legacy_ledger_does_not_infer_recovery():
    original = session()
    row = original.model_dump()
    row["_id"] = original.id
    row["timeline"] = [{"event_type": "GW_CONFIGURED", "received_at": START + timedelta(minutes=9)}]
    result = impact_from_session(row, utc_now() + timedelta(days=1), historical=False)
    assert result.severity == "critical"
