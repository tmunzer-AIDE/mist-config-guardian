"""Real MongoDB coverage for monitoring polls racing device events and each other.

A poll reads a session, spends seconds reading Mist, then writes. These tests
run the competing writer inside that gap, which is where the races live.
Skipped unless ``MONGO_TEST_URL`` names a reachable MongoDB.
"""

import os
from collections.abc import Awaitable, Callable
from datetime import timedelta
from types import SimpleNamespace
from typing import Self
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.monitoring import (
    DeviceType,
    MonitoringSession,
    MonitoringStatus,
    SleObservation,
)
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services import monitoring
from mist_config_guardian_backend.services.monitoring import MonitoringEventService, MonitoringPollService

MONGO_URL = os.environ.get("MONGO_TEST_URL")
pytestmark = [
    pytest.mark.skipif(not MONGO_URL, reason="MONGO_TEST_URL is not set"),
    pytest.mark.usefixtures("database"),
]

_POLL_FAILED = "A monitoring poll failed; collection will be retried."


@pytest_asyncio.fixture
async def database():
    client = AsyncMongoClient(MONGO_URL, tz_aware=True)
    database_name = f"guardian_monitoring_poll_test_{uuid4().hex}"
    await init_beanie(client[database_name], document_models=[MonitoringSession])
    try:
        yield
    finally:
        await client.drop_database(database_name)
        await client.close()


class _NoAiConfiguration:
    async def impact_ai_runtime(self) -> None:
        return None


class _RecordingProjector:
    def __init__(self) -> None:
        self.rebuilt: list[str] = []

    async def rebuild(self, _organization_id: PydanticObjectId, audit_id: str) -> None:
        self.rebuilt.append(audit_id)


def _service(projector: _RecordingProjector | None = None) -> MonitoringPollService:
    settings = Settings(environment="test", database_enabled=False)
    return MonitoringPollService(
        CredentialVault(settings),
        _NoAiConfiguration(),  # type: ignore[arg-type]
        projector or _RecordingProjector(),  # type: ignore[arg-type]
    )


def _observation() -> SleObservation:
    return SleObservation(
        scope="device", scope_id="gateway", values={"gateway-health": 98.0}, sample_counts={"gateway-health": 50}
    )


async def _due_session() -> MonitoringSession:
    now = utc_now()
    return await MonitoringSession(
        organization_id=PydanticObjectId(),
        audit_ids=["audit-1"],
        site_id="site-1",
        device_mac="aabbccddeeff",
        device_type=DeviceType.GATEWAY,
        status=MonitoringStatus.MONITORING,
        active=True,
        baseline=SleObservation(
            scope="device", scope_id="gateway", values={"gateway-health": 99.0}, sample_counts={"gateway-health": 50}
        ),
        monitoring_started_at=now - timedelta(minutes=10),
        monitoring_ends_at=now + timedelta(minutes=50),
        next_poll_at=now - timedelta(seconds=1),
    ).insert()


def _mist(monkeypatch: pytest.MonkeyPatch, capture: Callable[[], Awaitable[SleObservation]]) -> None:
    """Answer SLE reads with ``capture``, which may act while the poll waits on Mist."""

    class Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *_exc: object) -> None:
            return None

        async def capture(self, **_kwargs: object) -> SleObservation:
            return await capture()

    monkeypatch.setattr(monitoring, "MistSleClient", Client)
    monkeypatch.setattr(monitoring, "service_token", AsyncMock(return_value="read-token"))
    monkeypatch.setattr(monitoring.Organization, "get", AsyncMock(return_value=SimpleNamespace(cloud_region="test")))


async def _device_event(session_id: PydanticObjectId, event_type: str) -> None:
    """What a webhook worker does for one device event: load, record, save."""
    current = await MonitoringSession.get(session_id)
    assert current is not None
    await MonitoringEventService._record_incident(current, event_type)  # noqa: SLF001


async def test_a_revert_recorded_while_mist_is_read_is_not_undone(monkeypatch) -> None:
    session = await _due_session()

    async def capture() -> SleObservation:
        await _device_event(session.id, "GW_CONFIG_REVERTED")
        return _observation()

    _mist(monkeypatch, capture)
    await _service().poll_active()

    stored = await MonitoringSession.get(session.id)
    assert stored is not None
    assert (stored.status, stored.active, stored.next_poll_at) == (MonitoringStatus.FAILED, False, None)
    assert [incident.event_type for incident in stored.incidents] == ["GW_CONFIG_REVERTED"]


async def test_an_incident_recorded_while_mist_is_read_is_kept_beside_the_observation(monkeypatch) -> None:
    session = await _due_session()
    projector = _RecordingProjector()

    async def capture() -> SleObservation:
        await _device_event(session.id, "GW_TUNNEL_DOWN")
        return _observation()

    _mist(monkeypatch, capture)
    await _service(projector).poll_active()

    stored = await MonitoringSession.get(session.id)
    assert stored is not None
    assert stored.status is MonitoringStatus.MONITORING
    assert [incident.event_type for incident in stored.incidents] == ["GW_TUNNEL_DOWN"]
    assert [item.values for item in stored.observations] == [{"gateway-health": 98.0}]
    # The verdict is the poll's, recomputed over the incident it did not read.
    assert stored.assessment is not None
    assert stored.assessment.incident_types == ("GW_TUNNEL_DOWN",)
    assert projector.rebuilt == ["audit-1"]


async def test_an_overlapping_run_skips_a_session_already_being_polled(monkeypatch) -> None:
    session = await _due_session()
    captured: list[SleObservation] = []
    overlapping: list[int] = []

    async def capture() -> SleObservation:
        captured.append(_observation())
        if len(captured) == 1:
            # The next beat fires while this run is still reading Mist.
            overlapping.append(await _service().poll_active())
        return captured[-1]

    _mist(monkeypatch, capture)
    polled = await _service().poll_active()

    assert (polled, overlapping, len(captured)) == (1, [0], 1)
    stored = await MonitoringSession.get(session.id)
    assert stored is not None
    assert len(stored.observations) == 1


async def test_a_failed_poll_does_not_reopen_a_session_an_event_closed(monkeypatch) -> None:
    session = await _due_session()

    async def capture() -> SleObservation:
        await _device_event(session.id, "GW_CONFIG_REVERTED")
        msg = "Mist is unavailable"
        raise RuntimeError(msg)

    _mist(monkeypatch, capture)
    await _service().poll_active()

    stored = await MonitoringSession.get(session.id)
    assert stored is not None
    assert (stored.status, stored.active) == (MonitoringStatus.FAILED, False)
    assert [incident.event_type for incident in stored.incidents] == ["GW_CONFIG_REVERTED"]
    assert _POLL_FAILED not in stored.warnings


async def test_a_failed_poll_is_retried_an_interval_later_with_a_warning(monkeypatch) -> None:
    session = await _due_session()

    async def capture() -> SleObservation:
        msg = "Mist is unavailable"
        raise RuntimeError(msg)

    _mist(monkeypatch, capture)
    started = utc_now()
    for _ in range(2):
        await _service().poll_active()

    stored = await MonitoringSession.get(session.id)
    assert stored is not None
    assert stored.status is MonitoringStatus.MONITORING
    assert stored.warnings == [_POLL_FAILED]
    assert stored.next_poll_at is not None
    assert stored.next_poll_at >= started + timedelta(minutes=5) - timedelta(seconds=1)
