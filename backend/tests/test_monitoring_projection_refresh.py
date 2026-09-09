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
