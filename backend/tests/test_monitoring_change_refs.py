"""Audit grouping never crosses organization boundaries or guesses by time."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

from beanie import PydanticObjectId

from mist_config_guardian_backend.api.routes.monitoring import _change_refs
from mist_config_guardian_backend.models.webhook import AuditChangeGroup


async def test_change_refs_batch_audits_in_the_requested_organization(monkeypatch):
    organization_id = PydanticObjectId()
    group = SimpleNamespace(
        id=PydanticObjectId(), audit_id="template-audit", summary="Template updated", message=None, occurred_at=None
    )
    queries = []

    def find(query):
        queries.append(query)
        return SimpleNamespace(to_list=AsyncMock(return_value=[group]))

    monkeypatch.setattr(AuditChangeGroup, "find", find)
    sessions = [SimpleNamespace(audit_ids=["template-audit"]), SimpleNamespace(audit_ids=["template-audit", "other"])]
    refs = await _change_refs(organization_id, sessions)
    assert queries == [{"organization_id": organization_id, "audit_id": {"$in": ["other", "template-audit"]}}]
    assert refs["template-audit"].title == "Template updated"
    assert "other" not in refs
    assert await _change_refs(organization_id, [SimpleNamespace(audit_ids=[])]) == {}
    assert len(queries) == 1


def test_session_response_publishes_the_baseline_trend_for_the_chart() -> None:
    """The browser draws the pre-change series, so it has to cross the wire."""
    from beanie import PydanticObjectId  # noqa: PLC0415

    from mist_config_guardian_backend.models.monitoring import (  # noqa: PLC0415
        DeviceType,
        MonitoringSession,
        SleObservation,
    )
    from mist_config_guardian_backend.schemas.monitoring import MonitoringSessionResponse  # noqa: PLC0415

    session = MonitoringSession.model_construct(
        id=PydanticObjectId(),
        organization_id=PydanticObjectId(),
        site_id="Seattle-DC",
        device_mac="5c:5b:35:1a:2b:a1",
        device_type=DeviceType.AP,
        baseline=SleObservation(
            values={"coverage": 90.0},
            trend={"coverage": [50.0, None, 90.0]},
            baseline_window="last-hour",
        ),
    )

    response = MonitoringSessionResponse.from_document(session)

    assert response.baseline is not None
    assert response.baseline.trend == {"coverage": [50.0, None, 90.0]}
    assert response.baseline.baseline_window == "last-hour"
