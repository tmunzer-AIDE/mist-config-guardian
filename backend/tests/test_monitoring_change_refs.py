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
