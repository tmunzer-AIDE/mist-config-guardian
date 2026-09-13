"""Retention covers both published and orphan artifacts, with bounded maintenance."""

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

from beanie import PydanticObjectId

from mist_config_guardian_backend.models.adjudication import ImpactAdjudication
from mist_config_guardian_backend.models.investigation import (
    ImpactInvestigation,
    InvestigationRevision,
    ModelRequestArtifact,
)
from mist_config_guardian_backend.models.neighbor_binding import NeighborBinding
from mist_config_guardian_backend.services import investigation_retention as service
from test_wlan_investigation import NOW, ORG


class Cursor:
    def __init__(self, rows):
        self.rows = rows

    def sort(self, *_):
        return self

    def limit(self, count):
        assert count == 100
        return self

    async def to_list(self, *, length):
        assert length == 100
        return self.rows


async def test_legacy_backfill_pins_org_policy_and_deletion_uses_only_proven_orphan_ids(monkeypatch):
    monkeypatch.setattr(service, "utc_now", lambda: NOW)
    monkeypatch.setattr(
        service.Organization, "get", AsyncMock(return_value=SimpleNamespace(monitoring_retention_days=30))
    )
    collections = []
    for model, timestamp in [
        (ImpactInvestigation, "created_at"),
        (InvestigationRevision, "generated_at"),
        (ModelRequestArtifact, "created_at"),
        (ImpactAdjudication, "reviewed_at"),
        (NeighborBinding, None),
    ]:
        identifier, orphan = PydanticObjectId(), PydanticObjectId()
        collection = SimpleNamespace(
            find=lambda *_args, identifier=identifier, timestamp=timestamp, **_kwargs: Cursor(
                [{"_id": identifier, "organization_id": ORG, timestamp: NOW}]
            ),
            aggregate=AsyncMock(return_value=Cursor([{"_id": orphan}])),
            update_one=AsyncMock(),
            delete_many=AsyncMock(return_value=SimpleNamespace(deleted_count=1)),
        )
        monkeypatch.setattr(model, "get_pymongo_collection", lambda *_, c=collection: c)
        collections.append((collection, identifier, orphan))
    assert await service.maintain_investigation_retention() == 9
    service.Organization.get.assert_awaited_once_with(ORG)
    for index, (collection, identifier, orphan) in enumerate(collections):
        if index < 4:
            assert collection.update_one.await_args.args == (
                {"_id": identifier, "organization_id": ORG, "retained_until": None},
                {"$set": {"retained_until": NOW + timedelta(days=30)}},
            )
        collection.delete_many.assert_awaited_once_with({"_id": {"$in": [orphan]}})
        assert collection.aggregate.await_args.kwargs["maxTimeMS"] == 5000
        pipeline = collection.aggregate.await_args.args[0]
        assert pipeline[2] == {"$match": {"retention_org": {"$size": 0}}}


def test_every_public_investigation_artifact_has_ttl_including_unreferenced_inserts():
    for model in (ImpactInvestigation, InvestigationRevision, ModelRequestArtifact, ImpactAdjudication):
        assert any(
            i.document.get("expireAfterSeconds") == 0 and dict(i.document["key"]) == {"retained_until": 1}
            for i in model.Settings.indexes
        )
