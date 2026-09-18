"""Guardian retention: TTL does the expiring, and maintenance only sweeps documents whose organization is gone.

Roots and runs are written with ``retained_until`` set, so a partial TTL index expires them without a job. The
hourly job exists for what a TTL cannot see -- an organization deleted out from under its documents -- and it
must delete only identifiers it proved are orphans, in bounded batches, after a one-day grace.
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

from beanie import PydanticObjectId

from mist_config_guardian_backend.models.guardian import GuardianInvestigation, GuardianRun
from mist_config_guardian_backend.services import guardian_retention as service

NOW = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)


class Cursor:
    def __init__(self, rows):
        self.rows = rows

    async def to_list(self, *, length):
        assert length == 100
        return self.rows


def collections(monkeypatch, rows):
    """Install one recording collection per Guardian model, answering the given orphan rows."""
    installed = {}
    for model in (GuardianInvestigation, GuardianRun):
        collection = SimpleNamespace(
            aggregate=AsyncMock(return_value=Cursor(rows)),
            delete_many=AsyncMock(return_value=SimpleNamespace(deleted_count=len(rows))),
        )
        monkeypatch.setattr(model, "get_pymongo_collection", lambda *_, c=collection: c)
        installed[model] = collection
    return installed


async def test_only_proven_orphan_identifiers_are_deleted_and_only_after_a_grace(monkeypatch):
    monkeypatch.setattr(service, "utc_now", lambda: NOW)
    orphan = PydanticObjectId()
    installed = collections(monkeypatch, [{"_id": orphan}])

    assert await service.maintain_guardian_retention() == 2

    for collection in installed.values():
        pipeline = collection.aggregate.await_args.args[0]
        assert pipeline[0] == {"$match": {"created_at": {"$lt": NOW - timedelta(days=1)}}}
        assert pipeline[1]["$lookup"]["localField"] == "organization_id"
        assert pipeline[1]["$lookup"]["from"] == "organizations"
        assert pipeline[2] == {"$match": {"retention_org": {"$size": 0}}}
        assert pipeline[3] == {"$limit": 100}
        assert collection.aggregate.await_args.kwargs["maxTimeMS"] == 5000
        # The deletion names the exact identifiers the lookup proved, never the filter that found them.
        collection.delete_many.assert_awaited_once_with({"_id": {"$in": [orphan]}})


async def test_a_database_with_no_orphans_deletes_nothing(monkeypatch):
    monkeypatch.setattr(service, "utc_now", lambda: NOW)
    installed = collections(monkeypatch, [])

    assert await service.maintain_guardian_retention() == 0

    for collection in installed.values():
        collection.delete_many.assert_not_awaited()


def test_guardian_collections_expire_through_partial_ttl_indexes():
    for model in (GuardianInvestigation, GuardianRun):
        assert any(
            i.document.get("expireAfterSeconds") == 0
            and dict(i.document["key"]) == {"retained_until": 1}
            and i.document.get("partialFilterExpression") == {"retained_until": {"$exists": True}}
            for i in model.Settings.indexes
        )


def test_retention_touches_no_collection_beyond_the_two_guardian_ones():
    source = service.__file__
    with open(source, encoding="utf-8") as handle:  # noqa: PTH123
        text = handle.read()
    for name in ("impact_investigations", "investigation_revisions", "impact_model_request_artifacts"):
        assert name not in text
    for name in ("impact_adjudications", "neighbor_bindings"):
        assert name not in text
