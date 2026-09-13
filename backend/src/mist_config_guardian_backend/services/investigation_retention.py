"""Bounded legacy TTL backfill and cleanup of investigation data for deleted organizations."""

from datetime import timedelta

from mist_config_guardian_backend.models.adjudication import ImpactAdjudication
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.investigation import (
    ImpactInvestigation,
    InvestigationRevision,
    ModelRequestArtifact,
)
from mist_config_guardian_backend.models.neighbor_binding import NeighborBinding
from mist_config_guardian_backend.models.organization import Organization

_BATCH = 100
_MAX_RETENTION_DAYS = 36_500


async def maintain_investigation_retention() -> int:
    """New roots/artifacts carry pinned TTL; this also covers old and orphan inserts."""
    changed = 0
    organizations = {}
    now = utc_now()
    families = [
        (ImpactInvestigation, "created_at"),
        (InvestigationRevision, "generated_at"),
        (ModelRequestArtifact, "created_at"),
        (ImpactAdjudication, "reviewed_at"),
    ]
    for model, timestamp in families:
        collection = model.get_pymongo_collection()
        rows = (
            await collection.find({"retained_until": None}, {"organization_id": 1, timestamp: 1})
            .sort("_id", 1)
            .limit(_BATCH)
            .to_list(length=_BATCH)
        )
        for row in rows:
            org_id = row["organization_id"]
            if org_id not in organizations:
                organizations[org_id] = await Organization.get(org_id)
            org = organizations[org_id]
            days = org.monitoring_retention_days if org else 1
            # Invalid historical policy must not turn into unbounded retention or datetime overflow.
            if type(days) is not int or not 1 <= days <= _MAX_RETENTION_DAYS or row.get(timestamp) is None:
                continue
            await collection.update_one(
                {"_id": row["_id"], "organization_id": org_id, "retained_until": None},
                {"$set": {"retained_until": row[timestamp] + timedelta(days=days)}},
            )
            changed += 1
    # Organization deletion has no UI route today. Cleanup also handles external
    # administrative deletion and private binding orphans, after a one-day grace.
    for model, timestamp, org_field in [
        *((m, t, "organization_id") for m, t in families),
        (NeighborBinding, "identity.captured_at", "identity.organization_id"),
    ]:
        collection = model.get_pymongo_collection()
        cursor = await collection.aggregate(
            [
                {"$match": {timestamp: {"$lt": now - timedelta(days=1)}}},
                {
                    "$lookup": {
                        "from": "organizations",
                        "localField": org_field,
                        "foreignField": "_id",
                        "as": "retention_org",
                    }
                },
                {"$match": {"retention_org": {"$size": 0}}},
                {"$limit": _BATCH},
                {"$project": {"_id": 1}},
            ],
            maxTimeMS=5000,
        )
        rows = await cursor.to_list(length=_BATCH)
        if rows:
            result = await collection.delete_many({"_id": {"$in": [r["_id"] for r in rows]}})
            changed += result.deleted_count
    return changed
