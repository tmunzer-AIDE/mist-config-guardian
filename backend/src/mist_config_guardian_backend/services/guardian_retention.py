"""Deleted-organization cleanup for the two Guardian collections.

Guardian roots and runs are written with ``retained_until`` already set, so the TTL monitor expires them without
help and nothing here backfills one. What a TTL cannot do is notice that the organization a document belongs to
is gone: those documents would sit until their own expiry. This deletes them, in bounded batches, after a
one-day grace so a document written moments ago is never judged against a lookup that has not caught up.
"""

from datetime import timedelta

from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.guardian import GuardianInvestigation, GuardianRun

_BATCH = 100


async def maintain_guardian_retention() -> int:
    """Delete orphaned Guardian documents, and return how many were removed."""
    changed = 0
    now = utc_now()
    for model in (GuardianInvestigation, GuardianRun):
        collection = model.get_pymongo_collection()
        cursor = await collection.aggregate(
            [
                {"$match": {"created_at": {"$lt": now - timedelta(days=1)}}},
                {
                    "$lookup": {
                        "from": "organizations",
                        "localField": "organization_id",
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
