"""Point-in-time navigation and configuration state reconstruction.

Reconstruction is a real query over the immutable version history, not a cached
view: for every logical object in scope it takes the newest version observed at
or before the instant, and drops the object when that version is a tombstone.
An object deleted *after* the instant is therefore part of the reconstruction,
flagged with the deletion state it carries today.

Nothing in this module writes. A historical read is a read.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol

from beanie import PydanticObjectId

from mist_config_guardian_backend.models.monitoring import ImpactSeverity
from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectVersion
from mist_config_guardian_backend.models.webhook import AuditChangeGroup
from mist_config_guardian_backend.schemas.point_in_time import (
    PointInTimeStateResponse,
    ReconstructedObjectResponse,
    TimelineMarkerListResponse,
    TimelineMarkerResponse,
)
from mist_config_guardian_backend.services.change_groups import as_utc, build_title, resolve_window

MARKER_LIMIT = 200
# A reconstruction covers a whole organization's configuration, which the
# product sizes in the low thousands of objects. The cap keeps a pathological
# archive from turning one request into an unbounded scan.
SCOPE_LIMIT = 10_000


@dataclass(frozen=True, slots=True)
class ReconstructedVersion:
    """The newest version of one object at the reconstructed instant."""

    logical_object_id: PydanticObjectId
    version_id: PydanticObjectId
    version: int
    is_deleted: bool


class PointInTimeReader(Protocol):
    """The queries point-in-time navigation is built from."""

    async def markers(
        self,
        organization_id: PydanticObjectId,
        *,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> list[AuditChangeGroup]:
        """Return change groups inside the window, oldest first."""

    async def logical_object(
        self,
        organization_id: PydanticObjectId,
        logical_object_id: PydanticObjectId,
    ) -> LogicalObject | None:
        """Return one logical object scoped to an organization."""

    async def version_at(
        self,
        organization_id: PydanticObjectId,
        logical_object_id: PydanticObjectId,
        at: datetime,
    ) -> ObjectVersion | None:
        """Return the newest version of one object observed at or before an instant."""

    async def scope_objects(
        self,
        organization_id: PydanticObjectId,
        *,
        site_id: str | None,
        limit: int,
    ) -> list[LogicalObject]:
        """Return every logical object in the organization or one of its sites."""

    async def versions_at(
        self,
        organization_id: PydanticObjectId,
        logical_object_ids: Sequence[PydanticObjectId],
        at: datetime,
    ) -> list[ReconstructedVersion]:
        """Return the newest live version of each object at or before an instant."""


class BeaniePointInTimeReader:
    """MongoDB-backed point-in-time queries."""

    async def markers(
        self,
        organization_id: PydanticObjectId,
        *,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> list[AuditChangeGroup]:
        """Return change groups inside the window, oldest first."""
        return (
            await AuditChangeGroup.find(
                {
                    "organization_id": organization_id,
                    "occurred_at": {"$gte": start, "$lte": end},
                }
            )
            .sort("occurred_at")
            .limit(limit)
            .to_list()
        )

    async def logical_object(
        self,
        organization_id: PydanticObjectId,
        logical_object_id: PydanticObjectId,
    ) -> LogicalObject | None:
        """Return one logical object scoped to an organization."""
        return await LogicalObject.find_one(
            LogicalObject.id == logical_object_id,
            LogicalObject.organization_id == organization_id,
        )

    async def version_at(
        self,
        organization_id: PydanticObjectId,
        logical_object_id: PydanticObjectId,
        at: datetime,
    ) -> ObjectVersion | None:
        """Return the newest version of one object observed at or before an instant."""
        return (
            await ObjectVersion.find(
                {
                    "organization_id": organization_id,
                    "logical_object_id": logical_object_id,
                    "observed_at": {"$lte": at},
                }
            )
            .sort("-version")
            .first_or_none()
        )

    async def scope_objects(
        self,
        organization_id: PydanticObjectId,
        *,
        site_id: str | None,
        limit: int,
    ) -> list[LogicalObject]:
        """Return every logical object in the organization or one of its sites."""
        criteria: dict[str, object] = {"organization_id": organization_id}
        if site_id is not None:
            criteria["site_mist_id"] = site_id
        return await LogicalObject.find(criteria).sort("object_type", "name").limit(limit).to_list()

    async def versions_at(
        self,
        organization_id: PydanticObjectId,
        logical_object_ids: Sequence[PydanticObjectId],
        at: datetime,
    ) -> list[ReconstructedVersion]:
        """Return the newest live version of each object at or before an instant."""
        if not logical_object_ids:
            return []
        pipeline: list[dict[str, object]] = [
            {
                "$match": {
                    "organization_id": organization_id,
                    "logical_object_id": {"$in": list(logical_object_ids)},
                    "observed_at": {"$lte": at},
                }
            },
            {"$sort": {"logical_object_id": 1, "version": -1}},
            {
                "$group": {
                    "_id": "$logical_object_id",
                    "version_id": {"$first": "$_id"},
                    "version": {"$first": "$version"},
                    "is_deleted": {"$first": "$is_deleted"},
                }
            },
            {"$match": {"is_deleted": False}},
        ]
        rows = await ObjectVersion.aggregate(pipeline).to_list()
        return [
            ReconstructedVersion(
                logical_object_id=row["_id"],
                version_id=row["version_id"],
                version=row["version"],
                is_deleted=bool(row["is_deleted"]),
            )
            for row in rows
        ]


class PointInTimeService:
    """Serve time-bar markers and reconstructed configuration state."""

    def __init__(self, reader: PointInTimeReader | None = None) -> None:
        self._reader = reader if reader is not None else BeaniePointInTimeReader()

    async def markers(
        self,
        organization_id: PydanticObjectId,
        *,
        range_key: str,
        as_of: datetime | None = None,
    ) -> TimelineMarkerListResponse:
        """Return every change marker drawn on the shell's time bar."""
        start, end = resolve_window(range_key, as_of)
        groups = await self._reader.markers(organization_id, start=start, end=end, limit=MARKER_LIMIT)
        # A marker's colour is its severity, which is today's verdict on the
        # change. Drawn on a past window it would paint that verdict along a
        # track of instants at which it was not yet reached.
        historical = as_of is not None
        return TimelineMarkerListResponse(
            items=[
                TimelineMarkerResponse(
                    at=as_utc(group.occurred_at or group.created_at),
                    severity=ImpactSeverity.NONE if historical else group.impact_severity,
                    impact_known=not historical,
                    change_group_id=str(group.id),
                    label=build_title(group.changed_objects, group.message),
                )
                for group in groups
                if group.id is not None
            ],
            range_start=start,
            range_end=end,
        )

    async def object_at(
        self,
        organization_id: PydanticObjectId,
        logical_object_id: PydanticObjectId,
        at: datetime,
    ) -> ObjectVersion | None:
        """Return one object's version at an instant, or none when it did not exist.

        A tombstone is "did not exist": it is what ``/state`` excludes, so the
        two endpoints agree on what the organization looked like at ``at``.
        """
        logical = await self._reader.logical_object(organization_id, logical_object_id)
        if logical is None:
            return None
        version = await self._reader.version_at(organization_id, logical_object_id, as_utc(at))
        if version is None or version.is_deleted:
            return None
        return version

    async def state_at(
        self,
        organization_id: PydanticObjectId,
        *,
        at: datetime,
        scope: Literal["org", "site"] = "org",
        site_id: str | None = None,
    ) -> PointInTimeStateResponse:
        """Reconstruct one scope's configuration as it existed at an instant."""
        instant = as_utc(at)
        objects = await self._reader.scope_objects(
            organization_id,
            site_id=site_id if scope == "site" else None,
            limit=SCOPE_LIMIT,
        )
        by_id = {logical.id: logical for logical in objects if logical.id is not None}
        versions = await self._reader.versions_at(organization_id, list(by_id), instant)
        items = []
        for version in versions:
            logical = by_id.get(version.logical_object_id)
            if logical is None:
                continue
            items.append(
                ReconstructedObjectResponse(
                    logical_object_id=str(version.logical_object_id),
                    object_type=logical.object_type,
                    name=logical.name,
                    version_id=str(version.version_id),
                    version=version.version,
                    # The object existed at the instant; the flag reports whether
                    # it has since been deleted, so the browser can mark it.
                    is_deleted=logical.is_deleted,
                )
            )
        items.sort(key=lambda item: (item.object_type, item.name, item.logical_object_id))
        return PointInTimeStateResponse(
            as_of=instant,
            scope=scope,
            object_count=len(items),
            objects=items,
        )
