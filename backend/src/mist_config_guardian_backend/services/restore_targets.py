"""Restorable object discovery and facet counts for restore step one."""

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Protocol

from beanie import PydanticObjectId

from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectVersion

TargetScope = Literal["all", "org", "site"]


@dataclass(frozen=True, slots=True)
class RestorableVersion:
    """The newest version of one logical object that can be restored."""

    version_id: PydanticObjectId
    version: int
    observed_at: datetime


@dataclass(frozen=True, slots=True)
class RestoreTarget:
    """One selectable restore target as the picker renders it."""

    logical_object_id: str
    version_id: str
    name: str
    object_type: str
    scope: str
    site_mist_id: str | None
    site_name: str | None
    version: int
    observed_at: datetime


@dataclass(frozen=True, slots=True)
class RestoreTargetTypeCount:
    """One object-type facet row."""

    type: str
    count: int


@dataclass(frozen=True, slots=True)
class RestoreTargetSite:
    """One site facet row."""

    id: str
    name: str


@dataclass(frozen=True, slots=True)
class RestoreTargetPage:
    """One page of targets plus the facet vocabularies the filters render."""

    items: list[RestoreTarget] = field(default_factory=list)
    total: int = 0
    types: list[RestoreTargetTypeCount] = field(default_factory=list)
    sites: list[RestoreTargetSite] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class RestoreTargetQuery:
    """Every filter the restore target picker can apply."""

    organization_id: PydanticObjectId
    scope: TargetScope = "all"
    site_id: str | None = None
    object_type: str | None = None
    q: str | None = None
    skip: int = 0
    limit: int = 50


class RestoreTargetSearch(Protocol):
    """One page of restore targets, filtered and faceted."""

    async def search(self, query: RestoreTargetQuery) -> RestoreTargetPage:
        """Return one page of restore targets with its filter facet counts."""


class RestoreTargetReader(Protocol):
    """Organization-scoped reads the in-memory search depends on."""

    async def logical_objects(self, organization_id: PydanticObjectId) -> list[LogicalObject]:
        """Return every logical object recorded for one organization."""

    async def restorable_versions(
        self,
        organization_id: PydanticObjectId,
    ) -> dict[PydanticObjectId, RestorableVersion]:
        """Return the newest non-deleted version per logical object."""


class MongoRestoreTargetReader:
    """MongoDB-backed target reads, scoped by organization on every query."""

    async def logical_objects(self, organization_id: PydanticObjectId) -> list[LogicalObject]:
        """Return every logical object recorded for one organization."""
        return await LogicalObject.find(LogicalObject.organization_id == organization_id).to_list()

    async def restorable_versions(
        self,
        organization_id: PydanticObjectId,
    ) -> dict[PydanticObjectId, RestorableVersion]:
        """Return the newest non-deleted version per logical object."""
        pipeline: list[dict[str, object]] = [
            {"$match": {"organization_id": organization_id, "is_deleted": False}},
            {"$sort": {"logical_object_id": 1, "version": -1}},
            {
                "$group": {
                    "_id": "$logical_object_id",
                    "version_id": {"$first": "$_id"},
                    "version": {"$first": "$version"},
                    "observed_at": {"$first": "$observed_at"},
                }
            },
        ]
        rows = await ObjectVersion.aggregate(pipeline).to_list()
        return {
            row["_id"]: RestorableVersion(
                version_id=row["version_id"],
                version=int(row["version"]),
                observed_at=row["observed_at"],
            )
            for row in rows
        }


class InMemoryRestoreTargetSearch:
    """Filter, facet, and paginate in Python, over everything the reader holds.

    This is the reference the behaviour is specified against. It reads the whole
    organization per request, so it is not what a deployment runs — see
    ``MongoRestoreTargetSearch``, which must agree with it.
    """

    def __init__(self, reader: RestoreTargetReader) -> None:
        self._reader = reader

    async def search(self, query: RestoreTargetQuery) -> RestoreTargetPage:
        """Return one page of restore targets with its filter facet counts."""
        logical_objects = await self._reader.logical_objects(query.organization_id)
        versions = await self._reader.restorable_versions(query.organization_id)
        site_names = {
            item.current_mist_id: item.name
            for item in logical_objects
            if item.object_type == "sites" and not item.is_deleted
        }

        targets = [
            RestoreTarget(
                logical_object_id=str(item.id),
                version_id=str(versions[item.id].version_id),
                name=item.name,
                object_type=item.object_type,
                scope=item.scope,
                site_mist_id=item.site_mist_id,
                site_name=(None if item.site_mist_id is None else site_names.get(item.site_mist_id)),
                version=versions[item.id].version,
                observed_at=versions[item.id].observed_at,
            )
            for item in logical_objects
            if item.id is not None and item.id in versions
        ]

        # Each facet row is counted with every filter except the one it drives,
        # so selecting a type never empties the type row it was chosen from.
        for_types = self._filter(targets, query, use_type=False, use_site=True)
        for_sites = self._filter(targets, query, use_type=True, use_site=False)
        matched = sorted(
            self._filter(targets, query, use_type=True, use_site=True),
            key=lambda target: (target.object_type, target.name.lower(), target.logical_object_id),
        )
        return RestoreTargetPage(
            items=matched[query.skip : query.skip + query.limit],
            total=len(matched),
            types=self._type_facets(for_types),
            sites=self._site_facets(for_sites),
        )

    @staticmethod
    def _filter(
        targets: Sequence[RestoreTarget],
        query: RestoreTargetQuery,
        *,
        use_type: bool,
        use_site: bool,
    ) -> list[RestoreTarget]:
        needle = (query.q or "").strip().lower()
        selected: list[RestoreTarget] = []
        for target in targets:
            if query.scope not in {"all", target.scope}:
                continue
            if use_site and query.site_id and target.site_mist_id != query.site_id:
                continue
            if use_type and query.object_type and target.object_type != query.object_type:
                continue
            if needle and needle not in target.name.lower() and needle not in target.object_type.lower():
                continue
            selected.append(target)
        return selected

    @staticmethod
    def _type_facets(targets: Iterable[RestoreTarget]) -> list[RestoreTargetTypeCount]:
        counts: dict[str, int] = {}
        for target in targets:
            counts[target.object_type] = counts.get(target.object_type, 0) + 1
        return [
            RestoreTargetTypeCount(type=object_type, count=count)
            for object_type, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        ]

    @staticmethod
    def _site_facets(targets: Iterable[RestoreTarget]) -> list[RestoreTargetSite]:
        sites: dict[str, str] = {}
        for target in targets:
            if target.site_mist_id is None:
                continue
            sites.setdefault(target.site_mist_id, target.site_name or target.site_mist_id)
        return [
            RestoreTargetSite(id=site_id, name=name)
            for site_id, name in sorted(sites.items(), key=lambda item: (item[1].lower(), item[0]))
        ]


class MongoRestoreTargetSearch:
    """Filter, facet, and paginate inside MongoDB, in one round trip.

    The page, its unpaged total, and both facet vocabularies are branches of a
    single ``$facet``: they read the same filtered set but apply different
    subsets of it, which is what lets a facet row survive being selected.
    """

    async def search(self, query: RestoreTargetQuery) -> RestoreTargetPage:
        """Return one page of restore targets with its filter facet counts."""
        rows = await LogicalObject.aggregate(_pipeline(query)).to_list()
        result: dict[str, Any] = rows[0] if rows else {}
        total = result.get("total") or []
        return RestoreTargetPage(
            items=[_target(row) for row in result.get("page") or []],
            total=int(total[0]["value"]) if total else 0,
            types=[
                RestoreTargetTypeCount(type=row["_id"], count=int(row["count"])) for row in result.get("types") or []
            ],
            sites=[RestoreTargetSite(id=row["_id"], name=row["name"]) for row in result.get("sites") or []],
        )


def _target(row: dict[str, Any]) -> RestoreTarget:
    newest = row["newest"]
    return RestoreTarget(
        logical_object_id=str(row["_id"]),
        version_id=str(newest["_id"]),
        name=row["name"],
        object_type=row["object_type"],
        scope=row["scope"],
        site_mist_id=row.get("site_mist_id"),
        site_name=row.get("site_name"),
        version=int(newest["version"]),
        observed_at=newest["observed_at"],
    )


def _pipeline(query: RestoreTargetQuery) -> list[dict[str, Any]]:
    """Build the one aggregation that answers a target page."""
    organization_id = query.organization_id

    stages: list[dict[str, Any]] = [
        {"$match": {"organization_id": organization_id}},
        # The newest version that is not a deletion is what a restore would
        # write back. An object with none of those is not a target at all,
        # which is what the $unwind below drops.
        {
            "$lookup": {
                "from": "object_versions",
                "let": {"logical_id": "$_id"},
                "pipeline": [
                    {
                        "$match": {
                            "organization_id": organization_id,
                            "is_deleted": False,
                            "$expr": {"$eq": ["$logical_object_id", "$$logical_id"]},
                        }
                    },
                    {"$sort": {"version": -1}},
                    {"$limit": 1},
                    {"$project": {"version": 1, "observed_at": 1}},
                ],
                "as": "newest",
            }
        },
        {"$unwind": "$newest"},
        # A site-scoped object shows the name of its site, which is itself a
        # logical object in this collection.
        {
            "$lookup": {
                "from": "logical_objects",
                "let": {"site_id": "$site_mist_id"},
                "pipeline": [
                    {
                        "$match": {
                            "organization_id": organization_id,
                            "object_type": "sites",
                            "is_deleted": False,
                            "$expr": {"$eq": ["$current_mist_id", "$$site_id"]},
                        }
                    },
                    {"$limit": 1},
                    {"$project": {"name": 1}},
                ],
                "as": "site",
            }
        },
        {
            "$addFields": {
                "site_name": {"$first": "$site.name"},
                # Sorting and the free-text match are case-insensitive, and a
                # collation would apply to the whole pipeline rather than these
                # two fields, so the folded forms are materialised here.
                "sort_name": {"$toLower": "$name"},
            }
        },
    ]

    common = _common_match(query)
    if common:
        stages.append({"$match": common})

    site_match = {"site_mist_id": query.site_id} if query.site_id else {}
    type_match = {"object_type": query.object_type} if query.object_type else {}
    both = {**site_match, **type_match}

    stages.append(
        {
            "$facet": {
                "page": [
                    *_maybe_match(both),
                    {"$sort": {"object_type": 1, "sort_name": 1, "_id": 1}},
                    {"$skip": query.skip},
                    {"$limit": query.limit},
                ],
                "total": [*_maybe_match(both), {"$count": "value"}],
                # The type row honours the site but not the type it drives, and
                # the site row the reverse.
                "types": [
                    *_maybe_match(site_match),
                    {"$group": {"_id": "$object_type", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1, "_id": 1}},
                ],
                "sites": [
                    *_maybe_match(type_match),
                    {"$match": {"site_mist_id": {"$ne": None}}},
                    {"$group": {"_id": "$site_mist_id", "name": {"$first": "$site_name"}}},
                    # A site whose own object is gone is still named by the
                    # objects in it, so it falls back to its Mist identifier.
                    {"$addFields": {"name": {"$ifNull": ["$name", "$_id"]}}},
                    {"$addFields": {"sort_name": {"$toLower": "$name"}}},
                    {"$sort": {"sort_name": 1, "_id": 1}},
                ],
            }
        }
    )
    return stages


def _common_match(query: RestoreTargetQuery) -> dict[str, Any]:
    """The filters every facet branch honours."""
    match: dict[str, Any] = {}
    if query.scope != "all":
        match["scope"] = query.scope
    needle = (query.q or "").strip()
    if needle:
        pattern = re.escape(needle)
        match["$or"] = [
            {"name": {"$regex": pattern, "$options": "i"}},
            {"object_type": {"$regex": pattern, "$options": "i"}},
        ]
    return match


def _maybe_match(criteria: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"$match": criteria}] if criteria else []


class RestoreTargetService:
    """Filter, facet, and paginate the restorable objects of one organization."""

    def __init__(self, search: RestoreTargetSearch | None = None) -> None:
        self._search = search or MongoRestoreTargetSearch()

    async def search(self, query: RestoreTargetQuery) -> RestoreTargetPage:
        """Return one page of restore targets with its filter facet counts."""
        return await self._search.search(query)
