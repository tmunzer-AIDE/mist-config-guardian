"""Global search across one organization's configuration and change history.

Search is deliberately narrow: a case-insensitive substring over indexed,
organization-scoped fields, with a hard per-kind cap. It is a navigation aid
that has to answer while the user is still typing, not a reporting query.

The user's term is escaped before it reaches a ``$regex``, so a term full of
regular-expression metacharacters searches for those characters.
"""

import re
from collections.abc import Sequence
from typing import Protocol

from beanie import PydanticObjectId

from mist_config_guardian_backend.models.restore import RestoreOperation
from mist_config_guardian_backend.models.snapshot import LogicalObject
from mist_config_guardian_backend.models.webhook import AuditChangeGroup
from mist_config_guardian_backend.schemas.search import (
    SearchResultListResponse,
    SearchResultResponse,
)
from mist_config_guardian_backend.services.change_groups import build_title, object_type_label
from mist_config_guardian_backend.services.deep_links import deep_link

MINIMUM_QUERY_LENGTH = 2
DEFAULT_LIMIT = 25
# Each kind is capped independently so one very common term cannot crowd the
# others out of the result set.
PER_KIND_LIMIT = 10


class SearchReader(Protocol):
    """The indexed lookups global search is built from."""

    async def objects(
        self,
        organization_id: PydanticObjectId,
        pattern: str,
        *,
        limit: int,
    ) -> list[LogicalObject]:
        """Return logical objects whose name or type matches the pattern."""

    async def change_groups(
        self,
        organization_id: PydanticObjectId,
        pattern: str,
        *,
        limit: int,
    ) -> list[AuditChangeGroup]:
        """Return change groups whose audit id, actor, or objects match."""

    async def sites(
        self,
        organization_id: PydanticObjectId,
        pattern: str,
        *,
        limit: int,
    ) -> list[LogicalObject]:
        """Return site objects whose name or Mist identifier matches."""

    async def restores(
        self,
        organization_id: PydanticObjectId,
        pattern: str,
        *,
        limit: int,
    ) -> list[RestoreOperation]:
        """Return restore operations whose identifier matches."""


class BeanieSearchReader:
    """MongoDB-backed search lookups."""

    async def objects(
        self,
        organization_id: PydanticObjectId,
        pattern: str,
        *,
        limit: int,
    ) -> list[LogicalObject]:
        """Return logical objects whose name or type matches the pattern."""
        return (
            await LogicalObject.find(
                {
                    "organization_id": organization_id,
                    "$or": [
                        {"name": {"$regex": pattern, "$options": "i"}},
                        {"object_type": {"$regex": pattern, "$options": "i"}},
                    ],
                }
            )
            .sort("object_type", "name")
            .limit(limit)
            .to_list()
        )

    async def change_groups(
        self,
        organization_id: PydanticObjectId,
        pattern: str,
        *,
        limit: int,
    ) -> list[AuditChangeGroup]:
        """Return change groups whose audit id, actor, or objects match."""
        return (
            await AuditChangeGroup.find(
                {
                    "organization_id": organization_id,
                    "$or": [
                        {"audit_id": {"$regex": pattern, "$options": "i"}},
                        {"actor": {"$regex": pattern, "$options": "i"}},
                        {"changed_objects.object_name": {"$regex": pattern, "$options": "i"}},
                    ],
                }
            )
            .sort("-occurred_at")
            .limit(limit)
            .to_list()
        )

    async def sites(
        self,
        organization_id: PydanticObjectId,
        pattern: str,
        *,
        limit: int,
    ) -> list[LogicalObject]:
        """Return site objects whose name or Mist identifier matches."""
        return (
            await LogicalObject.find(
                {
                    "organization_id": organization_id,
                    "object_type": "sites",
                    "$or": [
                        {"name": {"$regex": pattern, "$options": "i"}},
                        {"current_mist_id": {"$regex": pattern, "$options": "i"}},
                    ],
                }
            )
            .sort("name")
            .limit(limit)
            .to_list()
        )

    async def restores(
        self,
        organization_id: PydanticObjectId,
        pattern: str,
        *,
        limit: int,
    ) -> list[RestoreOperation]:
        """Return restore operations whose identifier matches."""
        pipeline: list[dict[str, object]] = [
            {"$match": {"organization_id": organization_id}},
            {"$sort": {"created_at": -1}},
            {"$addFields": {"identifier": {"$toString": "$_id"}}},
            {"$match": {"identifier": {"$regex": pattern, "$options": "i"}}},
            {"$limit": limit},
        ]
        return await RestoreOperation.aggregate(
            pipeline,
            projection_model=RestoreOperation,
        ).to_list()


class SearchService:
    """Answer the header's global search for one organization."""

    def __init__(self, reader: SearchReader | None = None) -> None:
        self._reader = reader if reader is not None else BeanieSearchReader()

    async def search(
        self,
        organization_id: PydanticObjectId,
        query: str,
        *,
        limit: int = DEFAULT_LIMIT,
    ) -> SearchResultListResponse:
        """Return every match for a term, ordered object, change, actor, site, restore."""
        term = query.strip()
        if len(term) < MINIMUM_QUERY_LENGTH:
            return SearchResultListResponse(items=[], total=0)
        pattern = re.escape(term)
        objects = await self._reader.objects(organization_id, pattern, limit=PER_KIND_LIMIT)
        groups = await self._reader.change_groups(organization_id, pattern, limit=PER_KIND_LIMIT)
        sites = await self._reader.sites(organization_id, pattern, limit=PER_KIND_LIMIT)
        restores = await self._reader.restores(organization_id, pattern, limit=PER_KIND_LIMIT)

        results = [
            *_object_results(objects),
            *_change_group_results(groups, term),
            *_actor_results(groups, term),
            *_site_results(sites),
            *_restore_results(restores),
        ]
        return SearchResultListResponse(items=results[:limit], total=len(results))


def _object_results(objects: Sequence[LogicalObject]) -> list[SearchResultResponse]:
    return [
        SearchResultResponse(
            kind="object",
            id=str(logical.id),
            title=logical.name or logical.current_mist_id,
            subtitle=object_type_label(logical.object_type, logical.scope),
            meta=f"v{logical.current_version}" + (" · deleted" if logical.is_deleted else ""),
            target="history",
            target_params=deep_link("history", object=str(logical.id)),
        )
        for logical in objects
        if logical.id is not None
    ]


def _change_group_results(
    groups: Sequence[AuditChangeGroup],
    term: str,
) -> list[SearchResultResponse]:
    lowered = term.lower()
    results = []
    for group in groups:
        if group.id is None:
            continue
        matched_audit = lowered in group.audit_id.lower()
        results.append(
            SearchResultResponse(
                kind="audit_id" if matched_audit else "change_group",
                id=str(group.id),
                title=build_title(group.changed_objects, group.message),
                subtitle=group.audit_id if matched_audit else (group.actor or "Unattributed"),
                meta=group.impact_severity.value.upper(),
                target="changes",
                target_params=deep_link("changes", group=str(group.id)),
            )
        )
    return results


def _actor_results(groups: Sequence[AuditChangeGroup], term: str) -> list[SearchResultResponse]:
    lowered = term.lower()
    counts: dict[str, int] = {}
    for group in groups:
        if group.actor and lowered in group.actor.lower():
            counts[group.actor] = counts.get(group.actor, 0) + 1
    return [
        SearchResultResponse(
            kind="actor",
            id=actor,
            title=actor,
            subtitle="Administrator",
            meta=f"{count} change group{'' if count == 1 else 's'}",
            target="changes",
            target_params=deep_link("changes", actor=actor),
        )
        for actor, count in sorted(counts.items())
    ]


def _site_results(sites: Sequence[LogicalObject]) -> list[SearchResultResponse]:
    """Open a site in History the same way any other object opens.

    A site is a logical object, so it is addressed by the ``object`` parameter
    History already selects on; a Mist identifier under its own name would name
    a filter no page implements and land on an unfiltered list.
    """
    return [
        SearchResultResponse(
            kind="site",
            id=str(site.id),
            title=site.name or site.current_mist_id,
            subtitle="Site",
            meta=site.current_mist_id,
            target="history",
            target_params=deep_link("history", object=str(site.id)),
        )
        for site in sites
        if site.id is not None
    ]


def _restore_results(operations: Sequence[RestoreOperation]) -> list[SearchResultResponse]:
    results = []
    for operation in operations:
        identifier = getattr(operation, "id", None)
        if identifier is None:
            continue
        status = getattr(operation, "status", None)
        mode = getattr(operation, "mode", None)
        results.append(
            SearchResultResponse(
                kind="restore",
                id=str(identifier),
                title=f"Restore {str(identifier)[-6:]}",
                subtitle=str(getattr(mode, "value", mode) or "restore").replace("_", " "),
                meta=str(getattr(status, "value", status) or "").upper(),
                target="restore",
                target_params=deep_link("restore", operation=str(identifier)),
            )
        )
    return results
