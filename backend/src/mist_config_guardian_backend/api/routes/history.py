"""Configuration object and immutable version history endpoints."""

import re
from typing import Annotated, Literal

from beanie import PydanticObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from mist_config_guardian_backend.api.dependencies import (
    get_organization_service,
    require_viewer,
)
from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectVersion
from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.schemas.history import (
    LogicalObjectListResponse,
    LogicalObjectResponse,
    ObjectVersionListResponse,
    ObjectVersionResponse,
)
from mist_config_guardian_backend.services.organizations import (
    OrganizationNotFoundError,
    OrganizationService,
)

router = APIRouter(prefix="/organizations/{organization_id}/objects")


class ObjectListFilters(BaseModel):
    """Configuration history list filters."""

    object_type: str | None = None
    site_id: str | None = None
    scope: Literal["org", "site"] | None = None
    include_deleted: bool = False
    q: str | None = None
    sort: Literal["updated_at", "name", "object_type", "site_mist_id", "current_version"] = "updated_at"
    direction: Literal["asc", "desc"] = "desc"
    skip: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1, le=500)


# Every supported sort can tie; the unique id keeps pagination deterministic.
OBJECT_LIST_SORT = ("-updated_at", "_id")


def object_list_sort(filters: ObjectListFilters) -> tuple[str, str]:
    """Sort the entire matching catalogue with a stable pagination tie-breaker."""
    return (f"{'-' if filters.direction == 'desc' else ''}{filters.sort}", "_id")


def object_list_criteria(
    organization_id: PydanticObjectId,
    filters: ObjectListFilters,
) -> dict[str, object]:
    """Translate list filters into the MongoDB criteria they select.

    Free text matches a name or a type, the way the search page and the restore
    picker do. The term is escaped before it reaches the ``$regex``, so a name
    full of punctuation is searched for rather than interpreted.
    """
    criteria: dict[str, object] = {"organization_id": organization_id}
    if filters.scope:
        criteria["scope"] = filters.scope
    if filters.object_type:
        criteria["object_type"] = filters.object_type
    if filters.site_id:
        criteria["site_mist_id"] = filters.site_id
    if not filters.include_deleted:
        criteria["is_deleted"] = False
    term = (filters.q or "").strip()
    if term:
        pattern = re.escape(term)
        criteria["$or"] = [
            {"name": {"$regex": pattern, "$options": "i"}},
            {"object_type": {"$regex": pattern, "$options": "i"}},
            {"current_mist_id": {"$regex": pattern, "$options": "i"}},
            {"site_mist_id": {"$regex": pattern, "$options": "i"}},
        ]
    return criteria


@router.get("")
async def list_objects(
    organization_id: PydanticObjectId,
    organizations: Annotated[OrganizationService, Depends(get_organization_service)],
    _viewer: Annotated[User, Depends(require_viewer)],
    filters: Annotated[ObjectListFilters, Query()],
) -> LogicalObjectListResponse:
    """List stable objects with optional type, site, free-text, and deletion filters."""
    try:
        await organizations.get(organization_id)
    except OrganizationNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    query = LogicalObject.find(object_list_criteria(organization_id, filters))
    total = await query.count()
    objects = await query.sort(*object_list_sort(filters)).skip(filters.skip).limit(filters.limit).to_list()
    return LogicalObjectListResponse(
        items=[LogicalObjectResponse.from_document(item) for item in objects],
        total=total,
    )


class ObjectFacet(BaseModel):
    """A complete catalogue facet, independent of object pagination."""

    id: str
    name: str
    count: int


class ObjectFacets(BaseModel):
    types: list[ObjectFacet]
    sites: list[ObjectFacet]


@router.get("/facets")
async def object_facets(
    organization_id: PydanticObjectId,
    organizations: Annotated[OrganizationService, Depends(get_organization_service)],
    _viewer: Annotated[User, Depends(require_viewer)],
    *,
    include_deleted: bool = False,
) -> ObjectFacets:
    """Return type/site filters for the entire organization's stored catalogue."""
    try:
        await organizations.get(organization_id)
    except OrganizationNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    criteria = object_list_criteria(organization_id, ObjectListFilters(include_deleted=include_deleted))
    groups = await LogicalObject.aggregate(
        [
            {"$match": criteria},
            {"$group": {"_id": {"type": "$object_type", "site": "$site_mist_id"}, "count": {"$sum": 1}}},
        ]
    ).to_list()
    sites = await LogicalObject.find({"organization_id": organization_id, "object_type": "sites"}).to_list()
    names = {site.current_mist_id: site.name for site in sites}
    types: dict[str, int] = {}
    counts: dict[str, int] = {}
    for row in groups:
        key = row["_id"]
        types[key["type"]] = types.get(key["type"], 0) + row["count"]
        if key.get("site"):
            counts[key["site"]] = counts.get(key["site"], 0) + row["count"]
    return ObjectFacets(
        types=[
            ObjectFacet(id=key, name=key.replace("_", " ").title(), count=value) for key, value in sorted(types.items())
        ],
        sites=[
            ObjectFacet(id=key, name=names.get(key, key), count=counts[key])
            for key in sorted(counts, key=lambda key: names.get(key, key).casefold())
        ],
    )


@router.get("/{logical_object_id}")
async def get_object(
    organization_id: PydanticObjectId,
    logical_object_id: PydanticObjectId,
    organizations: Annotated[OrganizationService, Depends(get_organization_service)],
    _viewer: Annotated[User, Depends(require_viewer)],
) -> LogicalObjectResponse:
    """Return one object's identity.

    The history rail holds a page rather than the whole catalogue, so the
    object being compared is not always in it — a link can name one that sorts
    past the first page, and a search can hide it. This resolves that object on
    its own so the comparison can still be labelled.
    """
    try:
        await organizations.get(organization_id)
    except OrganizationNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    logical = await LogicalObject.find_one(
        LogicalObject.id == logical_object_id,
        LogicalObject.organization_id == organization_id,
    )
    if logical is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Object not found")
    return LogicalObjectResponse.from_document(logical)


@router.get("/{logical_object_id}/versions")
async def list_object_versions(
    organization_id: PydanticObjectId,
    logical_object_id: PydanticObjectId,
    organizations: Annotated[OrganizationService, Depends(get_organization_service)],
    _viewer: Annotated[User, Depends(require_viewer)],
) -> ObjectVersionListResponse:
    """Return an object's immutable timeline newest first."""
    try:
        await organizations.get(organization_id)
    except OrganizationNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    logical = await LogicalObject.find_one(
        LogicalObject.id == logical_object_id,
        LogicalObject.organization_id == organization_id,
    )
    if logical is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Object not found")
    versions = (
        await ObjectVersion.find(
            ObjectVersion.organization_id == organization_id,
            ObjectVersion.logical_object_id == logical_object_id,
        )
        .sort("-version")
        .to_list()
    )
    return ObjectVersionListResponse(
        items=[ObjectVersionResponse.from_document(item) for item in versions],
        total=len(versions),
    )
