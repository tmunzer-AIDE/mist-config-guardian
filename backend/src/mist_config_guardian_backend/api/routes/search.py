"""Global search endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from mist_config_guardian_backend.api.dependencies import require_organization, require_viewer
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.schemas.search import SearchResultListResponse
from mist_config_guardian_backend.services.search import (
    DEFAULT_LIMIT,
    MINIMUM_QUERY_LENGTH,
    SearchService,
)

router = APIRouter(prefix="/organizations/{organization_id}/search")


def get_search_service() -> SearchService:
    """Build the global search service."""
    return SearchService()


@router.get("")
async def search_organization(
    organization: Annotated[Organization, Depends(require_organization)],
    _viewer: Annotated[User, Depends(require_viewer)],
    service: Annotated[SearchService, Depends(get_search_service)],
    q: Annotated[str, Query(min_length=MINIMUM_QUERY_LENGTH)],
    limit: Annotated[int, Query(ge=1, le=100)] = DEFAULT_LIMIT,
) -> SearchResultListResponse:
    """Search objects, change groups, actors, sites, and restores in one organization."""
    if organization.id is None:
        msg = "Persisted organization is missing an identifier"
        raise ValueError(msg)
    return await service.search(organization.id, q, limit=limit)
