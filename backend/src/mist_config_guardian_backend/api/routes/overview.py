"""Organization overview aggregate endpoint."""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from mist_config_guardian_backend.api.dependencies import require_organization, require_viewer
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.schemas.overview import OrganizationOverviewResponse
from mist_config_guardian_backend.services.overview import OverviewService

router = APIRouter(prefix="/organizations/{organization_id}/overview")


def get_overview_service() -> OverviewService:
    """Build the Overview read model."""
    return OverviewService()


class OverviewFilters(BaseModel):
    """Window and depth of the Overview read model."""

    range: Literal["24h", "7d", "30d"] = "24h"
    # The shell polls the counts on every navigation, so it asks for them alone.
    counts_only: bool = Field(default=False)


@router.get("")
async def read_overview(
    organization: Annotated[Organization, Depends(require_organization)],
    viewer: Annotated[User, Depends(require_viewer)],
    service: Annotated[OverviewService, Depends(get_overview_service)],
    filters: Annotated[OverviewFilters, Query()],
) -> OrganizationOverviewResponse:
    """Return the Overview read model, or only its navigation badge counts."""
    return await service.collect(
        organization,
        range_key=filters.range,
        viewer_email=viewer.email,
        counts_only=filters.counts_only,
    )
