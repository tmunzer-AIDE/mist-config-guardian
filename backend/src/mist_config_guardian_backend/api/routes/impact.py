"""Read-only site Impact workspace endpoints."""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from mist_config_guardian_backend.api.dependencies import get_credential_vault, require_organization, require_viewer
from mist_config_guardian_backend.api.routes.change_groups import _identifier
from mist_config_guardian_backend.integrations.mist_topology import fetch_site_topology
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.schemas.impact import ImpactSiteList, SiteChangeList, SiteTopology
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services import site_impact
from mist_config_guardian_backend.services.change_groups import as_utc
from mist_config_guardian_backend.services.service_credentials import service_token

router = APIRouter(prefix="/organizations/{organization_id}/impact")


class ImpactFilters(BaseModel):
    range: Literal["24h", "7d", "30d"] = "24h"
    as_of: datetime | None = None
    skip: int = Field(default=0, ge=0)
    limit: int = Field(default=50, ge=1, le=100)


async def _site(organization: Organization, site_id: str, at: datetime) -> None:
    sites = await site_impact.list_sites(_identifier(organization), at)
    if not any(site.id == site_id for site in sites.items):
        raise HTTPException(
            status_code=404, detail="Site not found in this organization's stored inventory or monitoring history"
        )


@router.get("/sites")
async def impact_sites(
    organization: Annotated[Organization, Depends(require_organization)],
    _viewer: Annotated[User, Depends(require_viewer)],
    as_of: datetime | None = None,
) -> ImpactSiteList:
    """Discover known sites without sending configuration or secrets."""
    return await site_impact.list_sites(_identifier(organization), as_utc(as_of) if as_of else utc_now())


@router.get("/sites/{site_id}/topology")
async def site_topology(
    site_id: UUID,
    organization: Annotated[Organization, Depends(require_organization)],
    _viewer: Annotated[User, Depends(require_viewer)],
    vault: Annotated[CredentialVault, Depends(get_credential_vault)],
    as_of: datetime | None = None,
) -> SiteTopology:
    """Read live all-device statistics; historical requests use stored inventory only."""
    site = str(site_id)
    end = as_utc(as_of) if as_of else utc_now()
    await _site(organization, site, end)
    if as_of is None:
        try:
            token = await service_token(organization, vault)
            return await fetch_site_topology(site_id=site, token=token, region=organization.cloud_region)
        except (httpx.HTTPError, ValueError):
            # Retain a useful inventory while explicitly withholding live health.
            result = await site_impact.stored_topology(_identifier(organization), site, end, historical=False)
            result.warnings.insert(
                0, "Live topology unavailable. Check the read-only Mist token and site statistics access."
            )
            return result
    return await site_impact.stored_topology(_identifier(organization), site, end, historical=True)


@router.get("/sites/{site_id}/changes")
async def site_changes(
    site_id: UUID,
    organization: Annotated[Organization, Depends(require_organization)],
    _viewer: Annotated[User, Depends(require_viewer)],
    filters: Annotated[ImpactFilters, Query()],
) -> SiteChangeList:
    """Page site configuration events, then expand only their small device summaries."""
    site = str(site_id)
    await _site(organization, site, as_utc(filters.as_of) if filters.as_of else utc_now())
    return await site_impact.list_changes(
        _identifier(organization),
        site,
        range_key=filters.range,
        end=filters.as_of,
        skip=filters.skip,
        limit=filters.limit,
    )
