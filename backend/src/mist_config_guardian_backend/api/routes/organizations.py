"""Managed Mist organization endpoints."""

from typing import Annotated

from beanie import PydanticObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, status

from mist_config_guardian_backend.api.dependencies import (
    get_organization_service,
    require_administrator,
    require_viewer,
)
from mist_config_guardian_backend.integrations.mist import MistVerificationError
from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.schemas.organization import (
    OrganizationCreateRequest,
    OrganizationListResponse,
    OrganizationResponse,
    OrganizationUpdateRequest,
    ServiceTokenUpdateRequest,
    WebhookSecretResponse,
)
from mist_config_guardian_backend.services.organizations import (
    OrganizationAlreadyExistsError,
    OrganizationNotFoundError,
    OrganizationService,
)

router = APIRouter(prefix="/organizations")


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_organization(
    request: OrganizationCreateRequest,
    organizations: Annotated[OrganizationService, Depends(get_organization_service)],
    _administrator: Annotated[User, Depends(require_administrator)],
) -> OrganizationResponse:
    """Verify and onboard a Mist organization."""
    try:
        organization = await organizations.create(request)
    except MistVerificationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    except OrganizationAlreadyExistsError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return OrganizationResponse.from_document(organization)


@router.post("/{organization_id}/webhook-secret/rotate")
async def rotate_webhook_secret(
    organization_id: PydanticObjectId,
    organizations: Annotated[OrganizationService, Depends(get_organization_service)],
    _administrator: Annotated[User, Depends(require_administrator)],
) -> WebhookSecretResponse:
    """Rotate and return a webhook secret exactly once."""
    try:
        organization, webhook_secret = await organizations.rotate_webhook_secret(organization_id)
    except OrganizationNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return WebhookSecretResponse(
        endpoint=f"/api/v1/webhooks/mist/{organization.id}",
        secret=webhook_secret,
    )


@router.get("")
async def list_organizations(
    organizations: Annotated[OrganizationService, Depends(get_organization_service)],
    _viewer: Annotated[User, Depends(require_viewer)],
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> OrganizationListResponse:
    """List managed Mist organizations."""
    items, total = await organizations.list(skip=skip, limit=limit)
    return OrganizationListResponse(
        items=[OrganizationResponse.from_document(item) for item in items],
        total=total,
    )


@router.get("/{organization_id}")
async def get_organization(
    organization_id: PydanticObjectId,
    organizations: Annotated[OrganizationService, Depends(get_organization_service)],
    _viewer: Annotated[User, Depends(require_viewer)],
) -> OrganizationResponse:
    """Return one managed organization."""
    try:
        organization = await organizations.get(organization_id)
    except OrganizationNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return OrganizationResponse.from_document(organization)


@router.patch("/{organization_id}")
async def update_organization(
    organization_id: PydanticObjectId,
    request: OrganizationUpdateRequest,
    organizations: Annotated[OrganizationService, Depends(get_organization_service)],
    _administrator: Annotated[User, Depends(require_administrator)],
) -> OrganizationResponse:
    """Update organization schedules and retention."""
    try:
        organization = await organizations.update(organization_id, request)
    except OrganizationNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return OrganizationResponse.from_document(organization)


@router.put("/{organization_id}/service-token")
async def replace_service_token(
    organization_id: PydanticObjectId,
    request: ServiceTokenUpdateRequest,
    organizations: Annotated[OrganizationService, Depends(get_organization_service)],
    _administrator: Annotated[User, Depends(require_administrator)],
) -> OrganizationResponse:
    """Replace and verify an organization's read-only service token."""
    try:
        organization = await organizations.replace_service_token(
            organization_id,
            request.service_token.get_secret_value(),
        )
    except OrganizationNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except MistVerificationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    return OrganizationResponse.from_document(organization)


@router.post("/{organization_id}/verify")
async def verify_organization(
    organization_id: PydanticObjectId,
    organizations: Annotated[OrganizationService, Depends(get_organization_service)],
    _administrator: Annotated[User, Depends(require_administrator)],
) -> OrganizationResponse:
    """Reverify the stored read-only service token."""
    try:
        organization = await organizations.verify_stored_token(organization_id)
    except OrganizationNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except MistVerificationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    return OrganizationResponse.from_document(organization)
