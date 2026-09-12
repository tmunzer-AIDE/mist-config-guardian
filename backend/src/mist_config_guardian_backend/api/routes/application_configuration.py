"""Administrator-managed application configuration endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from mist_config_guardian_backend.api.dependencies import (
    get_application_configuration_service,
    require_administrator,
)
from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.schemas.application_configuration import (
    ImpactAiSettingsResponse,
    ImpactAiSettingsUpdate,
    SmtpConnectionTestResponse,
    SmtpSettingsResponse,
    SmtpSettingsUpdate,
)
from mist_config_guardian_backend.services.application_configuration import (
    ApplicationConfigurationError,
    ApplicationConfigurationService,
)

router = APIRouter(prefix="/settings")


@router.get("/impact-ai")
async def get_impact_ai_settings(
    settings: Annotated[
        ApplicationConfigurationService,
        Depends(get_application_configuration_service),
    ],
    _administrator: Annotated[User, Depends(require_administrator)],
) -> ImpactAiSettingsResponse:
    """Return safe AI impact-provider settings."""
    return await settings.get_impact_ai()


@router.put("/impact-ai")
async def update_impact_ai_settings(
    request: ImpactAiSettingsUpdate,
    settings: Annotated[
        ApplicationConfigurationService,
        Depends(get_application_configuration_service),
    ],
    _administrator: Annotated[User, Depends(require_administrator)],
) -> ImpactAiSettingsResponse:
    """Update AI impact-provider settings."""
    try:
        return await settings.update_impact_ai(request)
    except ApplicationConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc


@router.get("/smtp")
async def read_smtp_settings(
    settings: Annotated[
        ApplicationConfigurationService,
        Depends(get_application_configuration_service),
    ],
    _administrator: Annotated[User, Depends(require_administrator)],
) -> SmtpSettingsResponse:
    """Return the stored SMTP settings without the password."""
    return await settings.get_smtp()


@router.put("/smtp")
async def update_smtp_settings(
    request: SmtpSettingsUpdate,
    settings: Annotated[
        ApplicationConfigurationService,
        Depends(get_application_configuration_service),
    ],
    _administrator: Annotated[User, Depends(require_administrator)],
) -> SmtpSettingsResponse:
    """Persist SMTP settings, refusing what cannot deliver safely."""
    try:
        return await settings.update_smtp(request)
    except ApplicationConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc


@router.post("/smtp/test")
async def check_smtp_connection(
    settings: Annotated[
        ApplicationConfigurationService,
        Depends(get_application_configuration_service),
    ],
    _administrator: Annotated[User, Depends(require_administrator)],
) -> SmtpConnectionTestResponse:
    """Probe the stored SMTP server and record the outcome."""
    return await settings.test_smtp_connection()
