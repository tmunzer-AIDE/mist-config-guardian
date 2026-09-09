"""AI provider configuration and secret-safe assistance endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from mist_config_guardian_backend.api.dependencies import (
    get_application_configuration_service,
    require_administrator,
    require_viewer,
)
from mist_config_guardian_backend.api.routes.diff import (
    VersionRepository,
    get_version_repository,
    load_version_pair,
)
from mist_config_guardian_backend.integrations.ai_provider import AiProviderError
from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.schemas.ai import (
    AiDiffFollowupResponse,
    AiDiffSummaryResponse,
    DiffFollowupRequest,
    DiffSummaryRequest,
)
from mist_config_guardian_backend.schemas.application_configuration import (
    AiConnectionTestResponse,
    AiModelListResponse,
    AiProviderDraft,
    AiSettingsResponse,
    AiSettingsUpdate,
)
from mist_config_guardian_backend.services.ai_assist import (
    AiAssistService,
    AiAuditRecorder,
    AiEvidenceError,
    AiUnavailableError,
    DiffSubject,
)
from mist_config_guardian_backend.services.application_configuration import (
    ApplicationConfigurationError,
    ApplicationConfigurationService,
)
from mist_config_guardian_backend.services.diff import diff_configurations
from mist_config_guardian_backend.services.mfa import require_fresh_mfa
from mist_config_guardian_backend.services.reauthentication import confirm_password
from mist_config_guardian_backend.services.throttling import ThrottleService, get_throttle_service

router = APIRouter(prefix="/ai")


def get_ai_audit_recorder() -> AiAuditRecorder:
    """Build the append-only AI request audit recorder."""
    return AiAuditRecorder()


def get_ai_assist_service(
    configuration: Annotated[
        ApplicationConfigurationService,
        Depends(get_application_configuration_service),
    ],
    recorder: Annotated[AiAuditRecorder, Depends(get_ai_audit_recorder)],
) -> AiAssistService:
    """Build the diff assistance service."""
    return AiAssistService(configuration, recorder=recorder)


@router.get("/settings")
async def get_ai_settings(
    settings: Annotated[
        ApplicationConfigurationService,
        Depends(get_application_configuration_service),
    ],
    _administrator: Annotated[User, Depends(require_administrator)],
) -> AiSettingsResponse:
    """Return safe AI provider settings."""
    return await settings.get_ai_settings()


@router.put("/settings")
async def update_ai_settings(
    request: AiSettingsUpdate,
    settings: Annotated[
        ApplicationConfigurationService,
        Depends(get_application_configuration_service),
    ],
    administrator: Annotated[User, Depends(require_administrator)],
    _stepped_up: Annotated[User, Depends(require_fresh_mfa)],
    throttle: Annotated[ThrottleService, Depends(get_throttle_service)],
) -> AiSettingsResponse:
    """Update AI provider settings, keeping the stored key when none is sent.

    These settings hold a provider API key, so this is a credential change and
    asks for the password like one.
    """
    await confirm_password(administrator, request.password.get_secret_value(), throttle)
    try:
        return await settings.update_ai_settings(request)
    except ApplicationConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc


@router.post("/settings/test")
async def check_ai_connection(
    settings: Annotated[
        ApplicationConfigurationService,
        Depends(get_application_configuration_service),
    ],
    recorder: Annotated[AiAuditRecorder, Depends(get_ai_audit_recorder)],
    _administrator: Annotated[User, Depends(require_administrator)],
    request: AiProviderDraft | None = None,
) -> AiConnectionTestResponse:
    """Check a draft provider, or persist a check of the saved provider."""
    try:
        return await settings.test_ai_connection(recorder, draft=request)
    except ApplicationConfigurationError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.get("/models")
async def list_ai_models(
    settings: Annotated[
        ApplicationConfigurationService,
        Depends(get_application_configuration_service),
    ],
    _administrator: Annotated[User, Depends(require_administrator)],
) -> AiModelListResponse:
    """Discover the models the configured provider advertises."""
    try:
        items = await settings.list_ai_models()
    except ApplicationConfigurationError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except AiProviderError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    return AiModelListResponse(items=items)


@router.post("/models")
async def list_draft_ai_models(
    request: AiProviderDraft,
    settings: Annotated[ApplicationConfigurationService, Depends(get_application_configuration_service)],
    _administrator: Annotated[User, Depends(require_administrator)],
) -> AiModelListResponse:
    """Discover models before saving provider settings or choosing a model."""
    try:
        items = await settings.list_ai_models(draft=request)
    except ApplicationConfigurationError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except AiProviderError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    return AiModelListResponse(items=items)


@router.post("/diff-summary")
async def summarize_diff(
    request: DiffSummaryRequest,
    assist: Annotated[AiAssistService, Depends(get_ai_assist_service)],
    repository: Annotated[VersionRepository, Depends(get_version_repository)],
    viewer: Annotated[User, Depends(require_viewer)],
) -> AiDiffSummaryResponse:
    """Summarise one comparison from redacted evidence only."""
    before, after = await load_version_pair(
        repository,
        request.organization_id,
        request.from_version_id,
        request.to_version_id,
    )
    diff = diff_configurations(before.configuration, after.configuration)
    subject = DiffSubject(
        organization_id=request.organization_id,
        from_version_id=request.from_version_id,
        to_version_id=request.to_version_id,
        user_id=viewer.id,
    )
    try:
        return await assist.summarize_diff(diff, subject, regenerate=request.regenerate)
    except AiUnavailableError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except (AiEvidenceError, AiProviderError) as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc


@router.post("/diff-followup")
async def answer_diff_followup(
    request: DiffFollowupRequest,
    assist: Annotated[AiAssistService, Depends(get_ai_assist_service)],
    repository: Annotated[VersionRepository, Depends(get_version_repository)],
    viewer: Annotated[User, Depends(require_viewer)],
) -> AiDiffFollowupResponse:
    """Answer one question against a single fixed comparison."""
    before, after = await load_version_pair(
        repository,
        request.organization_id,
        request.from_version_id,
        request.to_version_id,
    )
    diff = diff_configurations(before.configuration, after.configuration)
    subject = DiffSubject(
        organization_id=request.organization_id,
        from_version_id=request.from_version_id,
        to_version_id=request.to_version_id,
        user_id=viewer.id,
    )
    try:
        return await assist.answer_followup(diff, subject, request.question)
    except AiUnavailableError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except (AiEvidenceError, AiProviderError) as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
