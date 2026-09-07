"""Restore planning and execution schemas."""

from datetime import datetime

from beanie import PydanticObjectId
from pydantic import BaseModel, Field, SecretStr

from mist_config_guardian_backend.models.restore import (
    RestoreAction,
    RestoreActionStatus,
    RestoreActionType,
    RestoreMode,
    RestoreOperation,
    RestoreStatus,
)
from mist_config_guardian_backend.snapshots.secrets import redact_configuration


class RestorePlanRequest(BaseModel):
    """Selected immutable versions for a restore plan."""

    version_ids: list[PydanticObjectId] = Field(min_length=1, max_length=100)
    mode: RestoreMode = RestoreMode.NON_DESTRUCTIVE
    include_dependencies: bool = True


class RestoreExecuteRequest(BaseModel):
    """Fresh delegated Mist administrator credential."""

    administrator_token: SecretStr = Field(min_length=1, max_length=2048)


class RestoreActionResponse(BaseModel):
    """Safe review representation for one planned action."""

    logical_object_id: str
    source_version_id: str
    order: int
    action: RestoreActionType
    scope: str
    object_type: str
    object_name: str
    current_mist_id: str
    site_mist_id: str | None
    configuration: dict[str, object]
    depends_on: list[str]
    status: RestoreActionStatus
    resulting_mist_id: str | None
    error: str | None

    @classmethod
    def from_model(cls, action: RestoreAction) -> "RestoreActionResponse":
        """Redact protected fields for plan review."""
        return cls(
            logical_object_id=str(action.logical_object_id),
            source_version_id=str(action.source_version_id),
            order=action.order,
            action=action.action,
            scope=action.scope,
            object_type=action.object_type,
            object_name=action.object_name,
            current_mist_id=action.current_mist_id,
            site_mist_id=action.site_mist_id,
            configuration=redact_configuration(action.protected_configuration),
            depends_on=[str(item) for item in action.depends_on],
            status=action.status,
            resulting_mist_id=action.resulting_mist_id,
            error=action.error,
        )


class RestoreOperationResponse(BaseModel):
    """Reviewable restore plan without delegated credentials."""

    id: str
    mode: RestoreMode
    include_dependencies: bool
    target_at: datetime
    status: RestoreStatus
    actions: list[RestoreActionResponse]
    warnings: list[str]
    preflight_errors: list[str]
    credential_actor: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    task_id: str | None

    @classmethod
    def from_document(cls, operation: RestoreOperation) -> "RestoreOperationResponse":
        """Create an API response with no credential material."""
        if operation.id is None:
            msg = "Persisted restore operation is missing an identifier"
            raise ValueError(msg)
        return cls(
            id=str(operation.id),
            mode=operation.mode,
            include_dependencies=operation.include_dependencies,
            target_at=operation.target_at,
            status=operation.status,
            actions=[RestoreActionResponse.from_model(action) for action in operation.actions],
            warnings=list(operation.warnings),
            preflight_errors=list(operation.preflight_errors),
            credential_actor=operation.credential_actor,
            started_at=operation.started_at,
            completed_at=operation.completed_at,
            created_at=operation.created_at,
            task_id=operation.task_id,
        )


class RestoreOperationListResponse(BaseModel):
    """Paginated restore operations."""

    items: list[RestoreOperationResponse]
    total: int
