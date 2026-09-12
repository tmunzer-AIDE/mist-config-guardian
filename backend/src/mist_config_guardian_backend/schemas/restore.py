"""Restore planning, targeting, verification, and execution schemas."""

from datetime import datetime
from typing import Self

from beanie import PydanticObjectId
from pydantic import BaseModel, Field, SecretStr, model_validator

from mist_config_guardian_backend.models.restore import (
    RestoreAction,
    RestoreActionStatus,
    RestoreActionType,
    RestoreMode,
    RestoreOperation,
    RestoreStatus,
)
from mist_config_guardian_backend.schemas.approval import ApprovalResponse
from mist_config_guardian_backend.schemas.mist_login import MistLoginCredentials
from mist_config_guardian_backend.services.restore_planner import (
    RestoreVerificationResult,
    VerificationStatus,
)
from mist_config_guardian_backend.services.restore_targets import RestoreTargetPage
from mist_config_guardian_backend.snapshots.secrets import redact_configuration


class RestorePlanRequest(BaseModel):
    """Selected immutable versions for a restore plan."""

    version_ids: list[PydanticObjectId] = Field(min_length=1, max_length=100)
    mode: RestoreMode = RestoreMode.NON_DESTRUCTIVE
    include_dependencies: bool = True


class RestoreExecuteRequest(BaseModel):
    """Fresh delegated Mist administrator credential."""

    administrator_token: SecretStr | None = Field(default=None, min_length=1, max_length=2048)
    mist_login: MistLoginCredentials | None = None
    use_prepared_credential: bool = False

    @model_validator(mode="after")
    def exactly_one_credential(self) -> Self:
        if sum((self.administrator_token is not None, self.mist_login is not None, self.use_prepared_credential)) != 1:
            msg = "Supply either an administrator token or Mist login"
            raise ValueError(msg)
        if self.administrator_token and self.administrator_token.get_secret_value().startswith("mist-session:"):
            msg = "Supply an API token, not an encoded session"
            raise ValueError(msg)
        return self

    def credential(self) -> str | MistLoginCredentials | None:
        if self.use_prepared_credential:
            return None
        if self.administrator_token is not None:
            return self.administrator_token.get_secret_value()
        if self.mist_login is None:
            msg = "Mist login is missing"
            raise ValueError(msg)
        return self.mist_login


class RestoreActionResponse(BaseModel):
    """Safe review representation for one planned action."""

    logical_object_id: str
    source_version_id: str
    baseline_version_id: str | None = None
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
            baseline_version_id=None if action.baseline_version_id is None else str(action.baseline_version_id),
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
    # The versions the requester chose; empty on operations planned before it
    # was recorded, which a client must treat as not rebuildable.
    requested_version_ids: list[str] = Field(default_factory=list)
    baseline_snapshot_id: str | None = None
    prepared_until: datetime | None = None
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
    approval: ApprovalResponse | None = None
    compensation_available: bool = False

    @classmethod
    def from_document(
        cls,
        operation: RestoreOperation,
        *,
        approval: ApprovalResponse | None = None,
        compensation_available: bool | None = None,
    ) -> "RestoreOperationResponse":
        """Create an API response with no credential material."""
        if operation.id is None:
            msg = "Persisted restore operation is missing an identifier"
            raise ValueError(msg)
        return cls(
            approval=approval,
            compensation_available=(
                operation.status is RestoreStatus.COMPENSATION_AVAILABLE
                if compensation_available is None
                else compensation_available
            ),
            id=str(operation.id),
            mode=operation.mode,
            include_dependencies=operation.include_dependencies,
            requested_version_ids=[str(version_id) for version_id in operation.requested_version_ids],
            baseline_snapshot_id=None
            if operation.baseline_snapshot_id is None
            else str(operation.baseline_snapshot_id),
            prepared_until=operation.delegated_credential_expires_at if operation.baseline_snapshot_id else None,
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


class RestoreTargetResponse(BaseModel):
    """One restorable object version offered on restore step one."""

    logical_object_id: str
    version_id: str
    name: str
    object_type: str
    scope: str
    site_mist_id: str | None
    site_name: str | None
    version: int
    observed_at: datetime


class RestoreTargetTypeCountResponse(BaseModel):
    """One object-type facet count."""

    type: str
    count: int


class RestoreTargetSiteResponse(BaseModel):
    """One site facet entry."""

    id: str
    name: str


class RestoreTargetListResponse(BaseModel):
    """Restore targets with the facet vocabularies the filter rows render."""

    items: list[RestoreTargetResponse]
    total: int
    types: list[RestoreTargetTypeCountResponse]
    sites: list[RestoreTargetSiteResponse]

    @classmethod
    def from_page(cls, page: RestoreTargetPage) -> "RestoreTargetListResponse":
        """Create an API response from one searched page of targets."""
        return cls(
            items=[
                RestoreTargetResponse(
                    logical_object_id=target.logical_object_id,
                    version_id=target.version_id,
                    name=target.name,
                    object_type=target.object_type,
                    scope=target.scope,
                    site_mist_id=target.site_mist_id,
                    site_name=target.site_name,
                    version=target.version,
                    observed_at=target.observed_at,
                )
                for target in page.items
            ],
            total=page.total,
            types=[RestoreTargetTypeCountResponse(type=item.type, count=item.count) for item in page.types],
            sites=[RestoreTargetSiteResponse(id=item.id, name=item.name) for item in page.sites],
        )


class VerificationCheckResponse(BaseModel):
    """One named post-restore check and its outcome."""

    label: str
    status: VerificationStatus
    detail: str | None = None


class RestoreVerificationResponse(BaseModel):
    """Post-restore checks, snapshot, and reopened monitoring sessions."""

    verified: bool
    checks: list[VerificationCheckResponse]
    post_snapshot_id: str | None
    monitoring_session_ids: list[str]

    @classmethod
    def from_result(cls, result: RestoreVerificationResult) -> "RestoreVerificationResponse":
        """Create an API response from a persisted verification result."""
        return cls(
            verified=result.verified,
            checks=[
                VerificationCheckResponse(label=check.label, status=check.status, detail=check.detail)
                for check in result.checks
            ],
            post_snapshot_id=result.post_snapshot_id,
            monitoring_session_ids=list(result.monitoring_session_ids),
        )
