"""Persisted restore plans and execution state."""

from datetime import datetime
from enum import StrEnum
from typing import ClassVar, Literal

from beanie import Document, PydanticObjectId
from pydantic import BaseModel, Field
from pymongo import IndexModel

from mist_config_guardian_backend.models.base import TimestampedModel


class RestoreMode(StrEnum):
    """Point-in-time treatment for objects created after the target."""

    EXACT = "exact"
    NON_DESTRUCTIVE = "non_destructive"


class RestoreStatus(StrEnum):
    """Restore operation lifecycle."""

    PLANNED = "planned"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    COMPENSATION_AVAILABLE = "compensation_available"
    COMPENSATED = "compensated"


class RestoreActionType(StrEnum):
    """Mist mutation required for one object."""

    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"


class RestoreActionStatus(StrEnum):
    """Execution state for one planned action."""

    PENDING = "pending"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class RestoreAction(BaseModel):
    """One deterministic action in a restore plan."""

    logical_object_id: PydanticObjectId
    source_version_id: PydanticObjectId
    order: int = Field(ge=0)
    action: RestoreActionType
    scope: Literal["org", "site"]
    object_type: str
    object_name: str
    current_mist_id: str
    site_mist_id: str | None = None
    protected_configuration: dict[str, object]
    expected_current_hash: str | None = None
    depends_on: list[PydanticObjectId] = Field(default_factory=list)
    status: RestoreActionStatus = RestoreActionStatus.PENDING
    resulting_mist_id: str | None = None
    error: str | None = None


class RestoreOperationStateRecord(TimestampedModel, Document):
    """Plan-lifecycle state stored beside a restore operation.

    Kept out of ``RestoreOperation`` because the executor rewrites that document
    on every action it completes; holding the plan hash, safety snapshot, and
    verification result separately means a progress write can never erase them.
    """

    organization_id: PydanticObjectId
    operation_id: PydanticObjectId
    plan_hash: str
    triggered_rules: list[dict[str, object]] = Field(default_factory=list)
    safety_snapshot: list[dict[str, object]] = Field(default_factory=list)
    verification: dict[str, object] | None = None
    compensates_operation_id: PydanticObjectId | None = None
    compensation_operation_id: PydanticObjectId | None = None

    class Settings:
        name = "restore_operation_state"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel(
                [("organization_id", 1), ("operation_id", 1)],
                unique=True,
                name="restore_state_operation_unique",
            ),
            IndexModel(
                [("organization_id", 1), ("compensates_operation_id", 1)],
                name="restore_state_compensates_lookup",
            ),
        ]


class RestoreOperation(TimestampedModel, Document):
    """Reviewable and auditable restore operation."""

    organization_id: PydanticObjectId
    requested_by: PydanticObjectId
    mode: RestoreMode
    include_dependencies: bool = True
    target_at: datetime
    status: RestoreStatus = RestoreStatus.PLANNED
    actions: list[RestoreAction] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    preflight_errors: list[str] = Field(default_factory=list)
    credential_actor: str | None = None
    encrypted_delegated_credential: str | None = None
    delegated_credential_expires_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    failure_action_order: int | None = None
    task_id: str | None = None

    class Settings:
        name = "restore_operations"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel([("organization_id", 1), ("created_at", -1)]),
            IndexModel([("organization_id", 1), ("status", 1)]),
            IndexModel([("requested_by", 1), ("created_at", -1)]),
        ]
