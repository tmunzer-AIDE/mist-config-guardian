"""Configuration snapshot and immutable version models."""

from datetime import datetime
from enum import StrEnum
from typing import Any, ClassVar, Literal

from beanie import Document, PydanticObjectId
from pydantic import BaseModel, Field
from pymongo import IndexModel

from mist_config_guardian_backend.models.base import TimestampedModel, utc_now


class SnapshotKind(StrEnum):
    """Snapshot collection reason."""

    INITIAL = "initial"
    RECONCILIATION = "reconciliation"
    MANUAL = "manual"


class SnapshotStatus(StrEnum):
    """Snapshot execution state."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class VersionEvent(StrEnum):
    """Reason an immutable object version was created."""

    INITIAL = "initial"
    CREATED = "created"
    UPDATED = "updated"
    DELETED = "deleted"
    RESTORED = "restored"


class ObjectReference(BaseModel):
    """A typed UUID reference found inside configuration."""

    target_mist_id: str
    target_type: str | None = None
    target_logical_object_id: PydanticObjectId | None = None
    field_path: str


class SnapshotError(BaseModel):
    """A scoped collection failure."""

    object_type: str
    scope_id: str | None = None
    message: str
    retryable: bool = False


class LogicalObject(TimestampedModel, Document):
    """Stable application identity across Mist UUID incarnations."""

    organization_id: PydanticObjectId
    scope: Literal["org", "site"]
    object_type: str
    source_key: str
    current_mist_id: str
    site_mist_id: str | None = None
    name: str
    is_deleted: bool = False
    current_version: int = Field(default=0, ge=0)

    class Settings:
        name = "logical_objects"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel(
                [
                    ("organization_id", 1),
                    ("scope", 1),
                    ("object_type", 1),
                    ("source_key", 1),
                ],
                unique=True,
                name="logical_object_source_unique",
            ),
            IndexModel([("organization_id", 1), ("site_mist_id", 1)]),
            IndexModel([("organization_id", 1), ("is_deleted", 1)]),
        ]


class ObjectIncarnation(Document):
    """One Mist UUID incarnation of a logical object."""

    organization_id: PydanticObjectId
    logical_object_id: PydanticObjectId
    mist_object_id: str
    site_mist_id: str | None = None
    ordinal: int = Field(ge=1)
    started_at: datetime = Field(default_factory=utc_now)
    ended_at: datetime | None = None

    class Settings:
        name = "object_incarnations"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel(
                [("logical_object_id", 1), ("ordinal", 1)],
                unique=True,
                name="logical_incarnation_ordinal_unique",
            ),
            IndexModel(
                [
                    ("organization_id", 1),
                    ("mist_object_id", 1),
                    ("site_mist_id", 1),
                ],
                name="incarnation_mist_lookup",
            ),
        ]


class ObjectVersion(Document):
    """Immutable canonical configuration version."""

    organization_id: PydanticObjectId
    logical_object_id: PydanticObjectId
    incarnation_id: PydanticObjectId
    snapshot_id: PydanticObjectId | None = None
    version: int = Field(ge=1)
    event: VersionEvent
    configuration: dict[str, Any]
    configuration_hash: str
    changed_fields: list[str] = Field(default_factory=list)
    references: list[ObjectReference] = Field(default_factory=list)
    is_deleted: bool = False
    observed_at: datetime = Field(default_factory=utc_now)
    actor: str | None = None
    audit_id: str | None = None

    class Settings:
        name = "object_versions"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel(
                [("organization_id", 1), ("logical_object_id", 1), ("version", 1)],
                unique=True,
                name="object_version_unique",
            ),
            IndexModel([("organization_id", 1), ("observed_at", -1)]),
            IndexModel([("organization_id", 1), ("audit_id", 1)]),
            IndexModel([("references.target_mist_id", 1)]),
        ]


class SnapshotManifest(TimestampedModel, Document):
    """Coverage and progress for a snapshot collection."""

    organization_id: PydanticObjectId
    kind: SnapshotKind
    status: SnapshotStatus = SnapshotStatus.PENDING
    active: bool = True
    started_at: datetime | None = None
    completed_at: datetime | None = None
    discovered_objects: int = Field(default=0, ge=0)
    created_versions: int = Field(default=0, ge=0)
    unchanged_objects: int = Field(default=0, ge=0)
    deleted_objects: int = Field(default=0, ge=0)
    errors: list[SnapshotError] = Field(default_factory=list)

    class Settings:
        name = "snapshot_manifests"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel([("organization_id", 1), ("created_at", -1)]),
            IndexModel([("organization_id", 1), ("status", 1)]),
            IndexModel(
                [("organization_id", 1), ("active", 1)],
                unique=True,
                partialFilterExpression={"active": True},
                name="one_active_snapshot_per_organization",
            ),
        ]
