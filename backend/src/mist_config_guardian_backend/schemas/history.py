"""Configuration history API schemas."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from mist_config_guardian_backend.models.snapshot import (
    LogicalObject,
    ObjectVersion,
    VersionEvent,
)
from mist_config_guardian_backend.snapshots.secrets import redact_configuration


class LogicalObjectResponse(BaseModel):
    """Stable configuration object identity."""

    id: str
    scope: Literal["org", "site"]
    object_type: str
    current_mist_id: str
    site_mist_id: str | None
    name: str
    is_deleted: bool
    current_version: int
    updated_at: datetime

    @classmethod
    def from_document(cls, logical: LogicalObject) -> "LogicalObjectResponse":
        """Create an API representation."""
        if logical.id is None:
            msg = "Persisted logical object is missing an identifier"
            raise ValueError(msg)
        return cls(
            id=str(logical.id),
            scope=logical.scope,
            object_type=logical.object_type,
            current_mist_id=logical.current_mist_id,
            site_mist_id=logical.site_mist_id,
            name=logical.name,
            is_deleted=logical.is_deleted,
            current_version=logical.current_version,
            updated_at=logical.updated_at,
        )


class LogicalObjectListResponse(BaseModel):
    """Paginated logical object list."""

    items: list[LogicalObjectResponse]
    total: int


class ObjectVersionResponse(BaseModel):
    """Secret-redacted immutable object version."""

    id: str
    version: int
    event: VersionEvent
    configuration: dict[str, object]
    configuration_hash: str
    changed_fields: list[str]
    is_deleted: bool
    observed_at: datetime
    actor: str | None
    audit_id: str | None

    @classmethod
    def from_document(cls, version: ObjectVersion) -> "ObjectVersionResponse":
        """Create a redacted API representation."""
        if version.id is None:
            msg = "Persisted object version is missing an identifier"
            raise ValueError(msg)
        return cls(
            id=str(version.id),
            version=version.version,
            event=version.event,
            configuration=redact_configuration(version.configuration),
            configuration_hash=version.configuration_hash,
            changed_fields=list(version.changed_fields),
            is_deleted=version.is_deleted,
            observed_at=version.observed_at,
            actor=version.actor,
            audit_id=version.audit_id,
        )


class ObjectVersionListResponse(BaseModel):
    """Complete version timeline for one logical object."""

    items: list[ObjectVersionResponse]
    total: int
