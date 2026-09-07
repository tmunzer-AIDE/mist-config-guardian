"""Snapshot API schemas."""

from datetime import datetime

from pydantic import BaseModel

from mist_config_guardian_backend.models.snapshot import (
    SnapshotError,
    SnapshotKind,
    SnapshotManifest,
    SnapshotStatus,
)


class SnapshotTriggerRequest(BaseModel):
    """Request a background snapshot."""

    kind: SnapshotKind = SnapshotKind.MANUAL


class SnapshotTaskResponse(BaseModel):
    """Accepted background task metadata."""

    task_id: str


class SnapshotManifestResponse(BaseModel):
    """Snapshot progress and coverage."""

    id: str
    kind: SnapshotKind
    status: SnapshotStatus
    started_at: datetime | None
    completed_at: datetime | None
    discovered_objects: int
    created_versions: int
    unchanged_objects: int
    deleted_objects: int
    errors: list[SnapshotError]
    created_at: datetime

    @classmethod
    def from_document(cls, manifest: SnapshotManifest) -> "SnapshotManifestResponse":
        """Create an API representation from a persisted manifest."""
        if manifest.id is None:
            msg = "Persisted snapshot manifest is missing an identifier"
            raise ValueError(msg)
        return cls(
            id=str(manifest.id),
            kind=manifest.kind,
            status=manifest.status,
            started_at=manifest.started_at,
            completed_at=manifest.completed_at,
            discovered_objects=manifest.discovered_objects,
            created_versions=manifest.created_versions,
            unchanged_objects=manifest.unchanged_objects,
            deleted_objects=manifest.deleted_objects,
            errors=list(manifest.errors),
            created_at=manifest.created_at,
        )


class SnapshotManifestListResponse(BaseModel):
    """Paginated snapshot history."""

    items: list[SnapshotManifestResponse]
    total: int
