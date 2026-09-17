"""Deterministic structured configuration comparison schemas."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from mist_config_guardian_backend.models.snapshot import ObjectVersion, VersionEvent
from mist_config_guardian_backend.snapshots.diffing import DIFF_SECRET_MASK, DiffChangeKind, DiffCounts, DiffEntry

__all__ = [
    "DIFF_SECRET_MASK",
    "ConfigurationDiff",
    "DiffChangeKind",
    "DiffCounts",
    "DiffEntry",
    "DiffSection",
    "DiffVersionRef",
    "RawConfigurationDiff",
]


class DiffSection(BaseModel):
    """A group of changes sharing the first configuration path segment."""

    key: str
    name: str
    path: str
    counts: DiffCounts
    detail: str
    notable: int = 0
    entries: list[DiffEntry] = Field(default_factory=list)
    entries_included: bool = True


class DiffVersionRef(BaseModel):
    """Identity of one side of a comparison."""

    id: str
    logical_object_id: str
    version: int
    event: VersionEvent
    observed_at: datetime
    actor: str | None = None
    is_deleted: bool = False

    @classmethod
    def from_document(cls, version: ObjectVersion) -> "DiffVersionRef":
        """Create an API representation of a stored version."""
        if version.id is None:
            msg = "Persisted object version is missing an identifier"
            raise ValueError(msg)
        return cls(
            id=str(version.id),
            logical_object_id=str(version.logical_object_id),
            version=version.version,
            event=version.event,
            observed_at=version.observed_at,
            actor=version.actor,
            is_deleted=version.is_deleted,
        )


class ConfigurationDiff(BaseModel):
    """Deterministic comparison of two redacted configuration documents."""

    mode: Literal["chips", "sections"] = "chips"
    summary: str = ""
    counts: DiffCounts = Field(default_factory=DiffCounts)
    entries: list[DiffEntry] = Field(default_factory=list)
    notable: list[DiffEntry] = Field(default_factory=list)
    sections: list[DiffSection] = Field(default_factory=list)
    entries_included: bool = True
    truncated: bool = False
    secret_fields: int = 0
    from_version: DiffVersionRef | None = None
    to_version: DiffVersionRef | None = None


class RawConfigurationDiff(BaseModel):
    """Side-by-side redacted JSON for the raw comparison view."""

    before: dict[str, object]
    after: dict[str, object]
    line_count: int
    from_version: DiffVersionRef | None = None
    to_version: DiffVersionRef | None = None
