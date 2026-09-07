"""Deterministic structured configuration comparison schemas."""

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

from mist_config_guardian_backend.models.snapshot import ObjectVersion, VersionEvent

DIFF_SECRET_MASK = "********"  # noqa: S105 - redaction sentinel, not a credential


class DiffChangeKind(StrEnum):
    """Classification of one changed configuration leaf."""

    ADDED = "ADDED"
    MODIFIED = "MODIFIED"
    REMOVED = "REMOVED"


class DiffEntry(BaseModel):
    """One changed configuration leaf rendered for display.

    ``before`` and ``after`` are display strings, never raw configuration
    values: encrypted material is replaced by the redaction mask before it ever
    reaches this model.
    """

    field: str
    kind: DiffChangeKind
    before: str | None = None
    after: str | None = None
    note: str
    section: str
    notable: bool = False
    secret: bool = False
    secret_unknown: bool = False
    reordered: bool = False


class DiffCounts(BaseModel):
    """Change magnitude for a diff or one of its sections."""

    changed: int = 0
    added: int = 0
    modified: int = 0
    removed: int = 0


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
