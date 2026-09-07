"""Shared model primitives."""

from datetime import UTC, datetime

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    """Return an aware UTC timestamp."""
    return datetime.now(UTC)


class TimestampedModel(BaseModel):
    """Creation and update timestamps."""

    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    def touch(self) -> None:
        """Update the modification timestamp."""
        self.updated_at = utc_now()
