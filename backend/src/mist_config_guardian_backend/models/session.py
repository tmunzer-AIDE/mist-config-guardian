"""Revocable browser and API session persistence."""

from datetime import datetime
from typing import ClassVar

from beanie import Document, PydanticObjectId
from pydantic import Field
from pymongo import IndexModel

from mist_config_guardian_backend.models.base import TimestampedModel, utc_now


class UserSession(TimestampedModel, Document):
    """One authenticated session bound to an opaque, hashed cookie value.

    The cookie value itself is never stored. Only its SHA-256 digest is kept so
    that a database disclosure cannot be replayed as a live session.
    """

    user_id: PydanticObjectId
    token_hash: str
    csrf_hash: str
    label: str = ""
    user_agent: str | None = None
    ip_address: str | None = None
    location: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    last_seen_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    revoked_at: datetime | None = None
    mfa_verified_at: datetime | None = None

    class Settings:
        name = "user_sessions"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel([("token_hash", 1)], unique=True, name="user_session_token_unique"),
            IndexModel([("user_id", 1), ("last_seen_at", -1)]),
            IndexModel([("expires_at", 1)], expireAfterSeconds=0, name="user_session_ttl"),
        ]
