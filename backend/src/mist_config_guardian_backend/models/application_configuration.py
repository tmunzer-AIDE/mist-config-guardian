"""Application-wide configuration persistence."""

from datetime import datetime
from typing import ClassVar, Literal

from beanie import Document, PydanticObjectId
from pydantic import Field
from pymongo import IndexModel

from mist_config_guardian_backend.models.base import TimestampedModel


class ApplicationConfiguration(TimestampedModel, Document):
    """Singleton configuration managed by local administrators."""

    key: Literal["global"] = "global"
    impact_ai_enabled: bool = False
    impact_ai_base_url: str = ""
    impact_ai_model: str = ""
    encrypted_impact_ai_api_key: str | None = None
    impact_ai_api_key_last_four: str | None = None
    impact_ai_max_response_tokens: int = Field(default=1500, ge=256, le=32_000)
    impact_ai_automatic_summaries: bool = False
    impact_ai_last_test_at: datetime | None = None
    impact_ai_last_test_ok: bool | None = None
    impact_ai_last_test_detail: str | None = None

    smtp_enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_security: Literal["starttls", "tls", "none"] = "starttls"
    smtp_username: str = ""
    encrypted_smtp_password: str | None = None
    smtp_password_last_four: str | None = None
    smtp_from_address: str = ""
    smtp_from_name: str = ""
    smtp_last_test_at: datetime | None = None
    smtp_last_test_ok: bool | None = None
    smtp_last_test_detail: str | None = None

    class Settings:
        name = "application_configuration"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel([("key", 1)], unique=True, name="application_configuration_key_unique"),
        ]


class AiRequestAudit(TimestampedModel, Document):
    """Append-only record of every outbound AI provider request.

    Prompts are never stored verbatim; only the bounded metadata needed to audit
    that a request happened, what it covered, and whether it succeeded.
    """

    purpose: Literal["impact_assessment", "diff_summary", "diff_followup", "connection_test"]
    organization_id: PydanticObjectId | None = None
    user_id: PydanticObjectId | None = None
    subject_id: str | None = None
    base_url: str = ""
    model: str = ""
    request_tokens: int | None = None
    response_tokens: int | None = None
    duration_ms: int | None = None
    succeeded: bool = False
    error: str | None = None
    redaction_applied: bool = True

    class Settings:
        name = "ai_request_audits"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel([("created_at", -1)]),
            IndexModel([("organization_id", 1), ("created_at", -1)]),
        ]
