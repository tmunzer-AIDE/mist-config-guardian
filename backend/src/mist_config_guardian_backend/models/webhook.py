"""Durable Mist webhook receipts and audit change groups."""

from datetime import datetime
from enum import StrEnum
from typing import ClassVar

from beanie import Document, PydanticObjectId
from pydantic import Field
from pymongo import IndexModel

from mist_config_guardian_backend.models.base import TimestampedModel


class WebhookProcessingStatus(StrEnum):
    """Asynchronous webhook processing state."""

    RECEIVED = "received"
    QUEUED = "queued"
    PROCESSING = "processing"
    PROCESSED = "processed"
    FAILED = "failed"


class WebhookReceipt(TimestampedModel, Document):
    """Authenticated immutable webhook event receipt."""

    organization_id: PydanticObjectId
    topic: str
    event_id: str
    audit_id: str | None = None
    payload_hash: str
    encrypted_payload: str
    signature_version: str
    signature_valid: bool = True
    source_ip: str | None = None
    status: WebhookProcessingStatus = WebhookProcessingStatus.RECEIVED
    processing_attempts: int = Field(default=0, ge=0)
    processing_error: str | None = None
    processed_at: datetime | None = None

    class Settings:
        name = "webhook_receipts"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel(
                [
                    ("organization_id", 1),
                    ("topic", 1),
                    ("event_id", 1),
                    ("payload_hash", 1),
                ],
                unique=True,
                name="webhook_receipt_deduplication",
            ),
            IndexModel([("organization_id", 1), ("created_at", -1)]),
            IndexModel([("organization_id", 1), ("status", 1)]),
            IndexModel([("organization_id", 1), ("audit_id", 1)]),
        ]


class AuditChangeGroup(TimestampedModel, Document):
    """Organization-scoped events belonging to one Mist administrator action."""

    organization_id: PydanticObjectId
    audit_id: str
    actor: str | None = None
    method: str | None = None
    message: str | None = None
    receipt_ids: list[PydanticObjectId] = Field(default_factory=list)
    affected_site_ids: list[str] = Field(default_factory=list)
    affected_object_ids: list[str] = Field(default_factory=list)

    class Settings:
        name = "audit_change_groups"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel(
                [("organization_id", 1), ("audit_id", 1)],
                unique=True,
                name="organization_audit_group_unique",
            ),
            IndexModel([("organization_id", 1), ("created_at", -1)]),
        ]
