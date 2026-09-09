"""Durable Mist webhook receipts and audit change groups."""

from datetime import datetime
from enum import StrEnum
from typing import ClassVar

from beanie import Document, PydanticObjectId
from pydantic import BaseModel, Field
from pymongo import IndexModel

from mist_config_guardian_backend.models.base import TimestampedModel
from mist_config_guardian_backend.models.monitoring import ImpactSeverity


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


class ChangeSource(StrEnum):
    """How the application learned about a change."""

    WEBHOOK = "webhook"
    RECONCILE = "reconcile"
    RESTORE = "restore"
    SNAPSHOT = "snapshot"


class RecoveryState(StrEnum):
    """Whether an impacting change has recovered."""

    NOT_APPLICABLE = "not_applicable"
    MONITORING = "monitoring"
    RECOVERED = "recovered"
    UNRECOVERED = "unrecovered"
    COMPLETED = "completed"


class BaselineConfidence(StrEnum):
    """Confidence in the pre-change baseline used for impact comparison."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class ChangedObjectRef(BaseModel):
    """One configuration object touched by an administrator action."""

    logical_object_id: PydanticObjectId
    object_type: str
    object_name: str
    scope: str
    site_mist_id: str | None = None
    event: str
    before_version_id: PydanticObjectId | None = None
    after_version_id: PydanticObjectId | None = None
    before_version: int | None = None
    after_version: int | None = None
    changed_fields: list[str] = Field(default_factory=list)


class AffectedDevice(BaseModel):
    """One device that received configuration from this change."""

    device_mac: str
    device_name: str = ""
    device_type: str = ""
    site_mist_id: str = ""


class ChangeEvidence(BaseModel):
    """One deterministic statement supporting the group's assessment."""

    label: str
    severity: ImpactSeverity = ImpactSeverity.NONE


class AuditChangeGroup(TimestampedModel, Document):
    """Organization-scoped events belonging to one Mist administrator action."""

    organization_id: PydanticObjectId
    audit_id: str
    actor: str | None = None
    method: str | None = None
    message: str | None = None
    source: ChangeSource = ChangeSource.WEBHOOK
    occurred_at: datetime | None = None
    receipt_ids: list[PydanticObjectId] = Field(default_factory=list)
    affected_site_ids: list[str] = Field(default_factory=list)
    affected_object_ids: list[str] = Field(default_factory=list)

    changed_objects: list[ChangedObjectRef] = Field(default_factory=list)
    affected_devices: list[AffectedDevice] = Field(default_factory=list)
    monitoring_session_ids: list[PydanticObjectId] = Field(default_factory=list)

    impact_severity: ImpactSeverity = ImpactSeverity.NONE
    recovery_state: RecoveryState = RecoveryState.NOT_APPLICABLE
    baseline_confidence: BaselineConfidence = BaselineConfidence.NONE
    deterministic_assessment: str | None = None
    evidence: list[ChangeEvidence] = Field(default_factory=list)
    degraded_metrics: list[str] = Field(default_factory=list)
    summary: str | None = None
    projection_updated_at: datetime | None = None
    # Incremented by every projection write. A rebuild reads it, recomputes,
    # and writes only if it is unchanged, so two workers rebuilding the same
    # group cannot have the slower one's older picture land last.
    projection_revision: int = 0

    class Settings:
        name = "audit_change_groups"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel([("organization_id", 1), ("affected_site_ids", 1), ("occurred_at", -1)]),
            IndexModel(
                [("organization_id", 1), ("audit_id", 1)],
                unique=True,
                name="organization_audit_group_unique",
            ),
            IndexModel([("organization_id", 1), ("created_at", -1)]),
            IndexModel([("organization_id", 1), ("occurred_at", -1)]),
            IndexModel([("organization_id", 1), ("impact_severity", 1), ("occurred_at", -1)]),
            IndexModel([("organization_id", 1), ("actor", 1), ("occurred_at", -1)]),
            IndexModel([("organization_id", 1), ("affected_site_ids", 1)]),
        ]
