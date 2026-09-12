"""Audit roots and immutable bounded shadow evidence revisions."""

from datetime import datetime
from typing import ClassVar, Literal

from beanie import Document, PydanticObjectId
from pydantic import Field
from pymongo import IndexModel

from mist_config_guardian_backend.impact.contracts import SessionEvidence, WlanAssessment, WlanRemovalPlan
from mist_config_guardian_backend.models.base import TimestampedModel


class ImpactInvestigation(TimestampedModel, Document):
    organization_id: PydanticObjectId
    audit_id: str
    anchor_known: bool = True
    changed_at: datetime
    first_due_at: datetime
    expires_at: datetime
    next_poll_at: datetime | None
    status: Literal["collecting", "monitoring", "completed", "incomplete"] = "collecting"
    stop_reason: str = ""
    generation: int = 0
    lease_until: datetime | None = None
    calls_used: int = 0
    calls_limit: int = 56
    revision: int = 0
    report_id: PydanticObjectId | None = None

    class Settings:
        name = "impact_investigations"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel([("organization_id", 1), ("audit_id", 1)], unique=True, name="audit_investigation_unique"),
            IndexModel([("next_poll_at", 1), ("lease_until", 1)]),
        ]


class InvestigationRevision(Document):
    """Written before a fenced root publish; losing writers leave unreferenced artifacts."""

    organization_id: PydanticObjectId
    investigation_id: PydanticObjectId
    revision: int
    generated_at: datetime
    plan: WlanRemovalPlan
    assessment: WlanAssessment
    evidence: list[SessionEvidence] = Field(default_factory=list, max_length=8)

    class Settings:
        name = "investigation_revisions"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel([("organization_id", 1), ("investigation_id", 1), ("revision", -1)]),
        ]
