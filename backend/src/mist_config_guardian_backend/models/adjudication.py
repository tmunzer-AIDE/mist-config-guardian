"""Human review records, separate from agent proposals and production settings."""

from datetime import datetime
from typing import ClassVar

from beanie import Document, PydanticObjectId
from pydantic import Field
from pymongo import IndexModel

from mist_config_guardian_backend.impact.acceptance import VerdictLabel


class ImpactAdjudication(Document):
    organization_id: PydanticObjectId
    investigation_id: PydanticObjectId
    audit_id: str
    report_id: PydanticObjectId
    revision: int
    reviewer_id: PydanticObjectId
    retained_until: datetime | None = None
    reviewed_at: datetime
    label: VerdictLabel
    rationale: str = Field(max_length=1500)
    evidence_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    class Settings:
        name = "impact_adjudications"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel([("retained_until", 1)], expireAfterSeconds=0),
            IndexModel([("organization_id", 1), ("policy_hash", 1), ("audit_id", 1)], unique=True),
        ]
