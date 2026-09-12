"""Audit roots and immutable bounded shadow evidence revisions."""

from datetime import datetime
from typing import ClassVar, Literal
from uuid import UUID

from beanie import Document, PydanticObjectId
from pydantic import Field
from pymongo import IndexModel

from mist_config_guardian_backend.impact.agent import (
    MAX_INPUT_BYTES_TOTAL,
    MAX_MODEL_CALLS,
    AgentCheckpoint,
    ModelRequestRecord,
)
from mist_config_guardian_backend.impact.contracts import InvestigationEvidence, WlanAssessment, WlanRemovalPlan
from mist_config_guardian_backend.impact.deployment import DeploymentEvidence
from mist_config_guardian_backend.impact.dispatch import MAX_DISPATCHES, DispatchRecord
from mist_config_guardian_backend.impact.limits import MAX_AUDIT_CALLS, MAX_CHECKPOINT_EVIDENCE
from mist_config_guardian_backend.impact.report import ImpactReport
from mist_config_guardian_backend.models.base import TimestampedModel

# Also excludes payloads embedded by the initial agent release. No bulk migration
# or loss of historical request context is needed to keep hot reads small.
ROOT_METADATA_PROJECTION = {"model_requests.input_json": 0, "model_requests.action": 0}


class ModelRequestArtifact(Document):
    """Insert-only normalized model input/action, separate from the root journal."""

    organization_id: PydanticObjectId
    investigation_id: PydanticObjectId
    request_id: UUID
    generation: int
    candidate_revision: int
    kind: Literal["input", "action"]
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    content_json: str = Field(max_length=24_000)
    created_at: datetime

    class Settings:
        name = "impact_model_request_artifacts"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel([("organization_id", 1), ("investigation_id", 1), ("request_id", 1)]),
        ]


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
    generation: int = 0  # Lease fencing token, not a completed-checkpoint counter.
    lease_until: datetime | None = None
    calls_used: int = 0
    calls_limit: int = MAX_AUDIT_CALLS
    revision: int = 0  # Number of successfully published checkpoints.
    report_id: PydanticObjectId | None = None
    dispatches: list[DispatchRecord] = Field(default_factory=list, max_length=MAX_DISPATCHES)
    model_calls_used: int = 0
    model_calls_limit: int = MAX_MODEL_CALLS
    model_input_bytes_reserved: int = 0
    model_input_bytes_limit: int = MAX_INPUT_BYTES_TOTAL
    model_requests: list[ModelRequestRecord] = Field(default_factory=list, max_length=MAX_MODEL_CALLS)

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
    previous_report_id: PydanticObjectId | None = None
    plan: WlanRemovalPlan
    assessment: WlanAssessment
    evidence: list[InvestigationEvidence] = Field(default_factory=list, max_length=MAX_CHECKPOINT_EVIDENCE)
    deployment: DeploymentEvidence | None = None
    agent: AgentCheckpoint | None = None
    report: ImpactReport | None = None  # Legacy revisions remain readable without fabricated history.

    class Settings:
        name = "investigation_revisions"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel([("organization_id", 1), ("investigation_id", 1), ("revision", -1)]),
        ]
