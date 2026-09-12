"""Compact operator preview of an immutable shadow evaluation, without client identifiers."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from mist_config_guardian_backend.impact.agent import AgentCheckpoint, CollectAction, ModelActivity, ReportAction
from mist_config_guardian_backend.impact.contracts import DispatchDenial, Window, WlanAssessment
from mist_config_guardian_backend.impact.deployment import DeploymentEvidence
from mist_config_guardian_backend.impact.dispatch import DispatchLog
from mist_config_guardian_backend.schemas.audit_impact import AuditImpactSummary


class ShadowCheckResponse(BaseModel):
    check_id: str
    target_handle: str
    window: Window
    captured_at: datetime
    state: str
    row_count: int
    reason: str
    dispatch_denial: DispatchDenial | None = None


class ModelRequestDetails(BaseModel):
    request_id: UUID
    input_state: Literal["available", "legacy", "unavailable"] = "unavailable"
    input_json: str | None = Field(default=None, max_length=24_000)
    action_state: Literal["available", "legacy", "unavailable", "not_recorded"] = "unavailable"
    action: CollectAction | ReportAction | None = None


class ShadowTargetResponse(BaseModel):
    handle: str
    site_id: str
    wlan_id: str


class ShadowInvestigationResponse(BaseModel):
    """Diagnostic preview; never replaces the published production verdict."""

    mode: Literal["shadow"] = "shadow"
    id: str
    audit_id: str
    stop_reason: str = ""
    status: str
    revision: int
    changed_at: datetime
    expires_at: datetime
    calls_used: int
    calls_limit: int
    assessment: WlanAssessment | None = None
    shadow_impact: AuditImpactSummary | None = None
    deployment: DeploymentEvidence | None = None
    dispatch_log: DispatchLog | None = None
    agent: AgentCheckpoint | None = None
    model_activity: ModelActivity | None = None
    targets: list[ShadowTargetResponse] = Field(default_factory=list)
    checks: list[ShadowCheckResponse] = Field(default_factory=list)
