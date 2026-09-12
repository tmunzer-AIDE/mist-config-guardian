"""Compact published-audit projection shared by all shadow presentation consumers."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

ShadowResult = Literal[
    "not_recorded", "pending", "unavailable", "insufficient_evidence", "no_observed_disconnect", "possible_disruption"
]


class AuditImpactSummary(BaseModel):
    """An audit's shadow result; never substitutes for production severity."""

    mode: Literal["shadow"] = "shadow"
    assessment_source: Literal["audit_investigation"] = "audit_investigation"
    result: ShadowResult
    investigation_id: str | None = None
    report_id: str | None = None
    revision: int | None = None
    status: str | None = None
    stop_reason: str = ""
    policy_version: str | None = None
    evaluated_at: datetime | None = None
    impact: Literal["info", "none", "warning", "critical"] | None = None
    confidence: Literal["low", "medium"] | None = None
    coverage: Literal["complete", "partial", "unmapped"] | None = None
    gap_count: int = 0
    unmapped_count: int = 0


class ShadowFeedCounts(BaseModel):
    """Mutually exclusive results for returned feed rows, not the whole time window."""

    scope: Literal["returned_feed"] = "returned_feed"
    mode: Literal["shadow"] = "shadow"
    total: int = 0
    not_recorded: int = 0
    pending: int = 0
    unavailable: int = 0
    insufficient_evidence: int = 0
    no_observed_disconnect: int = 0
    possible_disruption: int = 0
