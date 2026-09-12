"""Small, versioned contracts shared by collectors, rules and future investigators."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Window(Contract):
    start: AwareDatetime
    end: AwareDatetime

    @model_validator(mode="after")
    def ordered(self) -> "Window":
        if self.end <= self.start:
            msg = "Evidence windows must have positive duration"
            raise ValueError(msg)
        return self


class WlanTarget(Contract):
    """A resolver-issued handle. Display names are deliberately not executable input."""

    handle: str
    site_id: UUID
    wlan_id: UUID
    logical_object_id: str
    before_version_id: str
    after_version_id: str


class WlanRemovalPlan(Contract):
    schema_version: Literal[1] = 1
    rule_id: Literal["wlan-removal.v1"] = "wlan-removal.v1"
    organization_id: str
    audit_id: str
    changed_at: AwareDatetime
    targets: tuple[WlanTarget, ...] = Field(default=(), max_length=4)
    unmapped: tuple[str, ...] = ()
    gaps: tuple[str, ...] = ()
    # These cannot be overridden by a skill or model-proposed corroborating check.
    exclusions: tuple[Literal["ap-health", "ap-availability", "site-sle"], ...] = (
        "ap-health",
        "ap-availability",
        "site-sle",
    )


class SessionRow(Contract):
    """Only identities and session boundaries; no usernames, SSIDs or tool prose."""

    client_mac: str = Field(pattern=r"^[0-9a-f]{12}$")
    ap_mac: str = Field(pattern=r"^[0-9a-f]{12}$")
    connected_at: AwareDatetime
    disconnected_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def ordered(self) -> "SessionRow":
        if self.disconnected_at is not None and self.disconnected_at < self.connected_at:
            msg = "Disconnect cannot precede connect"
            raise ValueError(msg)
        return self


class SessionEvidence(Contract):
    check_id: Literal["wlan-client-sessions.v1"] = "wlan-client-sessions.v1"
    target_handle: str
    window: Window
    captured_at: AwareDatetime
    state: Literal["complete", "partial", "error", "pending", "budget_exhausted"]
    rows: tuple[SessionRow, ...] = Field(default=(), max_length=1000)
    reason: str = ""


class WlanFinding(Contract):
    target_handle: str
    state: Literal["unknown", "no_observed_impact", "possible_disruption"]
    impact: Literal["info", "none", "warning"]
    confidence: Literal["low", "medium"]
    # Exact counts only within returned evidence, never extrapolated across APs.
    baseline_clients: int | None = None
    disconnected_clients: int | None = None
    serving_ap_macs: tuple[str, ...] = ()
    explanation: str


class WlanAssessment(Contract):
    schema_version: Literal[1] = 1
    policy_version: Literal["wlan-removal.v1"] = "wlan-removal.v1"
    audit_id: str
    evaluated_at: datetime
    impact: Literal["info", "none", "warning"]
    confidence: Literal["low", "medium"]
    coverage: Literal["complete", "partial", "unmapped"]
    findings: tuple[WlanFinding, ...]
    gaps: tuple[str, ...]
