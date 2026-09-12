"""Small, versioned contracts shared by collectors, rules and future investigators."""

from datetime import datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from mist_config_guardian_backend.impact.change_context import ChangeContext
from mist_config_guardian_backend.impact.limits import MAX_PORT_TARGETS, MAX_WLAN_TARGETS


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
    change_kind: Literal["removed", "disabled", "unknown"] = "unknown"


class PortTarget(Contract):
    """One concrete changed switch port, bound to immutable audit versions."""

    handle: str = Field(pattern=r"^[0-9a-f]{64}$")
    device_handle: str = Field(pattern=r"^[0-9a-f]{64}$")
    site_id: UUID
    device_mac: str = Field(pattern=r"^[0-9a-f]{12}$")
    port_id: str = Field(pattern=r"^(ge|xe|et)-[0-9]{1,3}/[0-9]{1,3}/[0-9]{1,3}$")
    before_version_id: str | None = None
    after_version_id: str


class WlanRemovalPlan(Contract):
    schema_version: Literal[1] = 1
    rule_id: Literal["wlan-removal.v1"] = "wlan-removal.v1"
    change_context: ChangeContext | None = None
    organization_id: str
    audit_id: str
    changed_at: AwareDatetime
    targets: tuple[WlanTarget, ...] = Field(default=(), max_length=MAX_WLAN_TARGETS)
    port_targets: tuple["PortTarget", ...] = Field(default=(), max_length=MAX_PORT_TARGETS)
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


class DispatchDenial(StrEnum):
    CREDENTIALS_UNAVAILABLE = "credentials_unavailable"
    CREDENTIALS_CHANGED = "credentials_changed"
    WINDOW_EXPIRED = "window_expired"
    LEASE_LOST = "lease_lost"
    BUDGET_EXHAUSTED = "budget_exhausted"
    JOURNAL_FULL = "journal_full"
    RESERVATION_REJECTED = "reservation_rejected"

    @property
    def explanation(self) -> str:
        return {
            self.CREDENTIALS_UNAVAILABLE: "Dispatch denied: organization access is unavailable or no longer verified.",
            self.CREDENTIALS_CHANGED: "Dispatch denied: the service credential changed; review organization access.",
            self.WINDOW_EXPIRED: "Dispatch denied: the investigation collection window expired.",
            self.LEASE_LOST: "Dispatch denied: this worker no longer holds an active investigation lease.",
            self.BUDGET_EXHAUSTED: "Dispatch denied: the investigation request budget is exhausted.",
            self.JOURNAL_FULL: "Dispatch denied: the investigation request journal is full.",
            self.RESERVATION_REJECTED: (
                "Dispatch denied: reservation was rejected; the reason could not be established."
            ),
        }[self]


class SessionEvidence(Contract):
    check_id: Literal["wlan-client-sessions.v1"] = "wlan-client-sessions.v1"
    target_handle: str
    window: Window
    captured_at: AwareDatetime
    # budget_exhausted is retained for persisted evidence from the earlier collector.
    state: Literal["complete", "partial", "error", "pending", "budget_exhausted", "dispatch_denied"]
    rows: tuple[SessionRow, ...] = Field(default=(), max_length=1000)
    reason: str = ""
    http_status: int | None = Field(default=None, ge=100, le=599)
    response_bytes: int | None = Field(default=None, ge=0)
    dispatch_denial: DispatchDenial | None = None

    @model_validator(mode="after")
    def denied_dispatch_has_no_result(self) -> "SessionEvidence":
        if (self.state == "dispatch_denied") != (self.dispatch_denial is not None):
            msg = "Dispatch denial requires a reason and dispatch_denied state"
            raise ValueError(msg)
        if self.dispatch_denial is not None and (
            self.rows or self.http_status is not None or self.response_bytes is not None
        ):
            msg = "A denied dispatch cannot contain a response"
            raise ValueError(msg)
        return self


class PortRow(Contract):
    """Most recent reported port state, not a transition or a managed peer identity."""

    up: bool | None = Field(default=None, strict=True)
    poe_on: bool | None = Field(default=None, strict=True)
    power_draw: float | None = Field(default=None, ge=0, allow_inf_nan=False, strict=True)
    observed_at: AwareDatetime | None = None
    neighbor_handle: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    neighbor_identity: Literal["unverified"] = "unverified"


class PortResponseError(StrEnum):
    SCOPE_MISMATCH = "scope_mismatch"
    INVALID_TIMESTAMP = "invalid_timestamp"
    INVALID_RESPONSE = "invalid_response"

    @property
    def explanation(self) -> str:
        return {
            self.SCOPE_MISMATCH: "Returned port does not match the resolved device, site and port; response rejected.",
            self.INVALID_TIMESTAMP: "Port observation timestamp is invalid or in the future; response rejected.",
            self.INVALID_RESPONSE: "Port response failed validation; no returned evidence was accepted.",
        }[self]


class PortEvidence(Contract):
    check_id: Literal["switch-port-snapshot.v1"] = "switch-port-snapshot.v1"
    target_handle: str
    # Requested investigation interval only: this endpoint cannot query history.
    window: Window
    captured_at: AwareDatetime
    state: Literal["complete", "partial", "error", "dispatch_denied"]
    rows: tuple[PortRow, ...] = Field(default=(), max_length=1)
    reason: str = Field(default="", max_length=500)
    http_status: int | None = Field(default=None, ge=100, le=599)
    response_bytes: int | None = Field(default=None, ge=0)
    response_error: PortResponseError | None = None
    dispatch_denial: DispatchDenial | None = None

    @model_validator(mode="after")
    def denied_dispatch_has_no_result(self) -> "PortEvidence":
        if self.response_error is not None and (self.state != "error" or self.rows):
            msg = "A rejected response requires error state and no accepted rows"
            raise ValueError(msg)
        if (self.state == "dispatch_denied") != (self.dispatch_denial is not None):
            msg = "Dispatch denial requires a reason and dispatch_denied state"
            raise ValueError(msg)
        if self.dispatch_denial is not None and (
            self.rows or self.http_status is not None or self.response_bytes is not None
        ):
            msg = "A denied dispatch cannot contain a response"
            raise ValueError(msg)
        return self


InvestigationEvidence = SessionEvidence | PortEvidence


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
