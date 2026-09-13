"""Small, versioned contracts shared by collectors, rules and future investigators."""

from datetime import datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID

from beanie import PydanticObjectId
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from mist_config_guardian_backend.impact.change_context import ChangeContext
from mist_config_guardian_backend.impact.limits import (
    MAX_NEIGHBOR_TARGETS,
    MAX_PORT_EVENTS,
    MAX_PORT_TARGETS,
    MAX_WLAN_TARGETS,
)


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
    auth_changed: bool = False
    change_kind: Literal["removed", "disabled", "authentication", "unknown"] = "unknown"


class PortTarget(Contract):
    """One concrete changed switch port, bound to immutable audit versions."""

    handle: str = Field(pattern=r"^[0-9a-f]{64}$")
    device_handle: str = Field(pattern=r"^[0-9a-f]{64}$")
    site_id: UUID
    device_mac: str = Field(pattern=r"^[0-9a-f]{12}$")
    port_id: str = Field(pattern=r"^(ge|xe|et)-[0-9]{1,3}/[0-9]{1,3}/[0-9]{1,3}$")
    domains: tuple[Literal["port-availability.v1", "switch-poe.v1"], ...] = ()
    before_version_id: str | None = None
    after_version_id: str


class CandidateReference(Contract):
    artifact_id: PydanticObjectId
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_dispatch_id: UUID


class NeighborTarget(Contract):
    """Inventory-verification capability, never an arbitrary device query."""

    handle: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_port_handle: str = Field(pattern=r"^[0-9a-f]{64}$")
    site_id: UUID
    mist_org_id: UUID
    binding: CandidateReference


class WlanRemovalPlan(Contract):
    schema_version: Literal[1] = 1
    rule_id: Literal["wlan-removal.v1"] = "wlan-removal.v1"
    change_context: ChangeContext | None = None
    organization_id: str
    audit_id: str
    changed_at: AwareDatetime
    targets: tuple[WlanTarget, ...] = Field(default=(), max_length=MAX_WLAN_TARGETS)
    port_targets: tuple["PortTarget", ...] = Field(default=(), max_length=MAX_PORT_TARGETS)
    neighbor_targets: tuple[NeighborTarget, ...] = Field(default=(), max_length=MAX_NEIGHBOR_TARGETS)
    neighbor_statistics: bool = False
    port_history: bool = False
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
    candidate_binding: CandidateReference | None = None
    dispatch_denial: DispatchDenial | None = None

    @model_validator(mode="after")
    def denied_dispatch_has_no_result(self) -> "PortEvidence":
        if self.candidate_binding is not None and (self.state != "complete" or len(self.rows) != 1):
            msg = "Candidate binding requires a complete port observation"
            raise ValueError(msg)
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


class ManagedNeighbor(Contract):
    device_handle: str = Field(pattern=r"^[0-9a-f]{64}$")
    kind: Literal["ap"] = "ap"
    identity: Literal["verified_inventory"] = "verified_inventory"
    # Managed membership is separate from the unverified physical/PoE relationship.
    relationship: Literal["unverified"] = "unverified"


class NeighborEvidence(Contract):
    check_id: Literal["neighbor-ap-inventory.v1"] = "neighbor-ap-inventory.v1"
    target_handle: str
    window: Window
    captured_at: AwareDatetime
    state: Literal["complete", "partial", "error", "dispatch_denied", "binding_unavailable"]
    rows: tuple[ManagedNeighbor, ...] = Field(default=(), max_length=1)
    reason: str = Field(default="", max_length=500)
    http_status: int | None = Field(default=None, ge=100, le=599)
    response_bytes: int | None = Field(default=None, ge=0)
    dispatch_denial: DispatchDenial | None = None

    @model_validator(mode="after")
    def evidence_state(self) -> "NeighborEvidence":
        if (self.state == "complete") != bool(self.rows):
            msg = "Only a complete unique inventory verification may contain a managed neighbor"
            raise ValueError(msg)
        if (self.state == "dispatch_denied") != (self.dispatch_denial is not None):
            msg = "Dispatch denial must carry its reason"
            raise ValueError(msg)
        if self.state in {"dispatch_denied", "binding_unavailable"} and (
            self.http_status is not None or self.response_bytes is not None
        ):
            msg = "An unexecuted inventory check cannot contain transport results"
            raise ValueError(msg)
        return self


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


class DomainFinding(Contract):
    rule_id: Literal["port-availability.v1", "switch-poe.v1", "wlan-authentication.v1"]
    target_handle: str
    state: Literal["unknown", "possible_disruption", "recovered"]
    impact: Literal["info", "warning", "critical"]
    current_impact: Literal["info", "none", "warning", "critical"]
    confidence: Literal["low", "medium"]
    attribution: Literal["plausible", "undetermined"] = "undetermined"
    device_mac: str | None = Field(default=None, pattern=r"^[0-9a-f]{12}$")
    port_id: str | None = None
    affected_clients: int | None = Field(default=None, ge=0)
    serving_ap_macs: tuple[str, ...] = ()
    service: Literal["port_link", "port_power", "wlan_authentication"]
    occurred_at: AwareDatetime | None = None
    recovered_at: AwareDatetime | None = None
    explanation: str = Field(max_length=500)


class WlanAssessment(Contract):
    schema_version: Literal[1] = 1
    policy_version: Literal["wlan-removal.v1", "impact-domains.v1"] = "wlan-removal.v1"
    audit_id: str
    evaluated_at: datetime
    impact: Literal["info", "none", "warning", "critical"]
    confidence: Literal["low", "medium"]
    coverage: Literal["complete", "partial", "unmapped"]
    domain_findings: tuple[DomainFinding, ...] = ()
    findings: tuple[WlanFinding, ...]
    gaps: tuple[str, ...]


class PortEventRow(Contract):
    event_type: Literal["SW_PORT_UP", "SW_PORT_DOWN", "SW_POE_PORT_ENABLED", "SW_POE_PORT_DISABLED"]
    occurred_at: AwareDatetime


class PortHistoryEvidence(Contract):
    check_id: Literal["switch-port-events.v1"] = "switch-port-events.v1"
    target_handle: str
    window: Window
    captured_at: AwareDatetime
    state: Literal["complete", "partial", "error", "dispatch_denied"]
    rows: tuple[PortEventRow, ...] = Field(default=(), max_length=MAX_PORT_EVENTS)
    reason: str = Field(default="", max_length=500)
    http_status: int | None = Field(default=None, ge=100, le=599)
    response_bytes: int | None = Field(default=None, ge=0)
    dispatch_denial: DispatchDenial | None = None

    @model_validator(mode="after")
    def valid_state(self) -> "PortHistoryEvidence":
        if (self.state == "dispatch_denied") != (self.dispatch_denial is not None):
            msg = "Dispatch denial requires an explicit reason"
            raise ValueError(msg)
        if self.state in {"error", "dispatch_denied"} and self.rows:
            msg = "Failed collection cannot contain accepted events"
            raise ValueError(msg)
        if self.state == "dispatch_denied" and (self.http_status is not None or self.response_bytes is not None):
            msg = "Unexecuted checks cannot contain transport metadata"
            raise ValueError(msg)
        return self


class AuthEventRow(Contract):
    client_handle: str = Field(pattern=r"^[0-9a-f]{64}$")
    ap_mac: str | None = Field(default=None, pattern=r"^[0-9a-f]{12}$")
    occurred_at: AwareDatetime
    outcome: Literal["success", "failure"]


class AuthEvidence(Contract):
    check_id: Literal["wlan-auth-events.v1"] = "wlan-auth-events.v1"
    target_handle: str
    window: Window
    captured_at: AwareDatetime
    state: Literal["complete", "partial", "error", "dispatch_denied"]
    rows: tuple[AuthEventRow, ...] = Field(default=(), max_length=MAX_PORT_EVENTS)
    reason: str = Field(default="", max_length=500)
    http_status: int | None = Field(default=None, ge=100, le=599)
    response_bytes: int | None = Field(default=None, ge=0)
    dispatch_denial: DispatchDenial | None = None

    @model_validator(mode="after")
    def valid_state(self) -> "AuthEvidence":
        if (self.state == "dispatch_denied") != (self.dispatch_denial is not None):
            msg = "Dispatch denial requires its reason"
            raise ValueError(msg)
        if self.state in {"error", "dispatch_denied"} and self.rows:
            msg = "Failed checks cannot contain accepted authentication events"
            raise ValueError(msg)
        if self.state == "dispatch_denied" and (self.http_status is not None or self.response_bytes is not None):
            msg = "Unexecuted checks cannot contain transport metadata"
            raise ValueError(msg)
        return self


class ApAdjacency(Contract):
    device_handle: str = Field(pattern=r"^[0-9a-f]{64}$")
    connected: bool | None = Field(default=None, strict=True)
    observed_at: AwareDatetime | None = None
    relationship: Literal["corroborated_recent", "unverified"] = "unverified"
    historical_dependency: Literal["not_established"] = "not_established"
    device_failure: Literal["not_established"] = "not_established"


class ApEvidence(Contract):
    check_id: Literal["neighbor-ap-statistics.v1"] = "neighbor-ap-statistics.v1"
    target_handle: str
    window: Window
    captured_at: AwareDatetime
    state: Literal["complete", "partial", "error", "dispatch_denied", "binding_unavailable"]
    rows: tuple[ApAdjacency, ...] = Field(default=(), max_length=1)
    reason: str = Field(default="", max_length=500)
    http_status: int | None = Field(default=None, ge=100, le=599)
    response_bytes: int | None = Field(default=None, ge=0)
    dispatch_denial: DispatchDenial | None = None

    @model_validator(mode="after")
    def evidence_state(self) -> "ApEvidence":
        if (self.state == "complete") != bool(self.rows):
            msg = "Only a unique validated AP snapshot may contain a row"
            raise ValueError(msg)
        if (self.state == "dispatch_denied") != (self.dispatch_denial is not None):
            msg = "Dispatch denial must carry its reason"
            raise ValueError(msg)
        if self.state in {"dispatch_denied", "binding_unavailable"} and (
            self.http_status is not None or self.response_bytes is not None
        ):
            msg = "An unexecuted AP check cannot contain transport results"
            raise ValueError(msg)
        return self


InvestigationEvidence = (
    SessionEvidence | PortEvidence | NeighborEvidence | PortHistoryEvidence | AuthEvidence | ApEvidence
)
