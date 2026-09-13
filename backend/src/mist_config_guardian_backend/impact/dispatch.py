"""Bounded dispatch metadata; no request headers, configuration or response prose."""

from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from mist_config_guardian_backend.impact.contracts import Contract, DocumentationId, Window
from mist_config_guardian_backend.impact.limits import MAX_AUDIT_CALLS

# One journal slot per authorized operational or local documentation check.
MAX_DISPATCHES = MAX_AUDIT_CALLS


class DispatchRecord(Contract):
    id: UUID
    generation: int = Field(ge=1)
    candidate_revision: int = Field(ge=1)
    check_id: Literal[
        "wlan-client-sessions.v1",
        "switch-port-snapshot.v1",
        "neighbor-ap-inventory.v1",
        "switch-port-events.v1",
        "wlan-auth-events.v1",
        "neighbor-ap-statistics.v1",
        "mist-docs-attribute.v1",
    ] = "wlan-client-sessions.v1"
    target_handle: str = Field(pattern=r"^[0-9a-f]{64}$")
    site_id: UUID | None = None
    document_id: DocumentationId | None = None
    wlan_id: UUID | None = None
    device_mac: str | None = Field(default=None, pattern=r"^[0-9a-f]{12}$")
    port_id: str | None = Field(default=None, pattern=r"^(ge|xe|et)-[0-9]{1,3}/[0-9]{1,3}/[0-9]{1,3}$")
    source_dispatch_id: UUID | None = None
    window: Window
    reserved_at: AwareDatetime
    # Reservation proves authorization, not that Mist received the request.
    state: Literal["reserved", "complete", "partial", "error"] = "reserved"
    finished_at: AwareDatetime | None = None
    http_status: int | None = Field(default=None, ge=100, le=599)
    response_bytes: int | None = Field(default=None, ge=0)
    row_count: int | None = Field(default=None, ge=0, le=1000)

    @model_validator(mode="after")
    def target_kind(self) -> "DispatchRecord":
        if self.check_id == "mist-docs-attribute.v1":
            if (
                self.http_status is not None
                or self.document_id is None
                or any(
                    v is not None
                    for v in (self.site_id, self.wlan_id, self.device_mac, self.port_id, self.source_dispatch_id)
                )
            ):
                msg = "Documentation dispatch requires only a pinned document identity"
                raise ValueError(msg)
            return self
        if self.site_id is None or self.document_id is not None:
            msg = "Operational checks require a site and cannot carry a documentation identity"
            raise ValueError(msg)
        if self.check_id in {"wlan-client-sessions.v1", "wlan-auth-events.v1"}:
            if self.wlan_id is None or self.device_mac is not None or self.port_id is not None:
                msg = "WLAN dispatch requires only a WLAN identity"
                raise ValueError(msg)
        elif self.check_id in {"neighbor-ap-inventory.v1", "neighbor-ap-statistics.v1"}:
            if (
                self.wlan_id is not None
                or self.device_mac is not None
                or self.port_id is not None
                or self.source_dispatch_id is None
            ):
                msg = "Inventory dispatch uses only a private source reference, never a neighbor MAC"
                raise ValueError(msg)
        elif self.wlan_id is not None or self.device_mac is None or self.port_id is None:
            msg = "Port dispatch requires only a device and port identity"
            raise ValueError(msg)
        if (
            self.check_id not in {"neighbor-ap-inventory.v1", "neighbor-ap-statistics.v1"}
            and self.source_dispatch_id is not None
        ):
            msg = "Source references are only valid for inventory checks"
            raise ValueError(msg)
        return self


class DispatchLog(Contract):
    """Current root activity, explicitly separate from a published report revision."""

    source: Literal["live_investigation_root"] = "live_investigation_root"
    records: tuple[DispatchRecord, ...] = Field(default=(), max_length=MAX_DISPATCHES)
    unlogged_reservations: int = Field(default=0, ge=0)
