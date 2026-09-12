"""Bounded dispatch metadata; no request headers, configuration or response prose."""

from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from mist_config_guardian_backend.impact.contracts import Contract, Window
from mist_config_guardian_backend.impact.limits import MAX_AUDIT_CALLS

# One journal slot per authorized operational request.
MAX_DISPATCHES = MAX_AUDIT_CALLS


class DispatchRecord(Contract):
    id: UUID
    generation: int = Field(ge=1)
    candidate_revision: int = Field(ge=1)
    check_id: Literal["wlan-client-sessions.v1", "switch-port-snapshot.v1"] = "wlan-client-sessions.v1"
    target_handle: str = Field(pattern=r"^[0-9a-f]{64}$")
    site_id: UUID
    wlan_id: UUID | None = None
    device_mac: str | None = Field(default=None, pattern=r"^[0-9a-f]{12}$")
    port_id: str | None = Field(default=None, pattern=r"^(ge|xe|et)-[0-9]{1,3}/[0-9]{1,3}/[0-9]{1,3}$")
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
        if self.check_id == "wlan-client-sessions.v1":
            if self.wlan_id is None or self.device_mac is not None or self.port_id is not None:
                msg = "WLAN dispatch requires only a WLAN identity"
                raise ValueError(msg)
        elif self.wlan_id is not None or self.device_mac is None or self.port_id is None:
            msg = "Port dispatch requires only a device and port identity"
            raise ValueError(msg)
        return self


class DispatchLog(Contract):
    """Current root activity, explicitly separate from a published report revision."""

    source: Literal["live_investigation_root"] = "live_investigation_root"
    records: tuple[DispatchRecord, ...] = Field(default=(), max_length=MAX_DISPATCHES)
    unlogged_reservations: int = Field(default=0, ge=0)
