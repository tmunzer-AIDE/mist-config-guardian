"""Bounded dispatch metadata; no request headers, configuration or response prose."""

from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, Field

from mist_config_guardian_backend.impact.contracts import Contract, Window

MAX_DISPATCHES = 56


class DispatchRecord(Contract):
    id: UUID
    generation: int = Field(ge=1)
    candidate_revision: int = Field(ge=1)
    check_id: Literal["wlan-client-sessions.v1"] = "wlan-client-sessions.v1"
    target_handle: str = Field(pattern=r"^[0-9a-f]{64}$")
    site_id: UUID
    wlan_id: UUID
    window: Window
    reserved_at: AwareDatetime
    # Reservation proves authorization, not that Mist received the request.
    state: Literal["reserved", "complete", "partial", "error"] = "reserved"
    finished_at: AwareDatetime | None = None
    http_status: int | None = Field(default=None, ge=100, le=599)
    response_bytes: int | None = Field(default=None, ge=0)
    row_count: int | None = Field(default=None, ge=0, le=1000)


class DispatchLog(Contract):
    """Current root activity, explicitly separate from a published report revision."""

    source: Literal["live_investigation_root"] = "live_investigation_root"
    records: tuple[DispatchRecord, ...] = Field(default=(), max_length=MAX_DISPATCHES)
    unlogged_reservations: int = Field(default=0, ge=0)
