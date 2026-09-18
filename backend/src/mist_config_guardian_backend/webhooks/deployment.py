"""Normalization of device-event webhooks into the compact signal stored on a receipt.

Ingestion records this beside the encrypted payload so later readers never reinterpret a raw body. The stored
shape is unchanged from the engine this replaced: Guardian's deployment pairing reads ``event_type``,
``device_mac``, ``site_id`` and ``occurred_at`` back from it, and the remaining fields describe what the event
said and what it failed to identify.
"""

import math
import re
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

DeploymentOutcome = Literal["pending", "configured", "failed", "reverted", "unknown"]
DeploymentDeviceType = Literal["ap", "switch", "gateway"]
_DEVICE_TYPES: dict[str, DeploymentDeviceType] = {"AP": "ap", "SW": "switch", "GW": "gateway"}
_EPOCH_MILLISECONDS = 100_000_000_000
_EVENTS: dict[str, DeploymentOutcome] = {
    "AP_CONFIG_CHANGED_BY_RRM": "pending",
    "AP_CONFIG_CHANGED_BY_USER": "pending",
    "GW_CONFIG_CHANGED_BY_USER": "pending",
    "SW_CONFIG_CHANGED_BY_USER": "pending",
    "AP_CONFIGURED": "configured",
    "GW_CONFIGURED": "configured",
    "SW_CONFIGURED": "configured",
    "AP_CONFIG_FAILED": "failed",
    "GW_CONFIG_FAILED": "failed",
    "SW_CONFIG_FAILED": "failed",
    "GW_CONFIG_REVERTED": "reverted",
    "SW_CONFIG_REVERTED": "reverted",
}


class DeploymentSignal(BaseModel):
    """What one allowlisted device event said, and which identities it did not carry."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_type: str
    outcome: DeploymentOutcome
    device_type: DeploymentDeviceType
    device_mac: str | None = Field(default=None, pattern=r"^[0-9a-f]{12}$")
    site_id: UUID | None = None
    occurred_at: AwareDatetime | None = None
    gaps: tuple[str, ...] = ()


def _string(payload: dict[str, object], *keys: str) -> str:
    return next((value for key in keys if isinstance(value := payload.get(key), str) and value), "")


def _timestamp(payload: dict[str, object]) -> datetime | None:
    for key in ("timestamp", "when", "occurred_at"):
        value = payload.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
            try:
                if math.isfinite(value):
                    return datetime.fromtimestamp(value / 1000 if value > _EPOCH_MILLISECONDS else value, tz=UTC)
            except (ValueError, OverflowError, OSError):
                continue
    return None


def normalize_deployment(topic: str, payload: dict[str, object]) -> DeploymentSignal | None:
    """Allowlisted event types; names, prose and secrets never enter the snapshot."""
    event_type = _string(payload, "type", "event_type")
    if topic != "device-events" or event_type not in _EVENTS:
        return None
    mac = _string(payload, "mac", "device_mac", "ap_mac").replace(":", "").replace("-", "").lower()
    mac = mac if re.fullmatch(r"[0-9a-f]{12}", mac) else None
    try:
        site = UUID(_string(payload, "site_id"))
    except ValueError:
        site = None
    occurred = _timestamp(payload)
    gaps = tuple(
        label
        for value, label in [
            (mac, "Device identity is missing or invalid."),
            (site, "Site identity is missing or invalid."),
            (occurred, "Event occurrence time is missing or invalid."),
        ]
        if value is None
    )
    return DeploymentSignal(
        event_type=event_type,
        outcome=_EVENTS[event_type],
        device_type=_DEVICE_TYPES[event_type[:2]],
        device_mac=mac,
        site_id=site,
        occurred_at=occurred,
        gaps=gaps,
    )
