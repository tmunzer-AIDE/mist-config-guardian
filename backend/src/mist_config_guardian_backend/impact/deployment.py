"""Normalized deployment signals, separate from outage evidence and verdicts."""

import math
import re
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, Field

from mist_config_guardian_backend.impact.contracts import Contract

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


class DeploymentSignal(Contract):
    event_type: str
    outcome: DeploymentOutcome
    device_type: Literal["ap", "switch", "gateway"]
    device_mac: str | None = Field(default=None, pattern=r"^[0-9a-f]{12}$")
    site_id: UUID | None = None
    occurred_at: AwareDatetime | None = None
    gaps: tuple[str, ...] = ()


class DeploymentObservation(Contract):
    receipt_id: str
    received_at: AwareDatetime
    correlation: Literal["audit_id", "session_candidate", "outside_window", "time_unknown"]
    signal: DeploymentSignal


class DeploymentDevice(Contract):
    device_mac: str
    site_id: UUID
    device_type: Literal["ap", "switch", "gateway"]
    outcome: DeploymentOutcome
    correlation: Literal["audit_id", "session_candidate", "ambiguous"]
    last_event_at: AwareDatetime | None = None
    receipt_ids: tuple[str, ...] = ()


class DeploymentEvidence(Contract):
    schema_version: Literal[1] = 1
    collected_at: AwareDatetime
    state: Literal["available", "partial", "unavailable"]
    coverage: Literal["observed_receipts_only"] = "observed_receipts_only"
    # Neither absent events nor a list of successful events establishes the expected fleet.
    expected_device_count: None = None
    devices: tuple[DeploymentDevice, ...] = Field(default=(), max_length=500)
    observations: tuple[DeploymentObservation, ...] = Field(default=(), max_length=2000)
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


def deployment_devices(observations: list[DeploymentObservation]) -> tuple[DeploymentDevice, ...]:
    """Deduplicate device identities before counting; occurrence time orders outcomes."""
    grouped: dict[tuple[UUID, str], list[DeploymentObservation]] = {}
    for observation in observations:
        signal = observation.signal
        if signal.site_id is not None and signal.device_mac is not None:
            grouped.setdefault((signal.site_id, signal.device_mac), []).append(observation)
    devices = []
    for (site, mac), events in sorted(grouped.items(), key=lambda item: (str(item[0][0]), item[0][1]))[:500]:
        explicit = [event for event in events if event.correlation == "audit_id"]
        ambiguous = any(event.correlation in {"outside_window", "time_unknown"} for event in events)
        latest_at = max((event.signal.occurred_at for event in explicit if event.signal.occurred_at), default=None)
        outcomes = {event.signal.outcome for event in explicit if event.signal.occurred_at == latest_at}
        # Unknown ordering or contradictory simultaneous outcomes must not choose a winner.
        outcome: DeploymentOutcome = next(iter(outcomes)) if len(outcomes) == 1 and not ambiguous else "unknown"
        devices.append(
            DeploymentDevice(
                device_mac=mac,
                site_id=site,
                device_type=events[0].signal.device_type,
                outcome=outcome,
                correlation="ambiguous" if ambiguous else "audit_id" if explicit else "session_candidate",
                last_event_at=latest_at,
                receipt_ids=tuple(sorted({event.receipt_id for event in events})),
            )
        )
    return tuple(devices)
