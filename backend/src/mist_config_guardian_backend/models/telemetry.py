"""Allowlisted operational evidence; configuration secrets never enter these records."""

from datetime import datetime

from pydantic import BaseModel, Field

from mist_config_guardian_backend.models.base import utc_now


class DeviceStateObservation(BaseModel):
    """A bounded device snapshot with explicit collection coverage."""

    captured_at: datetime = Field(default_factory=utc_now)
    device: dict[str, object] = Field(default_factory=dict)
    radios: list[dict[str, object]] = Field(default_factory=list)
    wlans: list[dict[str, object]] = Field(default_factory=list)
    clients: list[dict[str, object]] = Field(default_factory=list)
    ports: list[dict[str, object]] = Field(default_factory=list)
    bgp: list[dict[str, object]] = Field(default_factory=list)
    ospf: list[dict[str, object]] = Field(default_factory=list)
    tunnels: list[dict[str, object]] = Field(default_factory=list)
    vpn_peers: list[dict[str, object]] = Field(default_factory=list)
    available: list[str] = Field(default_factory=list)
    errors: dict[str, str] = Field(default_factory=dict)


class DeviceStateFinding(BaseModel):
    """Explainable before/after evidence, independent of AI assistance."""

    kind: str
    subject: str
    severity: str = "warning"
    before: str
    after: str
    detail: str
    affected_clients: int = 0


class DeviceStateComparison(BaseModel):
    """One trigger's initial state and independently scheduled follow-up."""

    triggered_at: datetime
    baseline: DeviceStateObservation
    due_at: datetime
    followup: DeviceStateObservation | None = None
    findings: list[DeviceStateFinding] = Field(default_factory=list)
    latest: DeviceStateObservation | None = None
    current_findings: list[DeviceStateFinding] | None = None
    recovered_at: datetime | None = None
