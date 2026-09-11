"""Small, explicit read models for the site Impact workspace."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Health = Literal["ok", "warning", "error", "critical", "unknown"]


class ImpactSite(BaseModel):
    id: str
    name: str


class ImpactSiteList(BaseModel):
    items: list[ImpactSite]


class TopologyDevice(BaseModel):
    id: str
    name: str
    mac: str
    kind: Literal["ap", "switch", "gateway", "unknown"] = "unknown"
    model: str = ""
    ip: str | None = None
    clients: int | None = None
    parent: str | None = None
    uplink: str | None = None
    tier: int = 2
    health: Health = "unknown"
    health_label: str = "No health evidence"
    last_seen: datetime | None = None


class TopologyLink(BaseModel):
    """Observed device adjacency; port lists do not imply a one-to-one circuit map."""

    source: str
    target: str
    source_ports: list[str] = Field(default_factory=list)
    target_ports: list[str] = Field(default_factory=list)


class SiteTopology(BaseModel):
    site_id: str
    devices: list[TopologyDevice] = Field(default_factory=list)
    links: list[TopologyLink] = Field(default_factory=list)
    collected_at: datetime | None = None
    source: Literal["mist", "stored", "historical"] = "stored"
    complete: bool = False
    warnings: list[str] = Field(default_factory=list)


class ImpactMetric(BaseModel):
    name: str
    baseline: float
    latest: float
    delta: float


class DeviceImpact(BaseModel):
    device_id: str
    device_name: str
    session_id: str
    severity: Health = "unknown"
    config_state: Literal["pending", "applied", "rolled_back", "unknown"] = "unknown"
    detected_at: datetime | None = None
    snapshot_at: datetime | None = None
    configured_at: datetime | None = None
    monitoring_started_at: datetime | None = None
    monitoring_ends_at: datetime | None = None
    completed_at: datetime | None = None
    monitoring_state: Literal["not_started", "monitoring", "completed", "stalled", "aborted", "unknown"] = "unknown"
    progress: int = Field(default=0, ge=0, le=100)
    observation_count: int = 0
    headline: str = "Waiting for comparable evidence"
    metrics: list[ImpactMetric] = Field(default_factory=list)
    collection_errors: list[str] = Field(default_factory=list)
    shared_window: bool = False


class SiteChange(BaseModel):
    id: str
    audit_id: str | None = None
    change_group_id: str | None = None
    occurred_at: datetime
    actor: str | None = None
    change_type: str = "Configuration change"
    title: str
    summary: str = ""
    impacts: list[DeviceImpact] = Field(default_factory=list)


class SiteChangeList(BaseModel):
    complete: bool = True
    warnings: list[str] = Field(default_factory=list)
    items: list[SiteChange]
    total: int
    as_of: datetime
    historical: bool = False
