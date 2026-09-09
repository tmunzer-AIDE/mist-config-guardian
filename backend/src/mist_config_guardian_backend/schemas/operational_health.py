"""Aggregate operational health API schemas."""

from datetime import datetime

from pydantic import BaseModel

from mist_config_guardian_backend.services.operational_health import (
    ComponentHealth,
    ComponentStatus,
    OperationalHealthReport,
)


class ComponentHealthResponse(BaseModel):
    """Health of one runtime component."""

    key: str
    label: str
    status: ComponentStatus
    detail: str
    latency_ms: int | None

    @classmethod
    def from_component(cls, component: ComponentHealth) -> "ComponentHealthResponse":
        """Convert one component health record into its API shape."""
        return cls(
            key=component.key,
            label=component.label,
            status=component.status,
            detail=component.detail,
            latency_ms=component.latency_ms,
        )


class OperationalHealthResponse(BaseModel):
    """Service health tab payload."""

    status: ComponentStatus
    checked_at: datetime
    components: list[ComponentHealthResponse]

    @classmethod
    def from_report(cls, report: OperationalHealthReport) -> "OperationalHealthResponse":
        """Convert an aggregate health report into its API shape."""
        return cls(
            status=report.status,
            checked_at=report.checked_at,
            components=[ComponentHealthResponse.from_component(item) for item in report.components],
        )
