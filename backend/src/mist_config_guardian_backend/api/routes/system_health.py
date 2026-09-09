"""Aggregate operational health endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from mist_config_guardian_backend.api.dependencies import require_viewer
from mist_config_guardian_backend.config import Settings, get_settings
from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.schemas.operational_health import OperationalHealthResponse
from mist_config_guardian_backend.services.operational_health import (
    OperationalHealthService,
    RuntimeHealthProbes,
)

router = APIRouter(prefix="/system")


def get_operational_health_service(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> OperationalHealthService:
    """Build the operational health service bound to the running MongoDB client."""
    database = getattr(request.app.state, "database", None)
    client = getattr(database, "client", None)
    return OperationalHealthService(settings, RuntimeHealthProbes(settings, client))


@router.get("/health")
async def read_operational_health(
    _viewer: Annotated[User, Depends(require_viewer)],
    service: Annotated[OperationalHealthService, Depends(get_operational_health_service)],
) -> OperationalHealthResponse:
    """Report the health of every component shown on the service health tab."""
    return OperationalHealthResponse.from_report(await service.collect())
