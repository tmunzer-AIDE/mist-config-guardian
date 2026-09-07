"""Health and readiness endpoints."""

from typing import Literal

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel

from mist_config_guardian_backend import __version__
from mist_config_guardian_backend.config import get_settings

router = APIRouter()


class HealthResponse(BaseModel):
    """Service health response."""

    status: Literal["ok"]
    name: str
    version: str


class ReadinessResponse(BaseModel):
    """Service readiness response."""

    status: Literal["ready"]


@router.get("/health")
async def health() -> HealthResponse:
    """Report process liveness without calling external dependencies."""
    settings = get_settings()
    return HealthResponse(status="ok", name=settings.app_name, version=__version__)


@router.get("/ready")
async def ready(request: Request) -> ReadinessResponse:
    """Report readiness after persistence initialization."""
    if not request.app.state.database.ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is not ready",
        )
    return ReadinessResponse(status="ready")
