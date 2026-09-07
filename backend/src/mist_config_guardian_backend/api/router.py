"""Versioned API router."""

from fastapi import APIRouter

from mist_config_guardian_backend.api.routes.application_configuration import (
    router as application_configuration_router,
)
from mist_config_guardian_backend.api.routes.auth import router as auth_router
from mist_config_guardian_backend.api.routes.health import router as health_router
from mist_config_guardian_backend.api.routes.history import router as history_router
from mist_config_guardian_backend.api.routes.monitoring import router as monitoring_router
from mist_config_guardian_backend.api.routes.organizations import router as organizations_router
from mist_config_guardian_backend.api.routes.restores import router as restores_router
from mist_config_guardian_backend.api.routes.snapshots import router as snapshots_router
from mist_config_guardian_backend.api.routes.webhooks import router as webhooks_router

router = APIRouter()
router.include_router(health_router, tags=["System"])
router.include_router(auth_router, tags=["Authentication"])
router.include_router(organizations_router, tags=["Organizations"])
router.include_router(snapshots_router, tags=["Snapshots"])
router.include_router(webhooks_router, tags=["Webhooks"])
router.include_router(history_router, tags=["Configuration History"])
router.include_router(restores_router, tags=["Restores"])
router.include_router(monitoring_router, tags=["Impact Monitoring"])
router.include_router(application_configuration_router, tags=["Application Settings"])
