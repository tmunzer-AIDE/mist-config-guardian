"""Versioned API router."""

from fastapi import APIRouter

from mist_config_guardian_backend.api.routes.account import router as account_router
from mist_config_guardian_backend.api.routes.ai import router as ai_router
from mist_config_guardian_backend.api.routes.application_configuration import (
    router as application_configuration_router,
)
from mist_config_guardian_backend.api.routes.approvals import router as approvals_router
from mist_config_guardian_backend.api.routes.auth import router as auth_router
from mist_config_guardian_backend.api.routes.change_groups import router as change_groups_router
from mist_config_guardian_backend.api.routes.diff import router as diff_router
from mist_config_guardian_backend.api.routes.health import router as health_router
from mist_config_guardian_backend.api.routes.history import router as history_router
from mist_config_guardian_backend.api.routes.monitoring import router as monitoring_router
from mist_config_guardian_backend.api.routes.notifications import router as notifications_router
from mist_config_guardian_backend.api.routes.organizations import router as organizations_router
from mist_config_guardian_backend.api.routes.overview import router as overview_router
from mist_config_guardian_backend.api.routes.point_in_time import router as point_in_time_router
from mist_config_guardian_backend.api.routes.restores import router as restores_router
from mist_config_guardian_backend.api.routes.search import router as search_router
from mist_config_guardian_backend.api.routes.snapshots import router as snapshots_router
from mist_config_guardian_backend.api.routes.system_health import router as system_health_router
from mist_config_guardian_backend.api.routes.users import router as users_router
from mist_config_guardian_backend.api.routes.webhooks import router as webhooks_router

router = APIRouter()
router.include_router(health_router, tags=["System"])
router.include_router(system_health_router, tags=["System"])
router.include_router(auth_router, tags=["Authentication"])
router.include_router(account_router, tags=["Account"])
router.include_router(users_router, tags=["User Administration"])
router.include_router(organizations_router, tags=["Organizations"])
router.include_router(overview_router, tags=["Overview"])
router.include_router(snapshots_router, tags=["Snapshots"])
router.include_router(webhooks_router, tags=["Webhooks"])
router.include_router(change_groups_router, tags=["Change Groups"])
router.include_router(history_router, tags=["Configuration History"])
router.include_router(diff_router, tags=["Configuration History"])
router.include_router(point_in_time_router, tags=["Point In Time"])
router.include_router(search_router, tags=["Search"])
router.include_router(restores_router, tags=["Restores"])
router.include_router(approvals_router, tags=["Approvals"])
router.include_router(monitoring_router, tags=["Impact Monitoring"])
router.include_router(notifications_router, tags=["Notifications"])
router.include_router(ai_router, tags=["AI Assist"])
router.include_router(application_configuration_router, tags=["Application Settings"])
