"""Administrator change-group read endpoints."""

from fastapi import APIRouter

router = APIRouter(prefix="/organizations/{organization_id}/change-groups")
