"""Global search endpoints."""

from fastapi import APIRouter

router = APIRouter(prefix="/organizations/{organization_id}/search")
