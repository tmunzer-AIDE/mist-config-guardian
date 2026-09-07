"""Organization overview aggregate endpoint."""

from fastapi import APIRouter

router = APIRouter(prefix="/organizations/{organization_id}/overview")
