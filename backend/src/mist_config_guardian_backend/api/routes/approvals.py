"""Two-person restore approval endpoints."""

from fastapi import APIRouter

router = APIRouter(prefix="/organizations/{organization_id}/approvals")
