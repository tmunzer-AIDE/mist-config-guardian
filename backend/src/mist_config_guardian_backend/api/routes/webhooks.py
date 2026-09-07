"""Public Mist webhook receiver."""

import logging
from typing import Annotated

from beanie import PydanticObjectId
from celery.exceptions import CeleryError
from fastapi import APIRouter, Depends, HTTPException, Request, status
from kombu.exceptions import OperationalError

from mist_config_guardian_backend.api.dependencies import get_webhook_ingestion_service
from mist_config_guardian_backend.config import Settings, get_settings
from mist_config_guardian_backend.models.webhook import (
    WebhookProcessingStatus,
    WebhookReceipt,
)
from mist_config_guardian_backend.schemas.webhook import WebhookAcceptedResponse
from mist_config_guardian_backend.services.webhooks import (
    WebhookIngestionService,
    WebhookOrganizationNotFoundError,
    WebhookPayloadError,
    WebhookSignatureError,
)
from mist_config_guardian_backend.webhooks.signatures import SignatureVersion
from mist_config_guardian_backend.worker import celery_app

router = APIRouter(prefix="/webhooks")
logger = logging.getLogger(__name__)


@router.post("/mist/{organization_id}", status_code=status.HTTP_202_ACCEPTED)
async def receive_mist_webhook(
    organization_id: PydanticObjectId,
    request: Request,
    ingestion: Annotated[WebhookIngestionService, Depends(get_webhook_ingestion_service)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> WebhookAcceptedResponse:
    """Authenticate and durably enqueue one Mist webhook delivery."""
    body = await request.body()
    if len(body) > settings.webhook_max_body_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="Webhook body exceeds the configured limit",
        )

    x_mist_signature = request.headers.get("x-mist-signature")
    x_mist_signature_v2 = request.headers.get("x-mist-signature-v2")
    signature_version = SignatureVersion.V2 if x_mist_signature_v2 is not None else SignatureVersion.V1
    signature = x_mist_signature_v2 or x_mist_signature
    try:
        result = await ingestion.ingest(
            organization_id,
            body=body,
            signature=signature,
            signature_version=signature_version,
            source_ip=request.client.host if request.client else None,
        )
    except WebhookOrganizationNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except WebhookSignatureError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    except WebhookPayloadError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc

    queued = 0
    for receipt_id in result.receipt_ids:
        try:
            celery_app.send_task("webhooks.process", args=[str(receipt_id)])
        except (CeleryError, OperationalError):
            logger.exception("Unable to queue webhook receipt %s", receipt_id)
            await WebhookReceipt.find_one(
                WebhookReceipt.id == receipt_id,
                WebhookReceipt.status == WebhookProcessingStatus.QUEUED,
            ).update(
                {
                    "$set": {
                        "status": WebhookProcessingStatus.RECEIVED,
                        "processing_error": "Worker queue is unavailable",
                    }
                }
            )
            continue
        queued += 1

    return WebhookAcceptedResponse(
        accepted=len(result.receipt_ids),
        duplicates=result.duplicate_count,
        queued=queued,
    )
