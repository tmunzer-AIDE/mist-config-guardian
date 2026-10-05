"""Public Mist webhook receiver."""

from typing import Annotated

from beanie import PydanticObjectId
from fastapi import APIRouter, Depends, HTTPException, Request, status

from mist_config_guardian_backend.api.dependencies import get_webhook_ingestion_service
from mist_config_guardian_backend.config import Settings, get_settings
from mist_config_guardian_backend.schemas.webhook import WebhookAcceptedResponse
from mist_config_guardian_backend.services.webhooks import (
    WebhookIngestionService,
    WebhookOrganizationNotFoundError,
    WebhookPayloadError,
    WebhookSignatureError,
    queue_receipt,
)
from mist_config_guardian_backend.webhooks.signatures import SignatureVersion

router = APIRouter(prefix="/webhooks")


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
        # A receipt the queue refuses stays stored and is retried by the sweep.
        if await queue_receipt(receipt_id):
            queued += 1

    return WebhookAcceptedResponse(
        accepted=len(result.receipt_ids),
        duplicates=result.duplicate_count,
        ignored=result.ignored_count,
        queued=queued,
    )
