"""Webhook receipt schemas."""

from pydantic import BaseModel


class WebhookAcceptedResponse(BaseModel):
    """Durable ingestion outcome."""

    accepted: int
    duplicates: int
    queued: int
