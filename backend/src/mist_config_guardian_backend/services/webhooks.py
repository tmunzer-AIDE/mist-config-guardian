"""Durable organization-bound webhook ingestion."""

import hashlib
import json
from dataclasses import dataclass, field

from beanie import PydanticObjectId
from pymongo.errors import DuplicateKeyError

from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.organization import Organization, OrganizationStatus
from mist_config_guardian_backend.models.webhook import (
    WebhookProcessingStatus,
    WebhookReceipt,
)
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.webhooks.signatures import (
    SignatureVersion,
    verify_signature,
)


class WebhookOrganizationNotFoundError(ValueError):
    """Raised when a webhook endpoint is not active."""


class WebhookSignatureError(ValueError):
    """Raised when webhook authentication fails."""


class WebhookPayloadError(ValueError):
    """Raised when a webhook payload is malformed or misrouted."""


@dataclass
class WebhookIngestionResult:
    """Receipt identifiers created from one delivery."""

    receipt_ids: list[PydanticObjectId] = field(default_factory=list)
    duplicate_count: int = 0


class WebhookIngestionService:
    """Authenticate, split, encrypt, and durably store webhook events."""

    def __init__(self, vault: CredentialVault) -> None:
        self._vault = vault

    async def ingest(
        self,
        organization_id: PydanticObjectId,
        *,
        body: bytes,
        signature: str | None,
        signature_version: SignatureVersion,
        source_ip: str | None,
    ) -> WebhookIngestionResult:
        """Persist each authenticated event idempotently."""
        organization = await Organization.get(organization_id)
        if (
            organization is None
            or organization.status is OrganizationStatus.DISABLED
            or organization.encrypted_webhook_secret is None
        ):
            msg = "Webhook endpoint is not configured"
            raise WebhookOrganizationNotFoundError(msg)

        secret = self._vault.decrypt_for_context(
            organization.encrypted_webhook_secret,
            context=f"webhook-signature:{organization.mist_org_id}",
        )
        if signature is None or not verify_signature(
            body,
            signature,
            secret,
            version=signature_version,
        ):
            msg = "Invalid webhook signature"
            raise WebhookSignatureError(msg)

        payload = self._decode_payload(body)
        self._validate_organization(payload, organization.mist_org_id)
        topic = payload.get("topic")
        if not isinstance(topic, str) or not topic:
            msg = "Webhook topic is required"
            raise WebhookPayloadError(msg)

        raw_events = payload.get("events")
        events = raw_events if isinstance(raw_events, list) and raw_events else [payload]
        result = WebhookIngestionResult()
        for index, raw_event in enumerate(events):
            if not isinstance(raw_event, dict):
                msg = f"Webhook event {index} must be an object"
                raise WebhookPayloadError(msg)
            event = {**payload, **raw_event}
            event.pop("events", None)
            self._validate_organization(event, organization.mist_org_id)
            serialized = json.dumps(event, sort_keys=True, separators=(",", ":"))
            payload_hash = hashlib.sha256(serialized.encode()).hexdigest()
            event_id = self._event_id(event, payload_hash, index)
            receipt = WebhookReceipt(
                organization_id=organization_id,
                topic=topic,
                event_id=event_id,
                audit_id=self._string_value(event.get("audit_id")),
                payload_hash=payload_hash,
                encrypted_payload=self._vault.encrypt_for_context(
                    serialized,
                    context=f"webhook-payload:{organization.mist_org_id}",
                ),
                signature_version=signature_version,
                source_ip=source_ip,
                status=WebhookProcessingStatus.QUEUED,
            )
            try:
                await receipt.insert()
            except DuplicateKeyError:
                result.duplicate_count += 1
                continue
            if receipt.id is None:
                msg = "Persisted webhook receipt is missing an identifier"
                raise RuntimeError(msg)
            result.receipt_ids.append(receipt.id)

        # Health bookkeeping names only its own fields. Saving the whole
        # organization would carry the encrypted webhook secret this request
        # read back over a rotation completed since, restoring the credential
        # the rotation was meant to retire.
        now = utc_now()
        await Organization.get_pymongo_collection().update_one(
            {"_id": organization.id},
            {"$set": {"webhook_last_received_at": now, "webhook_last_signature_valid": True, "updated_at": now}},
        )
        organization.webhook_last_received_at = now
        organization.webhook_last_signature_valid = True
        return result

    @staticmethod
    def _decode_payload(body: bytes) -> dict[str, object]:
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            msg = "Webhook body must be valid JSON"
            raise WebhookPayloadError(msg) from exc
        if not isinstance(payload, dict):
            msg = "Webhook body must be a JSON object"
            raise WebhookPayloadError(msg)
        return payload

    @staticmethod
    def _validate_organization(payload: dict[str, object], expected_org_id: str) -> None:
        payload_org_id = payload.get("org_id")
        if payload_org_id is not None and payload_org_id != expected_org_id:
            msg = "Webhook organization does not match endpoint"
            raise WebhookPayloadError(msg)

    @staticmethod
    def _event_id(event: dict[str, object], payload_hash: str, index: int) -> str:
        for key in ("id", "event_id", "audit_id"):
            value = WebhookIngestionService._string_value(event.get(key))
            if value:
                return value
        return f"generated-{index}-{payload_hash[:24]}"

    @staticmethod
    def _string_value(value: object) -> str | None:
        return value if isinstance(value, str) and value else None
