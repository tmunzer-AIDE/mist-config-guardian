"""Signed Mist audit deliveries retain their administrator-action identifier."""

import hashlib
import hmac
import json
from unittest.mock import AsyncMock

import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.organization import Organization, OrganizationStatus
from mist_config_guardian_backend.models.webhook import WebhookReceipt
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.webhooks import WebhookIngestionService
from mist_config_guardian_backend.webhooks.signatures import SignatureVersion


@pytest.mark.parametrize(
    ("topic", "identifiers", "expected_audit_id"),
    [
        ("audits", {"id": "audit-1"}, "audit-1"),
        ("audits", {"id": "event-1", "audit_id": "audit-1"}, "audit-1"),
        ("audits", {"id": "audit-1", "audit_id": ""}, "audit-1"),
        ("device-events", {"id": "device-event-1"}, None),
        ("device-events", {"id": "event-1", "audit_id": "audit-1"}, "audit-1"),
    ],
)
@pytest.mark.parametrize("batched", [False, True])
async def test_signed_delivery_correlates_only_audit_identifiers(
    monkeypatch: pytest.MonkeyPatch,
    topic: str,
    identifiers: dict[str, str],
    expected_audit_id: str | None,
    *,
    batched: bool,
) -> None:
    vault = CredentialVault(Settings(environment="test", database_enabled=False))
    secret = "test-webhook-secret"
    organization_id = PydanticObjectId()
    organization = Organization.model_construct(
        id=organization_id,
        mist_org_id="org-1",
        status=OrganizationStatus.VERIFIED,
        encrypted_webhook_secret=vault.encrypt_for_context(secret, context="webhook-signature:org-1"),
    )
    monkeypatch.setattr(Organization, "get", AsyncMock(return_value=organization))
    monkeypatch.setattr(Organization, "get_pymongo_collection", AsyncMock)
    monkeypatch.setattr(WebhookReceipt, "get_pymongo_collection", classmethod(lambda _cls: AsyncMock()))
    receipts: list[WebhookReceipt] = []

    async def insert(receipt: WebhookReceipt) -> WebhookReceipt:
        receipt.id = PydanticObjectId()
        receipts.append(receipt)
        return receipt

    monkeypatch.setattr(WebhookReceipt, "insert", insert)
    event = {**identifiers, "site_id": "site-1", "message": "Update Site Settings"}
    payload = {"topic": topic, "org_id": "org-1", **({"events": [event]} if batched else event)}
    body = json.dumps(payload).encode()
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    result = await WebhookIngestionService(vault).ingest(
        organization_id,
        body=body,
        signature=signature,
        signature_version=SignatureVersion.V2,
        source_ip=None,
    )

    assert result.receipt_ids == [receipts[0].id]
    assert receipts[0].audit_id == expected_audit_id
    assert receipts[0].event_id == identifiers["id"]
    stored = json.loads(vault.decrypt_for_context(receipts[0].encrypted_payload, context="webhook-payload:org-1"))
    assert stored == {"topic": topic, "org_id": "org-1", **event}
