"""Signed Mist audit deliveries retain their administrator-action identifier."""

import hashlib
import hmac
import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.organization import Organization, OrganizationStatus
from mist_config_guardian_backend.models.webhook import WebhookProcessingStatus, WebhookReceipt
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services import webhook_processing
from mist_config_guardian_backend.services.audit_versioning import AuditVersioningService
from mist_config_guardian_backend.services.guardian import GuardianService
from mist_config_guardian_backend.services.impact_investigations import ImpactInvestigationService
from mist_config_guardian_backend.services.monitoring import MonitoringEventService
from mist_config_guardian_backend.services.webhook_processing import WebhookProcessingService
from mist_config_guardian_backend.services.webhooks import (
    WebhookIngestionResult,
    WebhookIngestionService,
)
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


async def _ingest(
    monkeypatch: pytest.MonkeyPatch,
    event: dict[str, object],
    *,
    topic: str,
) -> tuple[WebhookIngestionResult, list[WebhookReceipt]]:
    """Sign and ingest one delivery, collecting whatever receipts it stored."""
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
    body = json.dumps({"topic": topic, "org_id": "org-1", **event}).encode()
    result = await WebhookIngestionService(vault).ingest(
        organization_id,
        body=body,
        signature=hmac.new(secret.encode(), body, hashlib.sha256).hexdigest(),
        signature_version=SignatureVersion.V2,
        source_ip=None,
    )
    return result, receipts


@pytest.mark.parametrize(
    "message",
    ['Accessed Org "TM-LAB"', "Packet Capture started", "Packet Capture stopped"],
)
async def test_operational_audit_is_never_stored(monkeypatch: pytest.MonkeyPatch, message: str) -> None:
    result, receipts = await _ingest(
        monkeypatch,
        {"id": "audit-1", "site_id": "site-1", "message": message},
        topic="audits",
    )

    assert receipts == []
    assert result.receipt_ids == []
    assert result.ignored_count == 1


async def test_configuration_audit_is_still_stored(monkeypatch: pytest.MonkeyPatch) -> None:
    result, receipts = await _ingest(
        monkeypatch,
        {
            "id": "f671ee11-61f8-44bd-bf4a-90b5f4049091",
            "mxcluster_id": "72df7314-b11b-49d8-8570-c7b39ab7c0c0",
            "message": 'Update MxCluster "campus_cluster"',
        },
        topic="audits",
    )

    assert result.receipt_ids == [receipts[0].id]
    assert result.ignored_count == 0


async def test_device_event_is_stored_whatever_its_message_says(monkeypatch: pytest.MonkeyPatch) -> None:
    # Device events carry the impact evidence a change group is measured from.
    # They are correlated by audit_id, not by message, so the audit filter must
    # never reach them.
    result, receipts = await _ingest(
        monkeypatch,
        {"id": "device-event-1", "audit_id": "audit-1", "mac": "5c5b35000001", "message": "AP Disconnected"},
        topic="device-events",
    )

    assert result.receipt_ids == [receipts[0].id]
    assert result.ignored_count == 0


async def _process(monkeypatch: pytest.MonkeyPatch, *, guardian_enabled: bool) -> list[tuple[str, object]]:
    """Process one stored audit receipt and report which investigation surfaces it started."""
    vault = CredentialVault(Settings(environment="test", database_enabled=False))
    organization = Organization.model_construct(id=PydanticObjectId(), mist_org_id="org-1")
    receipt = WebhookReceipt.model_construct(
        id=PydanticObjectId(),
        organization_id=organization.id,
        topic="audits",
        event_id="audit-1",
        audit_id="audit-1",
        payload_hash="hash",
        encrypted_payload=vault.encrypt_for_context(
            json.dumps({"id": "audit-1", "timestamp": 1_800_000_000}), context="webhook-payload:org-1"
        ),
        signature_version="v2",
        status=WebhookProcessingStatus.RECEIVED,
        processing_attempts=0,
        created_at=datetime(2026, 9, 16, 12, 0, tzinfo=UTC),
    )
    started: list[tuple[str, object]] = []
    monkeypatch.setattr(WebhookReceipt, "get", AsyncMock(return_value=receipt))
    monkeypatch.setattr(WebhookReceipt, "save", AsyncMock())
    monkeypatch.setattr(Organization, "get", AsyncMock(return_value=organization))
    monkeypatch.setattr(webhook_processing, "get_settings", lambda: Settings(guardian_enabled=guardian_enabled))
    monkeypatch.setattr(WebhookProcessingService, "_add_to_change_group", AsyncMock())
    monkeypatch.setattr(WebhookProcessingService, "project", AsyncMock())
    monkeypatch.setattr(AuditVersioningService, "apply", AsyncMock())
    monkeypatch.setattr(MonitoringEventService, "handle", AsyncMock(return_value=None))

    async def guardian_ensure(_self: object, org: object, audit_id: str, **kwargs: object) -> None:
        started.append(("guardian", (org, audit_id, kwargs["changed_at"], kwargs["anchor_known"])))

    async def legacy_ensure(_self: object, *args: object, **_kwargs: object) -> None:
        started.append(("legacy", args))

    monkeypatch.setattr(GuardianService, "ensure", guardian_ensure)
    monkeypatch.setattr(ImpactInvestigationService, "ensure", legacy_ensure)

    await WebhookProcessingService(vault, projector=AsyncMock()).process(receipt.id)
    return started


async def test_an_audit_starts_no_guardian_investigation_while_the_feature_is_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert await _process(monkeypatch, guardian_enabled=False) == []


async def test_an_audit_starts_one_guardian_root_with_its_own_event_time(monkeypatch: pytest.MonkeyPatch) -> None:
    started = await _process(monkeypatch, guardian_enabled=True)

    assert [name for name, _ in started] == ["guardian"]
    _organization, audit_id, changed_at, anchor_known = started[0][1]
    assert (audit_id, anchor_known) == ("audit-1", True)
    assert changed_at == datetime.fromtimestamp(1_800_000_000, tz=UTC)
