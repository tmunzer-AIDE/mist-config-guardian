"""Removal of change groups stored before audits were filtered at ingestion.

Ingestion now drops Mist audits that changed no configuration, but whatever
arrived before that keeps its change group and buries the real changes in the
timeline. This purges those groups and the receipts behind them.

The decision is deliberately conservative: a group is removed only when nothing
about it suggests a configuration change.
"""

import json
import logging
from collections.abc import Sequence

from mist_config_guardian_backend.models.webhook import AuditChangeGroup, WebhookReceipt
from mist_config_guardian_backend.security.credentials import (
    CredentialDecryptionError,
    CredentialVault,
)
from mist_config_guardian_backend.webhooks.audits import is_configuration_change

logger = logging.getLogger(__name__)


def is_operational_noise(
    group: AuditChangeGroup,
    payloads: Sequence[dict[str, object]],
) -> bool:
    """Report whether a stored change group can be removed without losing history.

    ``payloads`` are the decrypted audit events behind the group. A group that
    versioned objects is kept whatever its payloads say: that history would be
    orphaned. A group whose receipts have already been pruned is judged by the
    message it recorded, which is the only evidence left.
    """
    if group.changed_objects:
        return False
    if any(is_configuration_change(payload) for payload in payloads):
        return False
    if payloads:
        return True
    return not is_configuration_change({"message": group.message} if group.message else {})


async def audit_payloads(
    group: AuditChangeGroup,
    vault: CredentialVault,
    *,
    mist_org_id: str,
) -> list[dict[str, object]]:
    """Decrypt the audit events stored for one change group."""
    receipts = await WebhookReceipt.find(
        WebhookReceipt.organization_id == group.organization_id,
        WebhookReceipt.audit_id == group.audit_id,
        WebhookReceipt.topic == "audits",
    ).to_list()
    payloads: list[dict[str, object]] = []
    for receipt in receipts:
        try:
            serialized = vault.decrypt_for_context(
                receipt.encrypted_payload,
                context=f"webhook-payload:{mist_org_id}",
            )
        except CredentialDecryptionError:
            # An unreadable payload is not evidence of anything. Skipping it
            # leaves the group to be judged by its message, which keeps a
            # configuration change rather than guessing it away.
            logger.warning("Unable to decrypt webhook receipt %s", receipt.id)
            continue
        payload = json.loads(serialized)
        if isinstance(payload, dict):
            payloads.append(payload)
    return payloads


async def purge_group(group: AuditChangeGroup) -> int:
    """Delete one change group and the audit receipts it was built from.

    Device-event receipts are left alone: they are correlated by ``audit_id``
    but belong to the monitoring history, not to this group.
    """
    if group.id is None:
        return 0
    deleted = await WebhookReceipt.find(
        WebhookReceipt.organization_id == group.organization_id,
        WebhookReceipt.audit_id == group.audit_id,
        WebhookReceipt.topic == "audits",
    ).delete()
    await group.delete()
    return int(getattr(deleted, "deleted_count", 0) or 0)
