"""Persistent document models."""

from beanie import Document

from mist_config_guardian_backend.models.application_configuration import (
    AiRequestAudit,
    ApplicationConfiguration,
)
from mist_config_guardian_backend.models.approval import RestoreApproval
from mist_config_guardian_backend.models.challenge import PendingTotpEnrollment, WebAuthnChallenge
from mist_config_guardian_backend.models.monitoring import MonitoringSession
from mist_config_guardian_backend.models.notification import Notification
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.restore import RestoreOperation, RestoreOperationStateRecord
from mist_config_guardian_backend.models.session import UserSession
from mist_config_guardian_backend.models.snapshot import (
    LogicalObject,
    ObjectIncarnation,
    ObjectVersion,
    SnapshotManifest,
)
from mist_config_guardian_backend.models.user import User, WebAuthnCredential
from mist_config_guardian_backend.models.webhook import AuditChangeGroup, WebhookReceipt


def document_models() -> list[type[Document]]:
    """Return every Beanie document initialized by the application."""
    return [
        AiRequestAudit,
        ApplicationConfiguration,
        Organization,
        User,
        UserSession,
        WebAuthnCredential,
        WebAuthnChallenge,
        PendingTotpEnrollment,
        LogicalObject,
        ObjectIncarnation,
        ObjectVersion,
        SnapshotManifest,
        WebhookReceipt,
        AuditChangeGroup,
        RestoreOperation,
        RestoreOperationStateRecord,
        RestoreApproval,
        MonitoringSession,
        Notification,
    ]


__all__ = [
    "AiRequestAudit",
    "ApplicationConfiguration",
    "AuditChangeGroup",
    "LogicalObject",
    "MonitoringSession",
    "Notification",
    "ObjectIncarnation",
    "ObjectVersion",
    "Organization",
    "PendingTotpEnrollment",
    "RestoreApproval",
    "RestoreOperation",
    "RestoreOperationStateRecord",
    "SnapshotManifest",
    "User",
    "UserSession",
    "WebAuthnChallenge",
    "WebAuthnCredential",
    "WebhookReceipt",
    "document_models",
]
