"""Persistent document models."""

from beanie import Document

from mist_config_guardian_backend.models.monitoring import MonitoringSession
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.restore import RestoreOperation
from mist_config_guardian_backend.models.snapshot import (
    LogicalObject,
    ObjectIncarnation,
    ObjectVersion,
    SnapshotManifest,
)
from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.models.webhook import AuditChangeGroup, WebhookReceipt


def document_models() -> list[type[Document]]:
    """Return every Beanie document initialized by the application."""
    return [
        Organization,
        User,
        LogicalObject,
        ObjectIncarnation,
        ObjectVersion,
        SnapshotManifest,
        WebhookReceipt,
        AuditChangeGroup,
        RestoreOperation,
        MonitoringSession,
    ]


__all__ = [
    "AuditChangeGroup",
    "LogicalObject",
    "MonitoringSession",
    "ObjectIncarnation",
    "ObjectVersion",
    "Organization",
    "RestoreOperation",
    "SnapshotManifest",
    "User",
    "WebhookReceipt",
    "document_models",
]
