"""The Overview page's purpose-built read model.

The Overview is one screen assembled from six collections. It is deliberately
not six page-level services stitched together in the route: the counts come from
a single faceted aggregation, the feed reuses the change-group read model's
batched lookups, and ``counts_only`` stops after the three counting queries the
shell's navigation badges need.

Restore approvals and restore operations are owned by another workstream, so
every field read from them is optional: a half-written or empty collection has
to render as an empty section, never as a failed Overview.
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol

from beanie import PydanticObjectId

from mist_config_guardian_backend.models.approval import ApprovalStatus, RestoreApproval
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.monitoring import ImpactSeverity
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.restore import RestoreOperation, RestoreStatus
from mist_config_guardian_backend.models.snapshot import SnapshotKind, SnapshotManifest, SnapshotStatus
from mist_config_guardian_backend.models.webhook import AuditChangeGroup, RecoveryState
from mist_config_guardian_backend.schemas.overview import (
    FailedRestoreResponse,
    OrganizationOverviewResponse,
    OverviewCountsResponse,
    PendingApprovalResponse,
    SafetyNetItemResponse,
)
from mist_config_guardian_backend.services.change_groups import (
    ChangeGroupService,
    as_utc,
    format_duration,
    resolve_window,
)

FEED_LIMIT = 50
APPROVAL_LIMIT = 10
FAILED_RESTORE_LIMIT = 10

# A safety-net row turns amber once the thing it watches is this far behind the
# cadence it promised. The webhook gap is the interval the design calls out.
_OVERDUE_FACTOR = 2
_WEBHOOK_GAP = timedelta(minutes=15)
_FAILED_STATUSES = (RestoreStatus.FAILED, RestoreStatus.COMPENSATION_AVAILABLE)
_RESTORE_MODE_TITLES: Mapping[str, str] = {
    "exact": "Exact point-in-time restore",
    "non_destructive": "Non-destructive restore",
}
_CRON_STEP = re.compile(r"^\*/(\d+)$")
_MINUTES_PER_HOUR = 60
_MINUTES_PER_DAY = 24 * 60


@dataclass(frozen=True, slots=True)
class ChangeGroupCounts:
    """The four change-group counts the Overview badges need."""

    change_groups: int = 0
    impacting: int = 0
    mine: int = 0
    unrecovered: int = 0


@dataclass(frozen=True, slots=True)
class SafetyNetInput:
    """Everything the safety-net card is derived from."""

    organization: Organization
    latest_snapshot: SnapshotManifest | None
    latest_reconciliation: SnapshotManifest | None
    now: datetime = field(default_factory=utc_now)


class OverviewReader(Protocol):
    """The small set of aggregate queries the Overview is built from."""

    async def change_group_counts(
        self,
        organization_id: PydanticObjectId,
        *,
        start: datetime,
        end: datetime,
        viewer_email: str,
    ) -> ChangeGroupCounts:
        """Return the four windowed change-group counts in one round trip."""

    async def pending_approval_count(self, organization_id: PydanticObjectId) -> int:
        """Count restore plans awaiting a decision."""

    async def failed_restore_count(self, organization_id: PydanticObjectId) -> int:
        """Count restores that stopped part way."""

    async def recent_groups(
        self,
        organization_id: PydanticObjectId,
        *,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> list[AuditChangeGroup]:
        """Return the newest change groups inside the window."""

    async def pending_approvals(
        self,
        organization_id: PydanticObjectId,
        *,
        limit: int,
    ) -> list[RestoreApproval]:
        """Return restore approvals awaiting a decision, oldest request first."""

    async def failed_restores(
        self,
        organization_id: PydanticObjectId,
        *,
        limit: int,
    ) -> list[RestoreOperation]:
        """Return restores that failed or are awaiting compensation."""

    async def latest_snapshot(self, organization_id: PydanticObjectId) -> SnapshotManifest | None:
        """Return the newest completed snapshot of any kind."""

    async def latest_reconciliation(self, organization_id: PydanticObjectId) -> SnapshotManifest | None:
        """Return the newest completed scheduled reconciliation."""


class BeanieOverviewReader:
    """MongoDB-backed Overview aggregates."""

    async def change_group_counts(
        self,
        organization_id: PydanticObjectId,
        *,
        start: datetime,
        end: datetime,
        viewer_email: str,
    ) -> ChangeGroupCounts:
        """Return the four windowed change-group counts in one round trip."""
        pipeline: list[dict[str, object]] = [
            {
                "$match": {
                    "organization_id": organization_id,
                    "occurred_at": {"$gte": start, "$lte": end},
                }
            },
            {
                "$facet": {
                    "change_groups": [{"$count": "value"}],
                    "impacting": [
                        {
                            "$match": {
                                "impact_severity": {
                                    "$in": [ImpactSeverity.WARNING.value, ImpactSeverity.CRITICAL.value]
                                }
                            }
                        },
                        {"$count": "value"},
                    ],
                    "mine": [
                        {"$match": {"actor": {"$regex": actor_pattern(viewer_email), "$options": "i"}}},
                        {"$count": "value"},
                    ],
                    "unrecovered": [
                        {"$match": {"recovery_state": RecoveryState.UNRECOVERED.value}},
                        {"$count": "value"},
                    ],
                }
            },
        ]
        rows = await AuditChangeGroup.aggregate(pipeline).to_list()
        return _counts_from_facet(rows[0] if rows else {})

    async def pending_approval_count(self, organization_id: PydanticObjectId) -> int:
        """Count restore plans awaiting a decision."""
        return await RestoreApproval.find(
            {"organization_id": organization_id, "status": ApprovalStatus.PENDING.value}
        ).count()

    async def failed_restore_count(self, organization_id: PydanticObjectId) -> int:
        """Count restores that stopped part way."""
        return await RestoreOperation.find(
            {
                "organization_id": organization_id,
                "status": {"$in": [item.value for item in _FAILED_STATUSES]},
            }
        ).count()

    async def recent_groups(
        self,
        organization_id: PydanticObjectId,
        *,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> list[AuditChangeGroup]:
        """Return the newest change groups inside the window."""
        return (
            await AuditChangeGroup.find(
                {
                    "organization_id": organization_id,
                    "occurred_at": {"$gte": start, "$lte": end},
                }
            )
            .sort("-occurred_at")
            .limit(limit)
            .to_list()
        )

    async def pending_approvals(
        self,
        organization_id: PydanticObjectId,
        *,
        limit: int,
    ) -> list[RestoreApproval]:
        """Return restore approvals awaiting a decision, oldest request first."""
        return (
            await RestoreApproval.find({"organization_id": organization_id, "status": ApprovalStatus.PENDING.value})
            .sort("created_at")
            .limit(limit)
            .to_list()
        )

    async def failed_restores(
        self,
        organization_id: PydanticObjectId,
        *,
        limit: int,
    ) -> list[RestoreOperation]:
        """Return restores that failed or are awaiting compensation."""
        return (
            await RestoreOperation.find(
                {
                    "organization_id": organization_id,
                    "status": {"$in": [item.value for item in _FAILED_STATUSES]},
                }
            )
            .sort("-updated_at")
            .limit(limit)
            .to_list()
        )

    async def latest_snapshot(self, organization_id: PydanticObjectId) -> SnapshotManifest | None:
        """Return the newest completed snapshot of any kind."""
        return (
            await SnapshotManifest.find(
                {
                    "organization_id": organization_id,
                    "status": {"$in": [SnapshotStatus.COMPLETED.value, SnapshotStatus.PARTIAL.value]},
                }
            )
            .sort("-created_at")
            .first_or_none()
        )

    async def latest_reconciliation(self, organization_id: PydanticObjectId) -> SnapshotManifest | None:
        """Return the newest completed scheduled reconciliation."""
        return (
            await SnapshotManifest.find(
                {
                    "organization_id": organization_id,
                    "kind": SnapshotKind.RECONCILIATION.value,
                    "status": {"$in": [SnapshotStatus.COMPLETED.value, SnapshotStatus.PARTIAL.value]},
                }
            )
            .sort("-created_at")
            .first_or_none()
        )


def actor_pattern(email: str) -> str:
    """Build the anchored pattern matching a user's address or its local part."""
    address = email.strip().lower()
    local = address.partition("@")[0]
    return f"^({re.escape(address)}|{re.escape(local)})$"


def _counts_from_facet(row: Mapping[str, object]) -> ChangeGroupCounts:
    def value(key: str) -> int:
        bucket = row.get(key)
        if isinstance(bucket, list) and bucket:
            first = bucket[0]
            if isinstance(first, Mapping):
                count = first.get("value")
                if isinstance(count, int):
                    return count
        return 0

    return ChangeGroupCounts(
        change_groups=value("change_groups"),
        impacting=value("impacting"),
        mine=value("mine"),
        unrecovered=value("unrecovered"),
    )


def cron_cadence_minutes(expression: str) -> int | None:
    """Read the cadence of the reconciliation cron expressions the app writes."""
    fields = expression.split()
    expected_fields = 5
    if len(fields) != expected_fields:
        return None
    minute, hour = fields[0], fields[1]
    step = _CRON_STEP.match(minute)
    if step:
        return int(step.group(1))
    step = _CRON_STEP.match(hour)
    if step:
        return int(step.group(1)) * _MINUTES_PER_HOUR
    if minute == "*":
        return 1
    if hour == "*":
        return _MINUTES_PER_HOUR
    return _MINUTES_PER_DAY


def format_cadence(minutes: int) -> str:
    """Render a cadence the way the safety-net card prints it (``12H``)."""
    if minutes % _MINUTES_PER_DAY == 0:
        return f"{minutes // _MINUTES_PER_DAY}D"
    if minutes % _MINUTES_PER_HOUR == 0:
        return f"{minutes // _MINUTES_PER_HOUR}H"
    return f"{minutes}M"


def format_clock(value: datetime) -> str:
    """Render an instant as the terse UTC clock the design uses (``14:18Z``)."""
    return as_utc(value).strftime("%H:%MZ")


def format_day(value: datetime) -> str:
    """Render an instant as the terse UTC day the design uses (``06 SEP``)."""
    return as_utc(value).strftime("%d %b").upper()


def build_safety_net(source: SafetyNetInput) -> list[SafetyNetItemResponse]:
    """Build the safety-net rows from snapshot, webhook, and credential state."""
    organization = source.organization
    now = as_utc(source.now)
    items = [_backup_row(source.latest_snapshot, now)]
    items.append(_webhook_row(organization, now))
    if source.latest_snapshot is not None:
        items.append(_reconciliation_row(organization, source.latest_reconciliation, now))
    items.append(_credential_row(organization))
    return items


def _backup_row(snapshot: SnapshotManifest | None, now: datetime) -> SafetyNetItemResponse:
    captured = _snapshot_instant(snapshot)
    if captured is None:
        return SafetyNetItemResponse(
            key="backup",
            label="No snapshot recorded",
            status="warn",
            detail="—",
        )
    behind = now - captured
    return SafetyNetItemResponse(
        key="backup",
        label=f"Backup {format_duration(behind)} behind",
        status="ok" if behind <= timedelta(days=1) else "warn",
        detail=format_clock(captured),
    )


def _webhook_row(organization: Organization, now: datetime) -> SafetyNetItemResponse:
    if not organization.encrypted_webhook_secret:
        return SafetyNetItemResponse(
            key="webhook",
            label="Webhook not configured",
            status="warn",
            detail="—",
        )
    received = organization.webhook_last_received_at
    if received is None:
        return SafetyNetItemResponse(
            key="webhook",
            label="No webhook events received",
            status="warn",
            detail="—",
        )
    gap = now - as_utc(received)
    if gap >= _WEBHOOK_GAP:
        return SafetyNetItemResponse(
            key="webhook",
            label=f"Webhook gap {format_duration(gap)}",
            status="warn",
            detail=format_clock(received),
        )
    return SafetyNetItemResponse(
        key="webhook",
        label="Webhook delivery current",
        status="ok",
        detail=format_clock(received),
    )


def _reconciliation_row(
    organization: Organization,
    reconciliation: SnapshotManifest | None,
    now: datetime,
) -> SafetyNetItemResponse:
    minutes = cron_cadence_minutes(organization.reconciliation_cron)
    cadence = format_cadence(minutes) if minutes is not None else "—"
    captured = _snapshot_instant(reconciliation)
    overdue = (
        minutes is not None and captured is not None and now - captured > timedelta(minutes=minutes * _OVERDUE_FACTOR)
    )
    return SafetyNetItemResponse(
        key="reconciliation",
        label="Reconciliation overdue" if overdue else "Reconciliation on schedule",
        status="warn" if overdue else "ok",
        detail=cadence,
    )


def _credential_row(organization: Organization) -> SafetyNetItemResponse:
    if organization.credential_error:
        return SafetyNetItemResponse(
            key="credential",
            label="Token not verified",
            status="crit",
            detail="—",
        )
    verified = organization.credential_verified_at
    if verified is None:
        return SafetyNetItemResponse(
            key="credential",
            label="Token not verified",
            status="warn",
            detail="—",
        )
    return SafetyNetItemResponse(
        key="credential",
        label="Service token verified",
        status="ok",
        detail=format_day(verified),
    )


def _snapshot_instant(snapshot: SnapshotManifest | None) -> datetime | None:
    if snapshot is None:
        return None
    captured = snapshot.completed_at or snapshot.started_at or snapshot.created_at
    return as_utc(captured) if captured is not None else None


def build_pending_approvals(approvals: Sequence[RestoreApproval]) -> list[PendingApprovalResponse]:
    """Render pending restore approvals, tolerating a partially written record."""
    rendered = []
    for approval in approvals:
        identifier = getattr(approval, "id", None)
        operation_id = getattr(approval, "restore_operation_id", None)
        if identifier is None or operation_id is None:
            continue
        objects = getattr(approval, "object_count", 0) or 0
        deletes = getattr(approval, "delete_count", 0) or 0
        detail = f"{objects} object{'' if objects == 1 else 's'}"
        if deletes:
            detail = f"{detail} · {deletes} deletion{'' if deletes == 1 else 's'}"
        rendered.append(
            PendingApprovalResponse(
                id=str(identifier),
                restore_operation_id=str(operation_id),
                title=getattr(approval, "summary", "") or "Restore approval",
                detail=detail,
                requested_by_email=getattr(approval, "requested_by_email", "") or "",
                requested_at=as_utc(getattr(approval, "created_at", None) or utc_now()),
            )
        )
    return rendered


def build_failed_restores(operations: Sequence[RestoreOperation]) -> list[FailedRestoreResponse]:
    """Render failed restores, tolerating a partially written operation."""
    rendered = []
    for operation in operations:
        identifier = getattr(operation, "id", None)
        if identifier is None:
            continue
        mode = getattr(operation, "mode", None)
        actions = getattr(operation, "actions", None) or []
        order = getattr(operation, "failure_action_order", None)
        detail = (
            f"Failed at action {order + 1} of {len(actions)}"
            if order is not None and actions
            else f"{len(actions)} planned action{'' if len(actions) == 1 else 's'}"
        )
        failed_at = (
            getattr(operation, "completed_at", None)
            or getattr(operation, "updated_at", None)
            or getattr(operation, "created_at", None)
            or utc_now()
        )
        rendered.append(
            FailedRestoreResponse(
                id=str(identifier),
                title=_RESTORE_MODE_TITLES.get(str(getattr(mode, "value", mode)), "Restore"),
                detail=detail,
                failed_at=as_utc(failed_at),
                compensation_available=getattr(operation, "status", None) is RestoreStatus.COMPENSATION_AVAILABLE,
            )
        )
    return rendered


class OverviewService:
    """Assemble the Overview page, or only its navigation badge counts."""

    def __init__(
        self,
        reader: OverviewReader | None = None,
        change_groups: ChangeGroupService | None = None,
    ) -> None:
        self._reader = reader if reader is not None else BeanieOverviewReader()
        self._change_groups = change_groups if change_groups is not None else ChangeGroupService()

    async def collect(
        self,
        organization: Organization,
        *,
        range_key: str,
        viewer_email: str,
        counts_only: bool = False,
    ) -> OrganizationOverviewResponse:
        """Build the Overview read model for one organization and window."""
        if organization.id is None:
            msg = "Persisted organization is missing an identifier"
            raise ValueError(msg)
        organization_id = organization.id
        start, end = resolve_window(range_key)
        counts = await self._counts(organization_id, start=start, end=end, viewer_email=viewer_email)
        if counts_only:
            return OrganizationOverviewResponse(
                generated_at=utc_now(),
                range_start=start,
                range_end=end,
                counts=counts,
            )

        groups = await self._reader.recent_groups(organization_id, start=start, end=end, limit=FEED_LIMIT)
        summaries = await self._change_groups.summarize(
            organization_id,
            groups,
            viewer_email=viewer_email,
        )
        approvals = await self._reader.pending_approvals(organization_id, limit=APPROVAL_LIMIT)
        failures = await self._reader.failed_restores(organization_id, limit=FAILED_RESTORE_LIMIT)
        snapshot = await self._reader.latest_snapshot(organization_id)
        reconciliation = await self._reader.latest_reconciliation(organization_id)
        return OrganizationOverviewResponse(
            generated_at=utc_now(),
            range_start=start,
            range_end=end,
            counts=counts,
            change_groups=summaries,
            safety_net=build_safety_net(
                SafetyNetInput(
                    organization=organization,
                    latest_snapshot=snapshot,
                    latest_reconciliation=reconciliation,
                )
            ),
            pending_approvals=build_pending_approvals(approvals),
            failed_restores=build_failed_restores(failures),
            latest_snapshot_at=_snapshot_instant(snapshot),
            latest_snapshot_objects=snapshot.discovered_objects if snapshot is not None else None,
        )

    async def _counts(
        self,
        organization_id: PydanticObjectId,
        *,
        start: datetime,
        end: datetime,
        viewer_email: str,
    ) -> OverviewCountsResponse:
        groups = await self._reader.change_group_counts(
            organization_id,
            start=start,
            end=end,
            viewer_email=viewer_email,
        )
        return OverviewCountsResponse(
            change_groups=groups.change_groups,
            impacting=groups.impacting,
            mine=groups.mine,
            unrecovered=groups.unrecovered,
            pending_approvals=await self._reader.pending_approval_count(organization_id),
            failed_restores=await self._reader.failed_restore_count(organization_id),
        )
