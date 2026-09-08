"""Organization overview read-model and API tests."""

from datetime import UTC, datetime, timedelta

import httpx
from beanie import PydanticObjectId

from mist_config_guardian_backend.api.dependencies import get_current_user, require_organization
from mist_config_guardian_backend.api.routes.overview import get_overview_service
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.main import create_app
from mist_config_guardian_backend.models.approval import ApprovalStatus, RestoreApproval
from mist_config_guardian_backend.models.monitoring import ImpactSeverity
from mist_config_guardian_backend.models.organization import (
    MistCloudRegion,
    Organization,
    OrganizationStatus,
)
from mist_config_guardian_backend.models.restore import (
    RestoreMode,
    RestoreOperation,
    RestoreStatus,
)
from mist_config_guardian_backend.models.snapshot import (
    SnapshotError,
    SnapshotKind,
    SnapshotManifest,
    SnapshotStatus,
)
from mist_config_guardian_backend.models.user import User, UserRole
from mist_config_guardian_backend.models.webhook import AuditChangeGroup, RecoveryState
from mist_config_guardian_backend.services.change_groups import ChangeGroupService
from mist_config_guardian_backend.services.overview import (
    ChangeGroupCounts,
    OverviewService,
    SafetyNetInput,
    actor_pattern,
    build_failed_restores,
    build_pending_approvals,
    build_safety_net,
    cron_cadence_minutes,
    format_cadence,
)

ORGANIZATION_ID = PydanticObjectId()
OTHER_ORGANIZATION_ID = PydanticObjectId()
NOW = datetime(2026, 9, 7, 14, 22, tzinfo=UTC)
VIEWER_EMAIL = "j.mercer@northwind.example"


def _organization(  # noqa: PLR0913 - a fixture builder mirrors the document's fields
    *,
    organization_id: PydanticObjectId = ORGANIZATION_ID,
    encrypted_webhook: str | None = "v1:configured",
    webhook_received: datetime | None = None,
    verified: datetime | None = datetime(2026, 9, 6, 9, 12, tzinfo=UTC),
    credential_error: str | None = None,
    cron: str = "0 */12 * * *",
    onboarded: datetime = NOW,
    initial_snapshot: datetime | None = None,
) -> Organization:
    return Organization.model_construct(
        id=organization_id,
        mist_org_id="org-1",
        name="Northwind Retail",
        cloud_region=MistCloudRegion.GLOBAL_01,
        status=OrganizationStatus.VERIFIED,
        encrypted_service_token="v1:encrypted-value",
        service_token_last_four="4f21",
        credential_key_version=1,
        credential_verified_at=verified,
        credential_error=credential_error,
        discovered_privileges=[],
        encrypted_webhook_secret=encrypted_webhook,
        webhook_secret_last_four="a9ac" if encrypted_webhook else None,
        webhook_secret_rotated_at=None,
        webhook_last_received_at=webhook_received,
        webhook_last_signature_valid=True,
        initial_snapshot_completed_at=initial_snapshot,
        reconciliation_cron=cron,
        configuration_retention_days=180,
        monitoring_retention_days=30,
        created_at=onboarded,
        updated_at=NOW,
    )


def _snapshot(
    *,
    kind: SnapshotKind = SnapshotKind.RECONCILIATION,
    completed_at: datetime | None = datetime(2026, 9, 7, 14, 18, tzinfo=UTC),
    objects: int = 1284,
    status: SnapshotStatus = SnapshotStatus.COMPLETED,
    errors: int = 0,
) -> SnapshotManifest:
    return SnapshotManifest.model_construct(
        id=PydanticObjectId(),
        organization_id=ORGANIZATION_ID,
        kind=kind,
        status=status,
        active=False,
        started_at=completed_at,
        completed_at=completed_at,
        discovered_objects=objects,
        created_versions=0,
        unchanged_objects=objects,
        deleted_objects=0,
        errors=[SnapshotError(object_type="wlans", message="boom") for _ in range(errors)],
        created_at=completed_at or NOW,
        updated_at=completed_at or NOW,
    )


def _group(*, audit_id: str, occurred_at: datetime | None = None) -> AuditChangeGroup:
    moment = occurred_at or datetime.now(tz=UTC) - timedelta(hours=1)
    return AuditChangeGroup.model_construct(
        id=PydanticObjectId(),
        organization_id=ORGANIZATION_ID,
        audit_id=audit_id,
        actor="j.mercer",
        method="PUT",
        message="modify wlan",
        occurred_at=moment,
        receipt_ids=[],
        affected_site_ids=[],
        affected_object_ids=[],
        changed_objects=[],
        affected_devices=[],
        monitoring_session_ids=[],
        impact_severity=ImpactSeverity.NONE,
        recovery_state=RecoveryState.NOT_APPLICABLE,
        degraded_metrics=[],
        summary="Nothing moved.",
        evidence=[],
        created_at=moment,
        updated_at=moment,
    )


def _approval(*, summary: str = "Exact point-in-time restore") -> RestoreApproval:
    return RestoreApproval.model_construct(
        id=PydanticObjectId(),
        organization_id=ORGANIZATION_ID,
        restore_operation_id=PydanticObjectId(),
        requested_by=PydanticObjectId(),
        requested_by_email="s.kaur@northwind.example",
        plan_hash="hash",
        triggered_rules=[],
        status=ApprovalStatus.PENDING,
        expires_at=NOW + timedelta(hours=24),
        summary=summary,
        object_count=14,
        delete_count=3,
        created_at=NOW - timedelta(minutes=26),
        updated_at=NOW,
    )


def _restore(
    *,
    status: RestoreStatus = RestoreStatus.COMPENSATION_AVAILABLE,
    failure_order: int | None = 2,
    actions: int = 9,
) -> RestoreOperation:
    return RestoreOperation.model_construct(
        id=PydanticObjectId(),
        organization_id=ORGANIZATION_ID,
        requested_by=PydanticObjectId(),
        mode=RestoreMode.EXACT,
        include_dependencies=True,
        target_at=NOW - timedelta(days=1),
        status=status,
        actions=[object()] * actions,
        warnings=[],
        preflight_errors=[],
        failure_action_order=failure_order,
        completed_at=NOW - timedelta(hours=6),
        created_at=NOW - timedelta(hours=7),
        updated_at=NOW - timedelta(hours=6),
    )


class _MemoryOverviewReader:
    """Reader double that records exactly which aggregates a request touched."""

    def __init__(self) -> None:
        self.counts = ChangeGroupCounts(change_groups=5, impacting=2, mine=1, unrecovered=1)
        self.approval_count = 2
        self.failure_count = 1
        self.groups: list[AuditChangeGroup] = []
        self.approvals: list[RestoreApproval] = []
        self.failures: list[RestoreOperation] = []
        self.snapshot: SnapshotManifest | None = None
        self.reconciliation: SnapshotManifest | None = None
        self.calls: list[str] = []
        self.scoped_to: list[PydanticObjectId] = []

    async def change_group_counts(
        self,
        organization_id: PydanticObjectId,
        *,
        start: datetime,
        end: datetime,
        viewer_email: str,
    ) -> ChangeGroupCounts:
        del start, end, viewer_email
        self.calls.append("change_group_counts")
        self.scoped_to.append(organization_id)
        return self.counts

    async def pending_approval_count(self, organization_id: PydanticObjectId) -> int:
        self.calls.append("pending_approval_count")
        self.scoped_to.append(organization_id)
        return self.approval_count

    async def failed_restore_count(self, organization_id: PydanticObjectId) -> int:
        self.calls.append("failed_restore_count")
        self.scoped_to.append(organization_id)
        return self.failure_count

    async def recent_groups(
        self,
        organization_id: PydanticObjectId,
        *,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> list[AuditChangeGroup]:
        del limit
        self.calls.append("recent_groups")
        self.scoped_to.append(organization_id)
        return [
            group
            for group in self.groups
            if group.organization_id == organization_id
            and group.occurred_at is not None
            and start <= group.occurred_at <= end
        ]

    async def pending_approvals(
        self,
        organization_id: PydanticObjectId,
        *,
        limit: int,
    ) -> list[RestoreApproval]:
        del limit
        self.calls.append("pending_approvals")
        self.scoped_to.append(organization_id)
        return [item for item in self.approvals if item.organization_id == organization_id]

    async def failed_restores(
        self,
        organization_id: PydanticObjectId,
        *,
        limit: int,
    ) -> list[RestoreOperation]:
        del limit
        self.calls.append("failed_restores")
        self.scoped_to.append(organization_id)
        return [item for item in self.failures if item.organization_id == organization_id]

    async def latest_snapshot(self, organization_id: PydanticObjectId) -> SnapshotManifest | None:
        self.calls.append("latest_snapshot")
        self.scoped_to.append(organization_id)
        return self.snapshot

    async def latest_reconciliation(self, organization_id: PydanticObjectId) -> SnapshotManifest | None:
        self.calls.append("latest_reconciliation")
        self.scoped_to.append(organization_id)
        return self.reconciliation


class _EmptyChangeGroupStore:
    """Enough of the change-group store for the Overview feed to render."""

    async def sessions_by_id(
        self,
        organization_id: PydanticObjectId,
        session_ids: list[PydanticObjectId],
    ) -> list[object]:
        del organization_id, session_ids
        return []

    async def site_names(
        self,
        organization_id: PydanticObjectId,
        site_ids: list[str],
    ) -> dict[str, str]:
        del organization_id, site_ids
        return {}


def _service(reader: _MemoryOverviewReader) -> OverviewService:
    return OverviewService(reader, ChangeGroupService(_EmptyChangeGroupStore()))


def _viewer(email: str = VIEWER_EMAIL) -> User:
    return User.model_construct(
        id=PydanticObjectId(),
        email=email,
        display_name="Viewer",
        password_hash="unused",
        role=UserRole.VIEWER,
        is_active=True,
    )


# ------------------------------------------------------------------- cadence


def test_cron_cadence_reads_the_expressions_the_app_writes() -> None:
    assert cron_cadence_minutes("*/15 * * * *") == 15
    assert cron_cadence_minutes("0 */12 * * *") == 12 * 60
    assert cron_cadence_minutes("0 * * * *") == 60
    assert cron_cadence_minutes("0 2 * * *") == 24 * 60
    assert cron_cadence_minutes("nonsense") is None


def test_cadence_formats_the_way_the_safety_net_prints_it() -> None:
    assert format_cadence(12 * 60) == "12H"
    assert format_cadence(24 * 60) == "1D"
    assert format_cadence(15) == "15M"


def test_actor_pattern_anchors_on_the_address_and_its_local_part() -> None:
    assert actor_pattern("J.Mercer@Northwind.example") == r"^(j\.mercer@northwind\.example|j\.mercer)$"


# ---------------------------------------------------------------- safety net


def test_safety_net_matches_the_designs_healthy_organization() -> None:
    rows = build_safety_net(
        SafetyNetInput(
            organization=_organization(webhook_received=NOW - timedelta(minutes=3)),
            latest_snapshot=_snapshot(),
            latest_reconciliation=_snapshot(),
            now=NOW,
        )
    )

    assert [row.key for row in rows] == ["backup", "webhook", "reconciliation", "credential"]
    assert (rows[0].label, rows[0].status, rows[0].detail) == ("Backup 4m behind", "ok", "14:18Z")
    assert (rows[1].label, rows[1].status) == ("Webhook delivery current", "ok")
    assert (rows[2].label, rows[2].status, rows[2].detail) == ("Reconciliation on schedule", "ok", "12H")
    assert (rows[3].label, rows[3].status, rows[3].detail) == ("Service token verified", "ok", "06 SEP")


def test_a_failed_backup_is_reported_however_recent_the_last_success_was() -> None:
    """Reporting the last success instead would leave the row green while every
    run since had been failing."""
    rows = build_safety_net(
        SafetyNetInput(
            organization=_organization(webhook_received=NOW),
            latest_snapshot=_snapshot(status=SnapshotStatus.FAILED),
            latest_reconciliation=_snapshot(),
            now=NOW,
        )
    )

    backup = next(row for row in rows if row.key == "backup")
    assert (backup.label, backup.status) == ("Last backup failed", "warn")


def test_a_partial_backup_is_not_a_backup() -> None:
    """Some objects captured and others given up on leaves the record incomplete."""
    rows = build_safety_net(
        SafetyNetInput(
            organization=_organization(webhook_received=NOW),
            latest_snapshot=_snapshot(status=SnapshotStatus.PARTIAL, errors=2),
            latest_reconciliation=_snapshot(),
            now=NOW,
        )
    )

    backup = next(row for row in rows if row.key == "backup")
    assert backup.label == "Last backup incomplete · 2 errors"
    assert backup.status == "warn"


def test_safety_net_reports_a_webhook_gap_with_its_interval() -> None:
    rows = build_safety_net(
        SafetyNetInput(
            organization=_organization(webhook_received=datetime(2026, 9, 7, 11, 4, tzinfo=UTC)),
            latest_snapshot=_snapshot(),
            latest_reconciliation=_snapshot(),
            now=datetime(2026, 9, 7, 11, 19, tzinfo=UTC),
        )
    )

    webhook = next(row for row in rows if row.key == "webhook")
    assert webhook.label == "Webhook gap 15m"
    assert webhook.status == "warn"
    assert webhook.detail == "11:04Z"


def test_safety_net_for_an_unverified_organization_drops_reconciliation() -> None:
    rows = build_safety_net(
        SafetyNetInput(
            organization=_organization(encrypted_webhook=None, verified=None),
            latest_snapshot=None,
            latest_reconciliation=None,
            now=NOW,
        )
    )

    assert [(row.key, row.label, row.status, row.detail) for row in rows] == [
        ("backup", "No snapshot recorded", "warn", "—"),
        ("webhook", "Webhook not configured", "warn", "—"),
        ("credential", "Token not verified", "warn", "—"),
    ]


def test_safety_net_escalates_a_credential_error_to_critical() -> None:
    rows = build_safety_net(
        SafetyNetInput(
            organization=_organization(credential_error="401 Unauthorized"),
            latest_snapshot=_snapshot(),
            latest_reconciliation=_snapshot(),
            now=NOW,
        )
    )

    credential = next(row for row in rows if row.key == "credential")
    assert credential.status == "crit"
    assert credential.label == "Token not verified"


def test_safety_net_flags_an_overdue_reconciliation() -> None:
    rows = build_safety_net(
        SafetyNetInput(
            organization=_organization(webhook_received=NOW),
            latest_snapshot=_snapshot(),
            latest_reconciliation=_snapshot(completed_at=NOW - timedelta(days=3)),
            now=NOW,
        )
    )

    reconciliation = next(row for row in rows if row.key == "reconciliation")
    assert reconciliation.label == "Reconciliation overdue"
    assert reconciliation.status == "warn"


def test_safety_net_flags_a_reconciliation_that_never_ran_once_its_cadence_has_passed() -> None:
    """With nothing to measure from, the clock runs from the organization's own start."""
    rows = build_safety_net(
        SafetyNetInput(
            organization=_organization(webhook_received=NOW, initial_snapshot=NOW - timedelta(days=3)),
            latest_snapshot=_snapshot(),
            latest_reconciliation=None,
            now=NOW,
        )
    )

    reconciliation = next(row for row in rows if row.key == "reconciliation")
    assert reconciliation.label == "Reconciliation never completed"
    assert reconciliation.status == "warn"


def test_a_manual_snapshot_does_not_postpone_the_never_reconciled_warning() -> None:
    """Taking a backup by hand is not reconciling; the deadline is not its to move."""
    rows = build_safety_net(
        SafetyNetInput(
            organization=_organization(webhook_received=NOW, onboarded=NOW - timedelta(days=3)),
            # A manual snapshot taken moments ago.
            latest_snapshot=_snapshot(completed_at=NOW),
            latest_reconciliation=None,
            now=NOW,
        )
    )

    reconciliation = next(row for row in rows if row.key == "reconciliation")
    assert (reconciliation.label, reconciliation.status) == ("Reconciliation never completed", "warn")


def test_a_reconciliation_not_yet_due_is_on_schedule_even_though_none_has_run() -> None:
    rows = build_safety_net(
        SafetyNetInput(
            organization=_organization(webhook_received=NOW, initial_snapshot=NOW),
            latest_snapshot=_snapshot(),
            latest_reconciliation=None,
            now=NOW,
        )
    )

    reconciliation = next(row for row in rows if row.key == "reconciliation")
    assert (reconciliation.label, reconciliation.status) == ("Reconciliation on schedule", "ok")


def test_safety_net_warns_when_a_configured_webhook_never_delivered() -> None:
    rows = build_safety_net(
        SafetyNetInput(
            organization=_organization(webhook_received=None),
            latest_snapshot=_snapshot(),
            latest_reconciliation=_snapshot(),
            now=NOW,
        )
    )

    webhook = next(row for row in rows if row.key == "webhook")
    assert webhook.label == "No webhook events received"
    assert webhook.status == "warn"


# -------------------------------------------------- approvals and failures


def test_pending_approvals_render_the_designs_object_and_deletion_counts() -> None:
    rows = build_pending_approvals([_approval()])

    assert rows[0].title == "Exact point-in-time restore"
    assert rows[0].detail == "14 objects · 3 deletions"
    assert rows[0].requested_by_email == "s.kaur@northwind.example"


def test_pending_approvals_survive_a_record_written_by_another_workstream() -> None:
    sparse = RestoreApproval.model_construct(
        id=PydanticObjectId(),
        organization_id=ORGANIZATION_ID,
        restore_operation_id=PydanticObjectId(),
    )
    headless = RestoreApproval.model_construct(id=PydanticObjectId())

    rows = build_pending_approvals([sparse, headless])

    assert len(rows) == 1
    assert rows[0].title == "Restore approval"
    assert rows[0].detail == "0 objects"
    assert rows[0].requested_by_email == ""


def test_failed_restores_name_the_action_they_stopped_on() -> None:
    rows = build_failed_restores([_restore()])

    assert rows[0].title == "Exact point-in-time restore"
    assert rows[0].detail == "Failed at action 3 of 9"
    assert rows[0].compensation_available is True


def test_failed_restores_without_a_failure_point_report_the_plan_size() -> None:
    rows = build_failed_restores([_restore(status=RestoreStatus.FAILED, failure_order=None, actions=4)])

    assert rows[0].detail == "4 planned actions"
    assert rows[0].compensation_available is False


def test_failed_restores_tolerate_an_empty_collection() -> None:
    assert build_failed_restores([]) == []
    assert build_pending_approvals([]) == []


# ----------------------------------------------------------------- assembly


async def test_counts_only_stops_after_the_three_counting_queries() -> None:
    reader = _MemoryOverviewReader()
    reader.groups.append(_group(audit_id="audit-1"))
    reader.approvals.append(_approval())
    reader.failures.append(_restore())
    reader.snapshot = _snapshot()

    overview = await _service(reader).collect(
        _organization(),
        range_key="24h",
        viewer_email=VIEWER_EMAIL,
        counts_only=True,
    )

    assert reader.calls == [
        "change_group_counts",
        "pending_approval_count",
        "failed_restore_count",
    ]
    assert overview.counts.change_groups == 5
    assert overview.counts.unrecovered == 1
    assert overview.counts.pending_approvals == 2
    assert overview.counts.failed_restores == 1
    assert overview.change_groups == []
    assert overview.safety_net == []
    assert overview.pending_approvals == []
    assert overview.failed_restores == []
    assert overview.latest_snapshot_at is None


async def test_full_overview_assembles_every_section_once() -> None:
    reader = _MemoryOverviewReader()
    reader.groups.append(_group(audit_id="audit-1"))
    reader.approvals.append(_approval())
    reader.failures.append(_restore())
    reader.snapshot = _snapshot()
    reader.reconciliation = _snapshot()

    overview = await _service(reader).collect(
        _organization(webhook_received=datetime.now(tz=UTC)),
        range_key="24h",
        viewer_email=VIEWER_EMAIL,
    )

    assert reader.calls == [
        "change_group_counts",
        "pending_approval_count",
        "failed_restore_count",
        "recent_groups",
        "pending_approvals",
        "failed_restores",
        "latest_snapshot",
        "latest_reconciliation",
    ]
    assert len(overview.change_groups) == 1
    assert overview.change_groups[0].is_mine is True
    assert len(overview.safety_net) == 4
    assert len(overview.pending_approvals) == 1
    assert len(overview.failed_restores) == 1
    assert overview.latest_snapshot_objects == 1284
    assert overview.range_start < overview.range_end


async def test_overview_range_widens_the_feed_window() -> None:
    reader = _MemoryOverviewReader()
    now = datetime.now(tz=UTC)
    reader.groups.extend(
        [
            _group(audit_id="today", occurred_at=now - timedelta(hours=3)),
            _group(audit_id="last-week", occurred_at=now - timedelta(days=5)),
        ]
    )

    day = await _service(reader).collect(_organization(), range_key="24h", viewer_email=VIEWER_EMAIL)
    week = await _service(reader).collect(_organization(), range_key="7d", viewer_email=VIEWER_EMAIL)

    assert [item.audit_id for item in day.change_groups] == ["today"]
    assert sorted(item.audit_id for item in week.change_groups) == ["last-week", "today"]


async def test_overview_as_of_ends_the_window_there_and_omits_what_has_no_past() -> None:
    """Browsing the past shows the changes of the past, not today's operational state."""
    reader = _MemoryOverviewReader()
    now = datetime.now(tz=UTC)
    reader.groups.extend(
        [
            _group(audit_id="today", occurred_at=now - timedelta(hours=3)),
            _group(audit_id="last-week", occurred_at=now - timedelta(days=5)),
        ]
    )
    reader.approvals.append(_approval())
    reader.failures.append(_restore())
    reader.snapshot = _snapshot()
    reader.reconciliation = _snapshot()

    overview = await _service(reader).collect(
        _organization(webhook_received=now),
        range_key="7d",
        viewer_email=VIEWER_EMAIL,
        as_of=now - timedelta(days=4),
    )

    assert overview.historical is True
    assert overview.range_end == now - timedelta(days=4)
    assert [item.audit_id for item in overview.change_groups] == ["last-week"]
    assert overview.pending_approvals == []
    assert overview.failed_restores == []
    assert overview.safety_net == []
    assert overview.latest_snapshot_at is None
    assert (overview.counts.pending_approvals, overview.counts.failed_restores) == (0, 0)
    # Nothing live was even asked for.
    assert not {"pending_approvals", "failed_restores", "latest_snapshot", "latest_reconciliation"} & set(reader.calls)


async def test_overview_scopes_every_query_to_one_organization() -> None:
    reader = _MemoryOverviewReader()
    reader.groups.append(_group(audit_id="audit-1"))
    reader.approvals.append(_approval())
    reader.failures.append(_restore())

    overview = await _service(reader).collect(
        _organization(organization_id=OTHER_ORGANIZATION_ID),
        range_key="24h",
        viewer_email=VIEWER_EMAIL,
    )

    assert set(reader.scoped_to) == {OTHER_ORGANIZATION_ID}
    assert overview.change_groups == []
    assert overview.pending_approvals == []
    assert overview.failed_restores == []


# ----------------------------------------------------------------------- api


def _app(service: OverviewService, organization: Organization) -> object:
    app = create_app(Settings(environment="test", database_enabled=False))
    app.dependency_overrides[get_current_user] = _viewer
    app.dependency_overrides[require_organization] = lambda: organization
    app.dependency_overrides[get_overview_service] = lambda: service
    return app


async def test_overview_endpoint_returns_the_full_contract() -> None:
    reader = _MemoryOverviewReader()
    reader.groups.append(_group(audit_id="audit-1"))
    reader.snapshot = _snapshot()
    app = _app(_service(reader), _organization(webhook_received=datetime.now(tz=UTC)))

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(f"/api/v1/organizations/{ORGANIZATION_ID}/overview", params={"range": "24h"})

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "generated_at",
        "range_start",
        "range_end",
        "counts",
        "change_groups",
        "safety_net",
        "pending_approvals",
        "failed_restores",
        "historical",
        "latest_snapshot_at",
        "latest_snapshot_objects",
    }
    assert set(body["counts"]) == {
        "change_groups",
        "impacting",
        "mine",
        "unrecovered",
        "pending_approvals",
        "failed_restores",
    }
    assert body["safety_net"][0]["label"] == "Backup 4m behind" or body["safety_net"][0]["key"] == "backup"


async def test_overview_endpoint_counts_only_returns_empty_sections() -> None:
    reader = _MemoryOverviewReader()
    reader.groups.append(_group(audit_id="audit-1"))
    app = _app(_service(reader), _organization())

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(
            f"/api/v1/organizations/{ORGANIZATION_ID}/overview",
            params={"counts_only": "true"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["counts"]["unrecovered"] == 1
    assert body["change_groups"] == []
    assert body["safety_net"] == []
    assert reader.calls == [
        "change_group_counts",
        "pending_approval_count",
        "failed_restore_count",
    ]


async def test_overview_endpoint_rejects_an_unknown_range() -> None:
    app = _app(_service(_MemoryOverviewReader()), _organization())

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(
            f"/api/v1/organizations/{ORGANIZATION_ID}/overview",
            params={"range": "all-time"},
        )

    assert response.status_code == 422
