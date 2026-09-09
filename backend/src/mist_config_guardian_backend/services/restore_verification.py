"""Post-restore verification: read-after-write, references, snapshot, monitoring.

The user interface must never report success while verification is incomplete,
so the executor treats this pass as part of the operation rather than as a
follow-up job: a failed check leaves the operation in a failed state.
"""

from collections.abc import Awaitable, Callable, Mapping
from datetime import timedelta
from uuid import uuid4

from beanie import PydanticObjectId
from celery.exceptions import CeleryError
from kombu.exceptions import OperationalError
from pymongo.errors import DuplicateKeyError

from mist_config_guardian_backend.integrations.mist_mutation import (
    MistMutationClient,
    MistMutationError,
)
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.monitoring import MonitoringSession, MonitoringStatus
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.restore import (
    RestoreActionStatus,
    RestoreActionType,
    RestoreOperation,
)
from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectVersion, SnapshotKind
from mist_config_guardian_backend.services.restore_planner import (
    RestoreStateStore,
    RestoreVerificationResult,
    VerificationCheck,
    get_restore_state_store,
    latest_version,
    load_or_build_state,
)
from mist_config_guardian_backend.snapshots.canonical import configuration_hash
from mist_config_guardian_backend.snapshots.registry import get_definition
from mist_config_guardian_backend.worker import celery_app

StaleReferenceFinder = Callable[[PydanticObjectId, set[str]], Awaitable[list[str]]]
SnapshotQueue = Callable[[PydanticObjectId], str | None]
MonitoringReopener = Callable[[PydanticObjectId, set[str]], Awaitable[list[str]]]

_MAX_REOPENED_SESSIONS = 50
_MONITORING_WINDOW_MINUTES = 60
_MONITORING_INTERVAL_MINUTES = 5
_MAX_REPORTED_FIELDS = 5


async def find_stale_references(
    organization_id: PydanticObjectId,
    replaced_ids: set[str],
) -> list[str]:
    """Name every current object still referencing a replaced Mist UUID."""
    if not replaced_ids:
        return []
    versions = await ObjectVersion.find(
        ObjectVersion.organization_id == organization_id,
        {"references.target_mist_id": {"$in": sorted(replaced_ids)}},
    ).to_list()
    stale: set[str] = set()
    for version in versions:
        current = await latest_version(version.logical_object_id)
        if current is None or current.id != version.id or current.is_deleted:
            continue
        logical = await LogicalObject.get(version.logical_object_id)
        stale.add(logical.name if logical is not None else str(version.logical_object_id))
    return sorted(stale)


def queue_post_restore_snapshot(organization_id: PydanticObjectId) -> str | None:
    """Queue a reconciling snapshot and return its task identifier."""
    task_id = str(uuid4())
    try:
        celery_app.send_task(
            "snapshots.collect",
            args=[str(organization_id), SnapshotKind.RECONCILIATION.value],
            task_id=task_id,
        )
    except (CeleryError, OperationalError):
        return None
    return task_id


async def reopen_monitoring_sessions(
    organization_id: PydanticObjectId,
    site_ids: set[str],
) -> list[str]:
    """Reopen closed monitoring windows for every site the restore touched."""
    if not site_ids:
        return []
    sessions = (
        await MonitoringSession.find(
            MonitoringSession.organization_id == organization_id,
            {"active": False, "site_id": {"$in": sorted(site_ids)}},
        )
        .sort("-created_at")
        .limit(_MAX_REOPENED_SESSIONS)
        .to_list()
    )
    now = utc_now()
    reopened: list[str] = []
    for session in sessions:
        session.active = True
        session.status = MonitoringStatus.MONITORING
        session.monitoring_started_at = now
        session.monitoring_ends_at = now + timedelta(minutes=_MONITORING_WINDOW_MINUTES)
        session.next_poll_at = now + timedelta(minutes=_MONITORING_INTERVAL_MINUTES)
        session.completed_at = None
        session.touch()
        try:
            await session.save()
        except DuplicateKeyError:
            continue
        if session.id is not None:
            reopened.append(str(session.id))
    return reopened


class RestoreVerificationService:
    """Verify a finished restore and persist the evidence for the API."""

    def __init__(
        self,
        store: RestoreStateStore | None = None,
        *,
        stale_references: StaleReferenceFinder | None = None,
        queue_snapshot: SnapshotQueue | None = None,
        reopen_monitoring: MonitoringReopener | None = None,
    ) -> None:
        self._store = store or get_restore_state_store()
        self._stale_references = stale_references or find_stale_references
        self._queue_snapshot = queue_snapshot or queue_post_restore_snapshot
        self._reopen_monitoring = reopen_monitoring or reopen_monitoring_sessions

    async def verify(
        self,
        client: MistMutationClient,
        organization: Organization,
        operation: RestoreOperation,
        *,
        id_map: Mapping[str, str],
        applied: Mapping[int, dict[str, object]],
    ) -> RestoreVerificationResult:
        """Run every post-restore check and persist the outcome."""
        checks = await self._read_after_write(client, organization, operation, applied)
        checks.append(await self._reference_check(operation.organization_id, set(id_map)))
        verified = all(check.status != "failed" for check in checks)

        snapshot_id = self._queue_snapshot(operation.organization_id)
        checks.append(
            VerificationCheck(
                label="Post-restore snapshot",
                status="ok" if snapshot_id else "skipped",
                detail=("Queued a reconciling snapshot" if snapshot_id else "The snapshot worker queue is unavailable"),
            )
        )
        session_ids = await self._reopen_monitoring(
            operation.organization_id,
            self._affected_sites(operation),
        )
        checks.append(
            VerificationCheck(
                label="Impact monitoring",
                status="ok" if session_ids else "skipped",
                detail=(
                    f"Reopened {len(session_ids)} monitoring sessions"
                    if session_ids
                    else "No closed monitoring session covers the restored sites"
                ),
            )
        )

        result = RestoreVerificationResult(
            verified=verified,
            checks=checks,
            post_snapshot_id=snapshot_id,
            monitoring_session_ids=session_ids,
        )
        await self.persist(operation, result)
        return result

    async def persist(
        self,
        operation: RestoreOperation,
        result: RestoreVerificationResult,
    ) -> None:
        """Store the verification result alongside the plan."""
        state = await load_or_build_state(self._store, operation)
        state.verification = result
        await self._store.save(state)

    async def result_for(self, operation: RestoreOperation) -> RestoreVerificationResult:
        """Return the persisted verification, or an unverified placeholder."""
        if operation.id is None:
            return RestoreVerificationResult()
        state = await self._store.load(operation.organization_id, operation.id)
        if state is None or state.verification is None:
            return RestoreVerificationResult(
                checks=[
                    VerificationCheck(
                        label="Post-restore verification",
                        status="skipped",
                        detail="This restore has not been executed yet",
                    )
                ]
            )
        return state.verification

    # -------------------------------------------------------------- internal
    async def _read_after_write(
        self,
        client: MistMutationClient,
        organization: Organization,
        operation: RestoreOperation,
        applied: Mapping[int, dict[str, object]],
    ) -> list[VerificationCheck]:
        checks: list[VerificationCheck] = []
        for action in operation.actions:
            if action.status is not RestoreActionStatus.COMPLETED:
                continue
            definition = get_definition(action.scope, action.object_type)
            if definition is None:
                checks.append(
                    VerificationCheck(
                        label=f"Read-after-write: {action.object_name}",
                        status="failed",
                        detail=f"Unsupported restore type {action.scope}:{action.object_type}",
                    )
                )
                continue
            try:
                current = await client.get_current(
                    definition,
                    action.resulting_mist_id or action.current_mist_id,
                    org_id=organization.mist_org_id,
                    site_id=action.site_mist_id,
                )
            except MistMutationError as exc:
                checks.append(
                    VerificationCheck(
                        label=f"Read-after-write: {action.object_name}",
                        status="failed",
                        detail=str(exc),
                    )
                )
                continue
            checks.append(self._compare(action.object_name, action.action, current, applied.get(action.order)))
        return checks

    @staticmethod
    def _compare(
        object_name: str,
        action_type: RestoreActionType,
        current: dict[str, object] | None,
        expected: dict[str, object] | None,
    ) -> VerificationCheck:
        label = f"Read-after-write: {object_name}"
        if action_type is RestoreActionType.DELETE:
            return VerificationCheck(
                label=label,
                status="ok" if current is None else "failed",
                detail=("Deleted object is gone" if current is None else "The object still exists in Mist"),
            )
        if current is None:
            return VerificationCheck(label=label, status="failed", detail="The object was not found after the write")
        if expected is None:
            return VerificationCheck(label=label, status="skipped", detail="No submitted payload was recorded")
        # Mist echoes server-managed fields the plan never sent, so the hash is
        # taken over exactly the fields this restore wrote.
        written = {key: value for key, value in current.items() if key in expected}
        if configuration_hash(written) == configuration_hash(expected):
            return VerificationCheck(label=label, status="ok", detail=f"{len(expected)} written fields match")
        differing = sorted(key for key in expected if written.get(key) != expected[key])
        listed = ", ".join(differing[:_MAX_REPORTED_FIELDS])
        if len(differing) > _MAX_REPORTED_FIELDS:
            listed = f"{listed}, +{len(differing) - _MAX_REPORTED_FIELDS} more"
        return VerificationCheck(label=label, status="failed", detail=f"Mist stored different values for {listed}")

    async def _reference_check(
        self,
        organization_id: PydanticObjectId,
        replaced_ids: set[str],
    ) -> VerificationCheck:
        label = "Replaced UUID references"
        if not replaced_ids:
            return VerificationCheck(label=label, status="skipped", detail="No object was recreated with a new UUID")
        stale = await self._stale_references(organization_id, replaced_ids)
        if not stale:
            return VerificationCheck(
                label=label,
                status="ok",
                detail=f"No current object references the {len(replaced_ids)} replaced UUIDs",
            )
        listed = ", ".join(stale[:_MAX_REPORTED_FIELDS])
        if len(stale) > _MAX_REPORTED_FIELDS:
            listed = f"{listed}, +{len(stale) - _MAX_REPORTED_FIELDS} more"
        return VerificationCheck(label=label, status="failed", detail=f"Still referencing a replaced UUID: {listed}")

    @staticmethod
    def _affected_sites(operation: RestoreOperation) -> set[str]:
        return {
            action.site_mist_id
            for action in operation.actions
            if action.status is RestoreActionStatus.COMPLETED and action.site_mist_id
        }
