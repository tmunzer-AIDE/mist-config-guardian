"""Post-restore verification and the execution progress it gates."""

from datetime import UTC, datetime, timedelta
from typing import Self

import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.organization import (
    MistCloudRegion,
    Organization,
    OrganizationStatus,
)
from mist_config_guardian_backend.models.restore import (
    RestoreAction,
    RestoreActionStatus,
    RestoreActionType,
    RestoreMode,
    RestoreOperation,
    RestoreStatus,
)
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.restore_executor import RestoreExecutionError, RestoreExecutor
from mist_config_guardian_backend.services.restore_planner import (
    RestoreOperationState,
    RestoreVerificationResult,
    VerificationCheck,
)
from mist_config_guardian_backend.services.restore_verification import RestoreVerificationService

ORGANIZATION_ID = PydanticObjectId()
OPERATION_ID = PydanticObjectId()
SOURCE_OPERATION_ID = PydanticObjectId()
REQUESTER_ID = PydanticObjectId()


def _vault() -> CredentialVault:
    return CredentialVault(Settings(environment="test", credential_encryption_key="test-key"))


def _organization() -> Organization:
    return Organization.model_construct(
        id=ORGANIZATION_ID,
        mist_org_id="org-1",
        name="Lab",
        cloud_region=MistCloudRegion.GLOBAL_01,
        status=OrganizationStatus.VERIFIED,
        encrypted_service_token="v1:encrypted-value",
        service_token_last_four="alue",
    )


def _action(
    order: int,
    action: RestoreActionType,
    *,
    status: RestoreActionStatus = RestoreActionStatus.PENDING,
    resulting_mist_id: str | None = None,
    configuration: dict[str, object] | None = None,
) -> RestoreAction:
    return RestoreAction(
        logical_object_id=PydanticObjectId(),
        source_version_id=PydanticObjectId(),
        order=order,
        action=action,
        scope="site",
        object_type="wlans",
        object_name=f"wlan-{order}",
        current_mist_id=f"mist-{order}",
        site_mist_id="site-a",
        protected_configuration=configuration or {"name": f"wlan-{order}", "enabled": True},
        expected_current_hash=None,
        status=status,
        resulting_mist_id=resulting_mist_id,
    )


def _operation(
    actions: list[RestoreAction],
    *,
    identifier: PydanticObjectId = OPERATION_ID,
    status: RestoreStatus = RestoreStatus.QUEUED,
    credential: str | None = "delegated-token",
) -> RestoreOperation:
    encrypted = None
    if credential is not None:
        encrypted = _vault().encrypt_for_context(credential, context=f"restore:{identifier}")
    return RestoreOperation.model_construct(
        id=identifier,
        organization_id=ORGANIZATION_ID,
        requested_by=REQUESTER_ID,
        mode=RestoreMode.NON_DESTRUCTIVE,
        include_dependencies=True,
        target_at=datetime(2026, 1, 1, tzinfo=UTC),
        status=status,
        actions=actions,
        warnings=[],
        preflight_errors=[],
        credential_actor="admin@example.com",
        encrypted_delegated_credential=encrypted,
        delegated_credential_expires_at=datetime.now(UTC) + timedelta(minutes=10),
        started_at=None,
        completed_at=None,
        failure_action_order=None,
        task_id="task-1",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        updated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


class _MemoryStateStore:
    """In-memory plan-lifecycle state."""

    def __init__(self) -> None:
        self.items: dict[tuple[PydanticObjectId, PydanticObjectId], RestoreOperationState] = {}

    async def load(self, organization_id, operation_id):
        return self.items.get((organization_id, operation_id))

    async def save(self, state):
        self.items[(state.organization_id, state.operation_id)] = state

    async def find_compensation_of(self, organization_id, operation_id):
        return next(
            (
                state
                for state in self.items.values()
                if state.organization_id == organization_id and state.compensates_operation_id == operation_id
            ),
            None,
        )


class _FakeClient:
    """A Mist mutation client that records writes and replays canned reads."""

    def __init__(self, readback: dict[str, dict[str, object] | None] | None = None) -> None:
        self.readback = readback or {}
        self.writes: list[tuple[str, str]] = []

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return

    async def create(self, definition, configuration, *, org_id, site_id):  # noqa: ARG002
        self.writes.append(("create", str(configuration.get("name"))))
        return {"id": "new-uuid", **configuration}

    async def update(self, definition, object_id, configuration, *, org_id, site_id):  # noqa: ARG002
        self.writes.append(("update", object_id))
        return dict(configuration)

    async def delete(self, definition, object_id, *, org_id, site_id) -> None:  # noqa: ARG002
        self.writes.append(("delete", object_id))

    async def get_current(self, definition, object_id, *, org_id, site_id):  # noqa: ARG002
        return self.readback.get(object_id)


class _StubNotifications:
    """Records restore lifecycle notifications."""

    def __init__(self) -> None:
        self.failed: list[str] = []
        self.completed: list[int] = []

    async def notify_restore_failed(self, *, organization_id, restore_id, reason, user_id=None):  # noqa: ARG002
        self.failed.append(reason)

    async def notify_restore_completed(self, *, organization_id, restore_id, applied_count, user_id=None):  # noqa: ARG002
        self.completed.append(applied_count)


class _StubVerifier:
    """Returns a fixed verification result and records the applied payloads."""

    def __init__(self, *, verified: bool) -> None:
        self.result = RestoreVerificationResult(
            verified=verified,
            checks=(
                []
                if verified
                else [
                    VerificationCheck(
                        label="Read-after-write: wlan-0",
                        status="failed",
                        detail="Mist stored different values for enabled",
                    )
                ]
            ),
        )
        self.applied: dict[int, dict[str, object]] = {}
        self.id_map: dict[str, str] = {}

    async def verify(self, client, organization, operation, *, id_map, applied):  # noqa: ARG002
        self.applied = dict(applied)
        self.id_map = dict(id_map)
        return self.result


# ---------------------------------------------------------------- verification


async def test_read_after_write_compares_only_the_fields_the_restore_wrote() -> None:
    service = _build_verifier()
    operation = _operation(
        [_action(0, RestoreActionType.UPDATE, status=RestoreActionStatus.COMPLETED, resulting_mist_id="mist-0")],
    )
    client = _FakeClient({"mist-0": {"name": "wlan-0", "enabled": True, "modified_time": 12345, "id": "mist-0"}})

    result = await service.verify(
        client,
        _organization(),
        operation,
        id_map={},
        applied={0: {"name": "wlan-0", "enabled": True}},
    )

    assert result.verified is True
    assert result.checks[0].status == "ok"


async def test_read_after_write_fails_when_mist_stored_something_else() -> None:
    service = _build_verifier()
    operation = _operation(
        [_action(0, RestoreActionType.UPDATE, status=RestoreActionStatus.COMPLETED, resulting_mist_id="mist-0")],
    )
    client = _FakeClient({"mist-0": {"name": "wlan-0", "enabled": False}})

    result = await service.verify(
        client,
        _organization(),
        operation,
        id_map={},
        applied={0: {"name": "wlan-0", "enabled": True}},
    )

    assert result.verified is False
    assert result.checks[0].status == "failed"
    assert "enabled" in (result.checks[0].detail or "")


async def test_a_delete_is_verified_by_absence() -> None:
    service = _build_verifier()
    operation = _operation([_action(0, RestoreActionType.DELETE, status=RestoreActionStatus.COMPLETED)])

    gone = await service.verify(_FakeClient({}), _organization(), operation, id_map={}, applied={})
    still_there = await service.verify(
        _FakeClient({"mist-0": {"name": "wlan-0"}}),
        _organization(),
        operation,
        id_map={},
        applied={},
    )

    assert gone.verified is True
    assert still_there.verified is False


async def test_a_stale_replaced_uuid_reference_fails_verification() -> None:
    service = _build_verifier(stale=["Corp firewall rule"])
    operation = _operation([_action(0, RestoreActionType.CREATE, status=RestoreActionStatus.COMPLETED)])

    result = await service.verify(
        _FakeClient({"mist-0": {"name": "wlan-0"}}),
        _organization(),
        operation,
        id_map={"old-uuid": "new-uuid"},
        applied={0: {"name": "wlan-0"}},
    )

    assert result.verified is False
    reference_check = next(check for check in result.checks if check.label == "Replaced UUID references")
    assert reference_check.status == "failed"
    assert "Corp firewall rule" in (reference_check.detail or "")


async def test_verification_queues_a_snapshot_and_reopens_monitoring() -> None:
    store = _MemoryStateStore()
    service = _build_verifier(store=store, sessions=["session-1", "session-2"])
    operation = _operation([_action(0, RestoreActionType.UPDATE, status=RestoreActionStatus.COMPLETED)])

    result = await service.verify(
        _FakeClient({"mist-0": {"name": "wlan-0", "enabled": True}}),
        _organization(),
        operation,
        id_map={},
        applied={0: {"name": "wlan-0", "enabled": True}},
    )

    assert result.post_snapshot_id == "snapshot-task"
    assert result.monitoring_session_ids == ["session-1", "session-2"]
    stored = await store.load(ORGANIZATION_ID, OPERATION_ID)
    assert stored is not None
    assert stored.verification is not None
    assert stored.verification.verified is True


async def test_verification_read_reports_an_unexecuted_plan() -> None:
    service = _build_verifier()

    result = await service.result_for(_operation([_action(0, RestoreActionType.UPDATE)]))

    assert result.verified is False
    assert result.checks[0].status == "skipped"


def _build_verifier(
    *,
    store: _MemoryStateStore | None = None,
    stale: list[str] | None = None,
    sessions: list[str] | None = None,
) -> RestoreVerificationService:
    async def _stale(_organization_id, _replaced):
        return list(stale or [])

    async def _reopen(_organization_id, _sites):
        return list(sessions or [])

    return RestoreVerificationService(
        store or _MemoryStateStore(),
        stale_references=_stale,
        queue_snapshot=lambda _organization_id: "snapshot-task",
        reopen_monitoring=_reopen,
    )


# ------------------------------------------------------------------- execution


@pytest.fixture
def executed(monkeypatch: pytest.MonkeyPatch) -> list[tuple[RestoreStatus, tuple, tuple]]:
    """Run the executor against fakes and record every persisted state."""
    saves: list[tuple[RestoreStatus, tuple, tuple]] = []

    async def _record(self) -> None:
        saves.append(
            (
                self.status,
                tuple(action.status for action in self.actions),
                tuple(action.resulting_mist_id for action in self.actions),
            )
        )

    monkeypatch.setattr(RestoreOperation, "save", _record)

    async def _organization_get(_document_id, *_args, **_kwargs):
        return _organization()

    monkeypatch.setattr(Organization, "get", _organization_get)

    async def _no_record_result(*_args, **_kwargs) -> None:
        return

    monkeypatch.setattr(RestoreExecutor, "_record_result", _no_record_result)

    async def _snapshot(*_args, **_kwargs):
        return []

    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_executor.capture_safety_snapshot",
        _snapshot,
    )
    return saves


def _run(
    monkeypatch: pytest.MonkeyPatch,
    operation: RestoreOperation,
    *,
    verified: bool,
    store: _MemoryStateStore | None = None,
) -> tuple[RestoreExecutor, _StubNotifications, _StubVerifier, _FakeClient]:
    client = _FakeClient()
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_executor.MistMutationClient",
        lambda **_kwargs: client,
    )

    async def _get(_document_id, *_args, **_kwargs):
        return operation

    monkeypatch.setattr(RestoreOperation, "get", _get)
    notifications = _StubNotifications()
    verifier = _StubVerifier(verified=verified)
    executor = RestoreExecutor(
        _vault(),
        store=store or _MemoryStateStore(),
        notifications=notifications,
        verifier=verifier,
    )
    return executor, notifications, verifier, client


@pytest.mark.usefixtures("executed")
async def test_a_verified_restore_completes(monkeypatch: pytest.MonkeyPatch) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE), _action(1, RestoreActionType.CREATE)])
    executor, notifications, verifier, client = _run(monkeypatch, operation, verified=True)

    result = await executor.execute(OPERATION_ID)

    assert result.status is RestoreStatus.COMPLETED
    assert result.completed_at is not None
    assert result.encrypted_delegated_credential is None
    assert notifications.completed == [2]
    assert notifications.failed == []
    assert client.writes == [("update", "mist-0"), ("create", "wlan-1")]
    assert verifier.id_map == {"mist-1": "new-uuid"}
    assert set(verifier.applied) == {0, 1}


@pytest.mark.usefixtures("executed")
async def test_a_failed_verification_never_reports_success(monkeypatch: pytest.MonkeyPatch) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    store = _MemoryStateStore()
    executor, notifications, _, _ = _run(monkeypatch, operation, verified=False, store=store)

    result = await executor.execute(OPERATION_ID)

    assert result.status is RestoreStatus.COMPENSATION_AVAILABLE
    assert result.status is not RestoreStatus.COMPLETED
    assert notifications.completed == []
    assert len(notifications.failed) == 1
    assert "Post-restore verification failed" in notifications.failed[0]
    assert any("verification failed" in error for error in result.preflight_errors)


async def test_per_action_progress_is_persisted_as_it_happens(
    monkeypatch: pytest.MonkeyPatch,
    executed: list[tuple[RestoreStatus, tuple, tuple]],
) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE), _action(1, RestoreActionType.CREATE)])
    executor, _, _, _ = _run(monkeypatch, operation, verified=True)

    await executor.execute(OPERATION_ID)

    statuses = [entry[1] for entry in executed]
    assert (RestoreActionStatus.EXECUTING, RestoreActionStatus.PENDING) in statuses
    assert (RestoreActionStatus.COMPLETED, RestoreActionStatus.PENDING) in statuses
    assert (RestoreActionStatus.COMPLETED, RestoreActionStatus.EXECUTING) in statuses
    assert executed[-1][1] == (RestoreActionStatus.COMPLETED, RestoreActionStatus.COMPLETED)
    assert executed[-1][2] == ("mist-0", "new-uuid")
    running = [entry for entry in executed if entry[0] is RestoreStatus.RUNNING]
    assert len(running) > 1


@pytest.mark.usefixtures("executed")
async def test_a_redelivered_task_refuses_to_apply_the_plan_twice(monkeypatch: pytest.MonkeyPatch) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE)], status=RestoreStatus.RUNNING)
    executor, _, _, client = _run(monkeypatch, operation, verified=True)

    with pytest.raises(RestoreExecutionError, match="not ready to execute"):
        await executor.execute(OPERATION_ID)

    assert client.writes == []


@pytest.mark.usefixtures("executed")
async def test_a_completed_action_is_not_applied_again_on_resume(monkeypatch: pytest.MonkeyPatch) -> None:
    operation = _operation(
        [
            _action(0, RestoreActionType.CREATE, status=RestoreActionStatus.COMPLETED, resulting_mist_id="new-uuid"),
            _action(1, RestoreActionType.UPDATE),
        ]
    )
    executor, _, verifier, client = _run(monkeypatch, operation, verified=True)

    await executor.execute(OPERATION_ID)

    assert client.writes == [("update", "mist-1")]
    assert verifier.id_map == {"mist-0": "new-uuid"}


@pytest.mark.usefixtures("executed")
async def test_a_verified_compensation_marks_both_operations_compensated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marked: list[PydanticObjectId] = []

    async def _mark(_organization_id, operation_id) -> None:
        marked.append(operation_id)

    monkeypatch.setattr(RestoreExecutor, "_mark_compensated", staticmethod(_mark))
    store = _MemoryStateStore()
    await store.save(
        RestoreOperationState(
            organization_id=ORGANIZATION_ID,
            operation_id=OPERATION_ID,
            plan_hash="plan-hash",
            compensates_operation_id=SOURCE_OPERATION_ID,
        )
    )
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    executor, _, _, _ = _run(monkeypatch, operation, verified=True, store=store)

    result = await executor.execute(OPERATION_ID)

    assert result.status is RestoreStatus.COMPENSATED
    assert marked == [SOURCE_OPERATION_ID]
