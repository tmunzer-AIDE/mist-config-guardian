"""Post-restore verification and the execution progress it gates."""

import logging
from datetime import UTC, datetime, timedelta
from typing import Self
from unittest.mock import AsyncMock

import pytest
from beanie import PydanticObjectId
from beanie.odm.fields import ExpressionField
from pymongo.errors import DuplicateKeyError

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.integrations.mist_mutation import MistMutationStatusError, MistMutationTransportError
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
from mist_config_guardian_backend.models.snapshot import (
    LogicalObject,
    ObjectReference,
    ObjectVersion,
    VersionEvent,
)
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.restore_executor import RestoreExecutionError, RestoreExecutor
from mist_config_guardian_backend.services.restore_planner import (
    RestoreOperationState,
    RestoreVerificationResult,
    SafetySnapshotEntry,
    VerificationCheck,
)
from mist_config_guardian_backend.services.restore_verification import (
    RestoreVerificationService,
    find_stale_references,
)

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


class _FailingClient(_FakeClient):
    """Fails every update with a chosen Mist error."""

    def __init__(self, error: Exception) -> None:
        super().__init__()
        self.error = error

    async def update(self, definition, object_id, configuration, *, org_id, site_id):  # noqa: ARG002
        self.writes.append(("update", object_id))
        raise self.error


class _NoIdClient(_FakeClient):
    """Accepts every create but answers without the new object's id."""

    async def create(self, definition, configuration, *, org_id, site_id):  # noqa: ARG002
        self.writes.append(("create", str(configuration.get("name"))))
        return {"name": configuration.get("name")}


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


@pytest.mark.parametrize(
    ("field_path", "expected"),
    [("tag_uuid", []), ("map_id", ["Switch"])],
)
async def test_stale_reference_check_ignores_inventory_tags(
    monkeypatch: pytest.MonkeyPatch,
    field_path: str,
    expected: list[str],
) -> None:
    logical_id = PydanticObjectId()
    version = ObjectVersion.model_construct(
        id=PydanticObjectId(),
        organization_id=ORGANIZATION_ID,
        logical_object_id=logical_id,
        incarnation_id=PydanticObjectId(),
        version=1,
        event=VersionEvent.UPDATED,
        configuration={},
        configuration_hash="hash",
        references=[ObjectReference(target_mist_id="replaced-id", field_path=field_path)],
        is_deleted=False,
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    logical = LogicalObject.model_construct(
        id=logical_id,
        organization_id=ORGANIZATION_ID,
        scope="site",
        object_type="devices",
        source_key="device-1",
        current_mist_id="device-1",
        site_mist_id="site-1",
        name="Switch",
        is_deleted=False,
        current_version=1,
    )

    class MatchingQuery:
        async def to_list(self) -> list[ObjectVersion]:
            return [version]

    monkeypatch.setattr(ObjectVersion, "find", lambda *_args, **_kwargs: MatchingQuery())
    monkeypatch.setattr(
        ObjectVersion,
        "organization_id",
        ExpressionField("organization_id"),
        raising=False,
    )
    latest = AsyncMock(return_value=version)
    get_logical = AsyncMock(return_value=logical)
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_verification.latest_version",
        latest,
    )
    monkeypatch.setattr(LogicalObject, "get", get_logical)

    stale = await find_stale_references(ORGANIZATION_ID, {"replaced-id"})

    assert stale == expected
    if field_path == "tag_uuid":
        latest.assert_not_awaited()
        get_logical.assert_not_awaited()


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
def credential_clears(monkeypatch: pytest.MonkeyPatch) -> list[tuple[list[dict[str, object]], dict[str, object]]]:
    """Record every field-scoped write, filter and payload.

    Recorded rather than asserted inside the fake: the executor swallows any
    error raised by that write, so an assertion there could never fail a test.
    """
    calls: list[tuple[list[dict[str, object]], dict[str, object]]] = []

    class _Recorded:
        def __init__(self, filters: tuple) -> None:
            self.filters = filters

        async def update(self, change, *_args, **_kwargs) -> None:
            calls.append(([criterion.query for criterion in self.filters], change))

    monkeypatch.setattr(RestoreOperation, "find_one", lambda *filters, **_kwargs: _Recorded(filters))
    return calls


@pytest.fixture
def executed(
    monkeypatch: pytest.MonkeyPatch,
    credential_clears: list[tuple[list[dict[str, object]], dict[str, object]]],  # noqa: ARG001 - installs the write recorder
) -> list[tuple[RestoreStatus, tuple, tuple]]:
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
    monkeypatch.setattr(RestoreOperation, "id", ExpressionField("id"), raising=False)

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
    client: _FakeClient | None = None,
) -> tuple[RestoreExecutor, _StubNotifications, _StubVerifier, _FakeClient]:
    client = client or _FakeClient()
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
async def test_an_unconfirmed_write_leaves_the_restore_compensable(monkeypatch: pytest.MonkeyPatch) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    client = _FailingClient(MistMutationTransportError("Unable to reach Mist to update wlans", outcome_unknown=True))
    executor, notifications, _, _ = _run(monkeypatch, operation, verified=True, client=client)

    result = await executor.execute(OPERATION_ID)

    assert result.status is RestoreStatus.COMPENSATION_AVAILABLE
    assert result.actions[0].status is RestoreActionStatus.FAILED
    assert result.actions[0].outcome_unknown is True
    assert result.encrypted_delegated_credential is None
    assert len(notifications.failed) == 1


@pytest.mark.usefixtures("executed")
async def test_a_create_answered_without_an_id_is_unconfirmed(monkeypatch: pytest.MonkeyPatch) -> None:
    operation = _operation([_action(0, RestoreActionType.CREATE)])
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True, client=_NoIdClient())

    result = await executor.execute(OPERATION_ID)

    assert client.writes == [("create", "wlan-0")]
    assert result.status is RestoreStatus.COMPENSATION_AVAILABLE
    assert result.actions[0].status is RestoreActionStatus.FAILED
    assert result.actions[0].outcome_unknown is True
    assert result.encrypted_delegated_credential is None
    assert len(notifications.failed) == 1


async def test_a_lost_completion_notification_never_reopens_a_completed_restore(
    monkeypatch: pytest.MonkeyPatch,
    executed: list[tuple[RestoreStatus, tuple, tuple]],
) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    executor, notifications, _, _ = _run(monkeypatch, operation, verified=True)

    async def _notifier_down(**_kwargs) -> None:
        msg = "notification store unavailable"
        raise RuntimeError(msg)

    monkeypatch.setattr(notifications, "notify_restore_completed", _notifier_down)

    result = await executor.execute(OPERATION_ID)

    assert result.status is RestoreStatus.COMPLETED
    assert executed[-1][0] is RestoreStatus.COMPLETED
    assert result.encrypted_delegated_credential is None
    assert result.preflight_errors == []
    assert notifications.failed == []


async def test_a_failed_source_update_never_reopens_a_completed_compensation(
    monkeypatch: pytest.MonkeyPatch,
    executed: list[tuple[RestoreStatus, tuple, tuple]],
) -> None:
    async def _mark_fails(_organization_id, _operation_id) -> None:
        msg = "database unavailable"
        raise RuntimeError(msg)

    monkeypatch.setattr(RestoreExecutor, "_mark_compensated", staticmethod(_mark_fails))
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
    executor, notifications, _, _ = _run(monkeypatch, operation, verified=True, store=store)

    result = await executor.execute(OPERATION_ID)

    assert result.status is RestoreStatus.COMPENSATED
    assert executed[-1][0] is RestoreStatus.COMPENSATED
    assert result.encrypted_delegated_credential is None
    assert result.preflight_errors == []
    assert notifications.failed == []
    assert notifications.completed == [1]


@pytest.mark.usefixtures("executed")
async def test_a_rejected_first_write_fails_the_restore(monkeypatch: pytest.MonkeyPatch) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    client = _FailingClient(MistMutationStatusError("Mist failed to update wlans (400)", status_code=400))
    executor, notifications, _, _ = _run(monkeypatch, operation, verified=True, client=client)

    result = await executor.execute(OPERATION_ID)

    assert result.status is RestoreStatus.FAILED
    assert result.actions[0].outcome_unknown is False
    assert result.encrypted_delegated_credential is None
    assert notifications.failed == ["wlan-0: Mist failed to update wlans (400)"]


@pytest.mark.usefixtures("executed")
async def test_an_unexpected_error_after_a_write_still_ends_the_restore(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _database_gone(*_args, **_kwargs) -> None:
        msg = "connection reset"
        raise RuntimeError(msg)

    monkeypatch.setattr(RestoreExecutor, "_record_result", _database_gone)
    operation = _operation([_action(0, RestoreActionType.UPDATE), _action(1, RestoreActionType.UPDATE)])
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True)

    result = await executor.execute(OPERATION_ID)

    assert client.writes == [("update", "mist-0")]
    assert result.status is RestoreStatus.COMPENSATION_AVAILABLE
    assert result.actions[0].status is RestoreActionStatus.COMPLETED
    assert result.completed_at is not None
    assert result.encrypted_delegated_credential is None
    assert notifications.failed == ["Restore worker error (RuntimeError)"]
    assert "connection reset" not in " ".join(result.preflight_errors)


@pytest.mark.usefixtures("executed")
async def test_an_error_before_any_write_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _broken_snapshot(*_args, **_kwargs):
        msg = "store unavailable"
        raise RuntimeError(msg)

    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_executor.capture_safety_snapshot",
        _broken_snapshot,
    )
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True)

    result = await executor.execute(OPERATION_ID)

    assert client.writes == []
    assert result.status is RestoreStatus.FAILED
    assert result.encrypted_delegated_credential is None
    assert len(notifications.failed) == 1


@pytest.mark.usefixtures("executed")
async def test_a_credential_that_will_not_decrypt_fails_the_restore(monkeypatch: pytest.MonkeyPatch) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    operation.encrypted_delegated_credential = "broken"
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True)

    with pytest.raises(RestoreExecutionError, match="could not be decrypted"):
        await executor.execute(OPERATION_ID)

    assert client.writes == []
    assert operation.status is RestoreStatus.FAILED
    assert operation.encrypted_delegated_credential is None
    assert len(notifications.failed) == 1


@pytest.mark.usefixtures("executed")
async def test_a_mist_error_during_preflight_fails_and_notifies_once(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _unreachable_snapshot(*_args, **_kwargs):
        msg = "Unable to reach Mist to read wlans"
        raise MistMutationTransportError(msg)

    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_executor.capture_safety_snapshot",
        _unreachable_snapshot,
    )
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True)

    result = await executor.execute(OPERATION_ID)

    assert client.writes == []
    assert result.status is RestoreStatus.FAILED
    assert result.encrypted_delegated_credential is None
    assert notifications.failed == ["Unable to reach Mist to read wlans"]


@pytest.mark.usefixtures("executed")
async def test_an_expired_credential_fails_and_notifies(monkeypatch: pytest.MonkeyPatch) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    operation.delegated_credential_expires_at = datetime.now(UTC) - timedelta(minutes=1)
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True)

    with pytest.raises(RestoreExecutionError, match="has expired"):
        await executor.execute(OPERATION_ID)

    assert client.writes == []
    assert operation.status is RestoreStatus.FAILED
    assert operation.encrypted_delegated_credential is None
    assert len(notifications.failed) == 1


async def test_a_version_number_that_stays_taken_is_given_up_after_bounded_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lookups = 0

    async def _latest(_logical_id):
        nonlocal lookups
        lookups += 1
        return ObjectVersion.model_construct(version=lookups + 1)

    class _AlwaysTaken:
        async def insert(self) -> None:
            msg = "E11000 duplicate key"
            raise DuplicateKeyError(msg)

    monkeypatch.setattr("mist_config_guardian_backend.services.restore_executor.latest_version", _latest)

    with pytest.raises(DuplicateKeyError):
        await RestoreExecutor._insert_next_version(PydanticObjectId(), lambda _latest: _AlwaysTaken())  # noqa: SLF001

    assert lookups == 3


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


@pytest.mark.usefixtures("executed")
async def test_an_unconfirmed_delete_that_never_happened_is_not_recreated(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _mark(_organization_id, _operation_id) -> None:
        return

    monkeypatch.setattr(RestoreExecutor, "_mark_compensated", staticmethod(_mark))
    recreate = _action(0, RestoreActionType.CREATE)
    recreate.outcome_unknown = True
    entry = SafetySnapshotEntry(
        logical_object_id=recreate.logical_object_id,
        order=0,
        action=RestoreActionType.CREATE,
        scope="site",
        object_type="wlans",
        object_name="wlan-0",
        mist_object_id="mist-0",
        site_mist_id="site-a",
        existed=True,
    )

    async def _snapshot(*_args, **_kwargs):
        return [entry]

    monkeypatch.setattr("mist_config_guardian_backend.services.restore_executor.capture_safety_snapshot", _snapshot)
    store = _MemoryStateStore()
    await store.save(
        RestoreOperationState(
            organization_id=ORGANIZATION_ID,
            operation_id=OPERATION_ID,
            plan_hash="plan-hash",
            compensates_operation_id=SOURCE_OPERATION_ID,
        )
    )
    operation = _operation([recreate])
    executor, _, _, client = _run(monkeypatch, operation, verified=True, store=store)

    result = await executor.execute(OPERATION_ID)

    assert client.writes == []
    assert result.actions[0].status is RestoreActionStatus.SKIPPED


@pytest.mark.usefixtures("executed")
async def test_a_compensation_that_changes_nothing_fails_despite_inherited_unconfirmed_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recreate = _action(0, RestoreActionType.CREATE)
    rejected = _action(1, RestoreActionType.UPDATE)
    pending = _action(2, RestoreActionType.UPDATE)
    for action in (recreate, rejected, pending):
        action.outcome_unknown = True
    entry = SafetySnapshotEntry(
        logical_object_id=recreate.logical_object_id,
        order=0,
        action=RestoreActionType.CREATE,
        scope="site",
        object_type="wlans",
        object_name="wlan-0",
        mist_object_id="mist-0",
        site_mist_id="site-a",
        existed=True,
    )

    async def _snapshot(*_args, **_kwargs):
        return [entry]

    monkeypatch.setattr("mist_config_guardian_backend.services.restore_executor.capture_safety_snapshot", _snapshot)
    store = _MemoryStateStore()
    await store.save(
        RestoreOperationState(
            organization_id=ORGANIZATION_ID,
            operation_id=OPERATION_ID,
            plan_hash="plan-hash",
            compensates_operation_id=SOURCE_OPERATION_ID,
        )
    )
    operation = _operation([recreate, rejected, pending])
    client = _FailingClient(MistMutationStatusError("Mist failed to update wlans (400)", status_code=400))
    executor, notifications, _, _ = _run(monkeypatch, operation, verified=True, store=store, client=client)

    result = await executor.execute(OPERATION_ID)

    assert client.writes == [("update", "mist-1")]
    assert [action.status for action in result.actions] == [
        RestoreActionStatus.SKIPPED,
        RestoreActionStatus.FAILED,
        RestoreActionStatus.PENDING,
    ]
    assert result.actions[1].outcome_unknown is False
    assert result.status is RestoreStatus.FAILED
    assert result.encrypted_delegated_credential is None
    assert len(notifications.failed) == 1


@pytest.mark.usefixtures("executed")
async def test_an_unconfirmed_delete_that_did_happen_is_recreated(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _mark(_organization_id, _operation_id) -> None:
        return

    monkeypatch.setattr(RestoreExecutor, "_mark_compensated", staticmethod(_mark))
    recreate = _action(0, RestoreActionType.CREATE)
    recreate.outcome_unknown = True
    entry = SafetySnapshotEntry(
        logical_object_id=recreate.logical_object_id,
        order=0,
        action=RestoreActionType.CREATE,
        scope="site",
        object_type="wlans",
        object_name="wlan-0",
        mist_object_id="mist-0",
        site_mist_id="site-a",
        existed=False,
    )

    async def _snapshot(*_args, **_kwargs):
        return [entry]

    monkeypatch.setattr("mist_config_guardian_backend.services.restore_executor.capture_safety_snapshot", _snapshot)
    store = _MemoryStateStore()
    await store.save(
        RestoreOperationState(
            organization_id=ORGANIZATION_ID,
            operation_id=OPERATION_ID,
            plan_hash="plan-hash",
            compensates_operation_id=SOURCE_OPERATION_ID,
        )
    )
    operation = _operation([recreate])
    executor, _, verifier, client = _run(monkeypatch, operation, verified=True, store=store)

    result = await executor.execute(OPERATION_ID)

    assert client.writes == [("create", "wlan-0")]
    assert result.actions[0].status is RestoreActionStatus.COMPLETED
    assert set(verifier.applied) == {0}


@pytest.mark.usefixtures("executed")
async def test_the_worker_heartbeats_around_every_phase(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []

    async def _beat(self, operation) -> None:  # noqa: ARG001
        events.append("beat")

    async def _snapshot(*_args, **_kwargs):
        events.append("capture")
        return []

    monkeypatch.setattr(RestoreExecutor, "_heartbeat", _beat)
    monkeypatch.setattr("mist_config_guardian_backend.services.restore_executor.capture_safety_snapshot", _snapshot)
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    executor, _, verifier, client = _run(monkeypatch, operation, verified=True)
    original_update = client.update
    original_verify = verifier.verify

    async def _update(*args, **kwargs):
        events.append("write")
        return await original_update(*args, **kwargs)

    async def _verify(*args, **kwargs):
        events.append("verify")
        return await original_verify(*args, **kwargs)

    client.update = _update
    verifier.verify = _verify

    await executor.execute(OPERATION_ID)

    assert events == ["capture", "beat", "beat", "write", "beat", "verify"]


@pytest.mark.usefixtures("executed")
async def test_the_credential_is_cleared_in_the_database_when_the_terminal_state_is_not_saved(
    monkeypatch: pytest.MonkeyPatch,
    credential_clears: list[tuple[list[dict[str, object]], dict[str, object]]],
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def _database_gone(*_args, **_kwargs) -> None:
        msg = "connection reset"
        raise RuntimeError(msg)

    async def _save_until_terminal(self) -> None:
        # Progress writes succeed; the terminal write in _fail_unexpectedly is lost.
        if self.completed_at is not None:
            msg = "primary stepped down"
            raise RuntimeError(msg)

    monkeypatch.setattr(RestoreExecutor, "_record_result", _database_gone)
    monkeypatch.setattr(RestoreOperation, "save", _save_until_terminal)
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    executor, notifications, _, _ = _run(monkeypatch, operation, verified=True)

    with caplog.at_level(logging.ERROR, logger="mist_config_guardian_backend.services.restore_executor"):
        await executor.execute(OPERATION_ID)

    assert "restore_terminal_state_unsaved" in caplog.text
    assert credential_clears == [
        (
            [{"id": OPERATION_ID}],
            {"$set": {"encrypted_delegated_credential": None, "delegated_credential_expires_at": None}},
        )
    ]
    assert notifications.failed == ["Restore worker error (RuntimeError)"]
