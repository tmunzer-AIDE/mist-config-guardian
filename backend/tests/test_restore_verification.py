"""Post-restore verification and the execution progress it gates."""

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Self
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
    RestoreActionReason,
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
from mist_config_guardian_backend.services.restore_compensation import capture_safety_snapshot
from mist_config_guardian_backend.services.restore_executor import RestoreExecutionError, RestoreExecutor
from mist_config_guardian_backend.services.restore_identity import RestoreIdentityConflictError
from mist_config_guardian_backend.services.restore_lease import ANOTHER_RESTORE_RUNNING, MemoryRestoreLeaseStore
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
from mist_config_guardian_backend.snapshots.canonical import configuration_hash
from mist_config_guardian_backend.snapshots.registry import get_definition

if TYPE_CHECKING:
    from collections.abc import Callable

ORGANIZATION_ID = PydanticObjectId()
OPERATION_ID = PydanticObjectId()
SOURCE_OPERATION_ID = PydanticObjectId()
REQUESTER_ID = PydanticObjectId()
WLAN_DEFINITION = get_definition("site", "wlans")


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


def _reversal(
    order: int,
    action_type: RestoreActionType,
    *,
    configuration: dict[str, object] | None = None,
) -> RestoreAction:
    """A compensating action expecting the object to hold what ``_run`` seeds the fake Mist with."""
    assert WLAN_DEFINITION is not None
    reversal = _action(order, action_type, configuration=configuration)
    reversal.compensates_action_order = order
    if action_type is not RestoreActionType.CREATE:
        reversal.expected_current_hash = configuration_hash(
            reversal.protected_configuration, ignored_fields=WLAN_DEFINITION.ignored_fields
        )
    return reversal


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
    """A Mist mutation client whose reads reflect its own writes."""

    def __init__(self, readback: dict[str, dict[str, object] | None] | None = None) -> None:
        self.state: dict[str, dict[str, object]] = {
            key: dict(value) for key, value in (readback or {}).items() if value is not None
        }
        self.writes: list[tuple[str, str]] = []
        self.reads: list[tuple[str, str | None]] = []

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return

    async def create(self, definition, configuration, *, org_id, site_id):  # noqa: ARG002
        self.writes.append(("create", str(configuration.get("name"))))
        created = {"id": "new-uuid", **configuration}
        self.state["new-uuid"] = created
        return dict(created)

    async def update(self, definition, object_id, configuration, *, org_id, site_id):  # noqa: ARG002
        self.writes.append(("update", object_id))
        self.state[object_id] = {"id": object_id, **configuration}
        return dict(configuration)

    async def delete(self, definition, object_id, *, org_id, site_id) -> None:  # noqa: ARG002
        self.writes.append(("delete", object_id))
        self.state.pop(object_id, None)

    async def get_current(self, definition, object_id, *, org_id, site_id):  # noqa: ARG002
        self.reads.append((object_id, site_id))
        value = self.state.get(object_id)
        return None if value is None else dict(value)

    async def list_objects(self, definition, *, org_id, site_id):  # noqa: ARG002
        # Nothing else in this Mist carries the name of an object a plan creates.
        return []


def _snapshot_entries(client: _FakeClient, operation: RestoreOperation) -> list[SafetySnapshotEntry]:
    """What capture_safety_snapshot records against the fake's current state."""
    assert WLAN_DEFINITION is not None
    entries = []
    for action in operation.actions:
        live = client.state.get(action.current_mist_id)
        entries.append(
            SafetySnapshotEntry(
                logical_object_id=action.logical_object_id,
                order=action.order,
                action=action.action,
                scope=action.scope,
                object_type=action.object_type,
                object_name=action.object_name,
                mist_object_id=action.current_mist_id,
                site_mist_id=action.site_mist_id,
                existed=live is not None,
                configuration=dict(live or {}),
                configuration_hash=(
                    None if live is None else configuration_hash(live, ignored_fields=WLAN_DEFINITION.ignored_fields)
                ),
            )
        )
    return entries


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


async def test_read_after_write_accepts_a_secret_mist_returns_masked() -> None:
    operation = _operation(
        [_action(0, RestoreActionType.UPDATE, status=RestoreActionStatus.COMPLETED, resulting_mist_id="mist-0")]
    )
    client = _FakeClient({"mist-0": {"name": "wlan-0", "psk": "********", "modified_time": 9}})

    result = await _build_verifier().verify(
        client, _organization(), operation, id_map={}, applied={0: {"name": "wlan-0", "psk": "correct-horse"}}
    )

    assert result.checks[0].status == "ok"


async def test_read_after_write_ignores_server_fields_mist_adds_inside_a_written_value() -> None:
    operation = _operation(
        [_action(0, RestoreActionType.UPDATE, status=RestoreActionStatus.COMPLETED, resulting_mist_id="mist-0")]
    )
    client = _FakeClient({"mist-0": {"name": "wlan-0", "schedule": {"enabled": True, "modified_time": 9}}})

    result = await _build_verifier().verify(
        client, _organization(), operation, id_map={}, applied={0: {"name": "wlan-0", "schedule": {"enabled": True}}}
    )

    assert result.checks[0].status == "ok"


async def test_read_after_write_still_fails_on_a_secret_mist_stored_differently() -> None:
    operation = _operation(
        [_action(0, RestoreActionType.UPDATE, status=RestoreActionStatus.COMPLETED, resulting_mist_id="mist-0")]
    )
    client = _FakeClient({"mist-0": {"name": "wlan-0", "psk": "battery-staple"}})

    result = await _build_verifier().verify(
        client, _organization(), operation, id_map={}, applied={0: {"name": "wlan-0", "psk": "correct-horse"}}
    )

    assert result.checks[0].status == "failed"
    assert result.checks[0].detail == "Mist stored different values for psk"


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


async def test_read_after_write_reads_where_the_object_now_lives() -> None:
    action = _action(0, RestoreActionType.CREATE, status=RestoreActionStatus.COMPLETED, resulting_mist_id="new-uuid")
    action.resulting_site_mist_id = "site-b"
    client = _FakeClient({"new-uuid": {"name": "wlan-0", "enabled": True}})

    await _build_verifier().verify(
        client, _organization(), _operation([action]), id_map={}, applied={0: {"name": "wlan-0", "enabled": True}}
    )

    assert client.reads == [("new-uuid", "site-b")]


async def test_monitoring_reopens_at_the_site_the_object_now_lives_in() -> None:
    moved = _action(0, RestoreActionType.CREATE, status=RestoreActionStatus.COMPLETED, resulting_mist_id="new-uuid")
    moved.resulting_site_mist_id = "site-b"
    stayed = _action(1, RestoreActionType.UPDATE, status=RestoreActionStatus.COMPLETED, resulting_mist_id="mist-1")
    reopened: list[set[str]] = []

    async def _reopen(_organization_id, site_ids):
        reopened.append(set(site_ids))
        return []

    service = RestoreVerificationService(
        _MemoryStateStore(),
        stale_references=AsyncMock(return_value=[]),
        queue_snapshot=lambda _organization_id: None,
        reopen_monitoring=_reopen,
    )

    await service.verify(
        _FakeClient({"new-uuid": {"name": "wlan-0"}, "mist-1": {"name": "wlan-1"}}),
        _organization(),
        _operation([moved, stayed]),
        id_map={},
        applied={},
    )

    assert reopened == [{"site-a", "site-b"}]


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


class _UpdateResult:
    def __init__(self, matched_count: int) -> None:
        self.matched_count = matched_count
        self.modified_count = matched_count


class _StoredOperation:
    """The stored restore operation as the executor's field-scoped writes see it.

    Writes are recorded rather than asserted inside the fake: the executor
    swallows some write errors, so an assertion there could never fail a test.
    A write filtered on a status matches only while the stored status equals
    it, so setting ``status`` mid-run is how a test lets the janitor close a run.
    """

    def __init__(self) -> None:
        self.status: RestoreStatus | None = None
        self.writes: list[tuple[list[dict[str, object]], dict[str, object]]] = []
        self.saves: list[tuple[RestoreStatus, tuple, tuple]] = []
        self.documents: list[dict[str, object]] = []
        self.clears: list[tuple[list[dict[str, object]], dict[str, object]]] = []
        self.fault: Callable[[dict[str, object]], Exception | None] | None = None

    def heartbeats(self) -> list[tuple[list[dict[str, object]], dict[str, object]]]:
        return [(filters, change) for filters, change in self.writes if list(change["$set"]) == ["updated_at"]]

    def update(self, filters: list[dict[str, object]], change: dict[str, object]) -> _UpdateResult:
        self.writes.append((filters, change))
        if self.fault is not None and (error := self.fault(change)) is not None:
            raise error
        expected = next((criterion["status"] for criterion in filters if "status" in criterion), None)
        if expected is None:
            if len(filters) == 1:
                self.clears.append((filters, change))
            return _UpdateResult(1)
        if self.status is None:
            # The first guarded write finds the status the executor loaded.
            self.status = expected
        if self.status is not expected:
            return _UpdateResult(0)
        document = change["$set"]
        if "status" in document:
            self.status = document["status"]
            self.remember(document)
        return _UpdateResult(1)

    def remember(self, document: dict[str, object]) -> None:
        actions = document["actions"]
        self.saves.append(
            (
                document["status"],
                tuple(action["status"] for action in actions),
                tuple(action["resulting_mist_id"] for action in actions),
            )
        )
        self.documents.append(
            {
                "status": document["status"],
                "encrypted_delegated_credential": document["encrypted_delegated_credential"],
                "delegated_credential_expires_at": document["delegated_credential_expires_at"],
                "preflight_errors": list(document["preflight_errors"]),
            }
        )


@pytest.fixture
def stored(monkeypatch: pytest.MonkeyPatch) -> _StoredOperation:
    """Replace the operation collection with a recorder that honours status filters."""
    operation = _StoredOperation()

    class _Query:
        def __init__(self, filters: tuple) -> None:
            self.filters = [criterion.query for criterion in filters]

        async def update(self, change, *_args, **_kwargs) -> _UpdateResult:
            return operation.update(self.filters, change)

    async def _save(self) -> None:
        # Only an operation without an id is still saved whole.
        operation.remember(self.model_dump())

    for name in ("id", "status"):
        monkeypatch.setattr(RestoreOperation, name, ExpressionField(name), raising=False)
    monkeypatch.setattr(RestoreOperation, "find_one", lambda *filters, **_kwargs: _Query(filters))
    monkeypatch.setattr(RestoreOperation, "save", _save)
    return operation


@pytest.fixture
def credential_clears(stored: _StoredOperation) -> list[tuple[list[dict[str, object]], dict[str, object]]]:
    """Every write addressed by id alone, which is the credential clear."""
    return stored.clears


@pytest.fixture
def executed(
    monkeypatch: pytest.MonkeyPatch,
    stored: _StoredOperation,
) -> list[tuple[RestoreStatus, tuple, tuple]]:
    """Run the executor against fakes and record every persisted state."""

    async def _organization_get(_document_id, *_args, **_kwargs):
        return _organization()

    monkeypatch.setattr(Organization, "get", _organization_get)

    async def _no_record_result(*_args, **_kwargs) -> None:
        return

    monkeypatch.setattr(RestoreExecutor, "_record_result", _no_record_result)

    async def _snapshot(client, _organization, operation, *_args, **_kwargs):
        return _snapshot_entries(client, operation)

    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_executor.capture_safety_snapshot",
        _snapshot,
    )
    return stored.saves


@pytest.fixture
def persisted(
    stored: _StoredOperation,
    executed: list[tuple[RestoreStatus, tuple, tuple]],  # noqa: ARG001 - installs the fakes this recorder refines
) -> list[dict[str, object]]:
    """Record what every accepted document write persisted, the credential fields included."""
    return stored.documents


_CREDENTIAL_CLEARED = {"$set": {"encrypted_delegated_credential": None, "delegated_credential_expires_at": None}}


def _assert_failed_before_running(
    operation: RestoreOperation,
    reason: str,
    *,
    persisted: list[dict[str, object]],
    notifications: _StubNotifications,
    client: _FakeClient,
) -> None:
    """A failed preparation ends FAILED, credential-free, with one reason and one notification."""
    assert client.writes == []
    assert operation.status is RestoreStatus.FAILED
    assert operation.completed_at is not None
    assert operation.preflight_errors == [reason]
    assert operation.encrypted_delegated_credential is None
    assert operation.delegated_credential_expires_at is None
    assert notifications.failed == [reason]
    assert notifications.completed == []
    assert persisted[-1] == {
        "status": RestoreStatus.FAILED,
        "encrypted_delegated_credential": None,
        "delegated_credential_expires_at": None,
        "preflight_errors": [reason],
    }


def _run(  # noqa: PLR0913 - every fake the executor accepts is optional here
    monkeypatch: pytest.MonkeyPatch,
    operation: RestoreOperation,
    *,
    verified: bool,
    store: _MemoryStateStore | None = None,
    client: _FakeClient | None = None,
    heartbeat_interval_seconds: float = 60.0,
    leases: MemoryRestoreLeaseStore | None = None,
) -> tuple[RestoreExecutor, _StubNotifications, _StubVerifier, _FakeClient]:
    client = client or _FakeClient()
    for action in operation.actions:
        if action.action is not RestoreActionType.CREATE:
            client.state.setdefault(action.current_mist_id, dict(action.protected_configuration))
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
        heartbeat_interval_seconds=heartbeat_interval_seconds,
        leases=leases or MemoryRestoreLeaseStore(),
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


@pytest.mark.parametrize("status", [RestoreStatus.RUNNING, RestoreStatus.COMPLETED])
async def test_a_redelivered_task_refuses_to_apply_the_plan_twice_and_touches_nothing(
    monkeypatch: pytest.MonkeyPatch,
    persisted: list[dict[str, object]],
    credential_clears: list[tuple[list[dict[str, object]], dict[str, object]]],
    status: RestoreStatus,
) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE)], status=status)
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True)

    with pytest.raises(RestoreExecutionError, match="not ready to execute"):
        await executor.execute(OPERATION_ID)

    # The run that owns this operation is still in charge of it: the redelivery
    # must not close it, notify about it, or take its credential away.
    assert client.writes == []
    assert persisted == []
    assert credential_clears == []
    assert notifications.failed == []
    assert notifications.completed == []
    assert operation.status is status
    assert operation.preflight_errors == []
    assert operation.encrypted_delegated_credential is not None
    assert operation.delegated_credential_expires_at is not None


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
    operation = _operation([_reversal(0, RestoreActionType.UPDATE)])
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


async def test_a_credential_that_will_not_decrypt_fails_the_restore(
    monkeypatch: pytest.MonkeyPatch,
    persisted: list[dict[str, object]],
    credential_clears: list[tuple[list[dict[str, object]], dict[str, object]]],
) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    operation.encrypted_delegated_credential = "broken"
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True)

    with pytest.raises(RestoreExecutionError, match="could not be decrypted"):
        await executor.execute(OPERATION_ID)

    _assert_failed_before_running(
        operation,
        "Delegated Mist administrator credential could not be decrypted",
        persisted=persisted,
        notifications=notifications,
        client=client,
    )
    assert credential_clears == [([{"id": OPERATION_ID}], _CREDENTIAL_CLEARED)]


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


async def test_an_expired_credential_fails_and_notifies(
    monkeypatch: pytest.MonkeyPatch,
    persisted: list[dict[str, object]],
    credential_clears: list[tuple[list[dict[str, object]], dict[str, object]]],
) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    operation.delegated_credential_expires_at = datetime.now(UTC) - timedelta(minutes=1)
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True)

    with pytest.raises(RestoreExecutionError, match="expired before execution"):
        await executor.execute(OPERATION_ID)

    _assert_failed_before_running(
        operation,
        "Delegated Mist administrator credential expired before execution",
        persisted=persisted,
        notifications=notifications,
        client=client,
    )
    assert credential_clears == [([{"id": OPERATION_ID}], _CREDENTIAL_CLEARED)]


async def test_an_organization_deleted_after_authorization_fails_and_clears_the_credential(
    monkeypatch: pytest.MonkeyPatch,
    persisted: list[dict[str, object]],
    credential_clears: list[tuple[list[dict[str, object]], dict[str, object]]],
) -> None:
    async def _deleted(_document_id, *_args, **_kwargs):
        return None

    monkeypatch.setattr(Organization, "get", _deleted)
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True)

    with pytest.raises(RestoreExecutionError, match="organization not found"):
        await executor.execute(OPERATION_ID)

    _assert_failed_before_running(
        operation,
        "Restore organization not found",
        persisted=persisted,
        notifications=notifications,
        client=client,
    )
    assert credential_clears == [([{"id": OPERATION_ID}], _CREDENTIAL_CLEARED)]


async def test_an_operation_without_an_identifier_fails_and_clears_the_credential(
    monkeypatch: pytest.MonkeyPatch,
    persisted: list[dict[str, object]],
    credential_clears: list[tuple[list[dict[str, object]], dict[str, object]]],
) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE)], identifier=None)
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True)

    with pytest.raises(RestoreExecutionError, match="missing an identifier"):
        await executor.execute(OPERATION_ID)

    _assert_failed_before_running(
        operation,
        "Persisted restore operation is missing an identifier",
        persisted=persisted,
        notifications=notifications,
        client=client,
    )
    # Without an id there is no document to address with a field-scoped write;
    # the saved document itself carries the cleared credential.
    assert credential_clears == []


async def test_an_unexpected_error_while_preparing_still_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    persisted: list[dict[str, object]],
    credential_clears: list[tuple[list[dict[str, object]], dict[str, object]]],
) -> None:
    async def _database_gone(_document_id, *_args, **_kwargs):
        msg = "connection reset"
        raise RuntimeError(msg)

    monkeypatch.setattr(Organization, "get", _database_gone)
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True)

    result = await executor.execute(OPERATION_ID)

    _assert_failed_before_running(
        result,
        "Restore worker error (RuntimeError)",
        persisted=persisted,
        notifications=notifications,
        client=client,
    )
    assert credential_clears == [([{"id": OPERATION_ID}], _CREDENTIAL_CLEARED)]


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
    operation = _operation([_reversal(0, RestoreActionType.UPDATE)])
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
        action.compensates_action_order = action.order
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

    async def _snapshot(client, _organization, operation, *_args, **_kwargs):
        return [entry, *_snapshot_entries(client, operation)[1:]]

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


async def _compensating_store() -> _MemoryStateStore:
    store = _MemoryStateStore()
    await store.save(
        RestoreOperationState(
            organization_id=ORGANIZATION_ID,
            operation_id=OPERATION_ID,
            plan_hash="plan-hash",
            compensates_operation_id=SOURCE_OPERATION_ID,
        )
    )
    return store


class _RefusingOneClient(_FakeClient):
    """Applies every update except the one to a chosen object, which Mist refuses."""

    def __init__(self, refused: str) -> None:
        super().__init__()
        self.refused = refused

    async def update(self, definition, object_id, configuration, *, org_id, site_id):
        if object_id != self.refused:
            return await super().update(definition, object_id, configuration, org_id=org_id, site_id=site_id)
        self.writes.append(("update", object_id))
        msg = "Mist failed to update wlans (400)"
        raise MistMutationStatusError(msg, status_code=400)


@pytest.mark.usefixtures("executed")
async def test_a_compensation_that_stops_after_a_reversal_fails_and_leaves_the_restore_compensable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marked: list[PydanticObjectId] = []

    async def _mark(_organization_id, operation_id) -> None:
        marked.append(operation_id)

    monkeypatch.setattr(RestoreExecutor, "_mark_compensated", staticmethod(_mark))
    operation = _operation([_reversal(0, RestoreActionType.UPDATE), _reversal(1, RestoreActionType.UPDATE)])
    client = _RefusingOneClient("mist-1")
    store = await _compensating_store()
    executor, notifications, _, _ = _run(monkeypatch, operation, verified=True, store=store, client=client)

    result = await executor.execute(OPERATION_ID)

    assert client.writes == [("update", "mist-0"), ("update", "mist-1")]
    assert [action.status for action in result.actions] == [RestoreActionStatus.COMPLETED, RestoreActionStatus.FAILED]
    assert result.status is RestoreStatus.FAILED
    assert result.encrypted_delegated_credential is None
    # The restore it reverses is left as it was: still compensable, and planned again from there.
    assert marked == []
    assert notifications.failed == ["wlan-1: Mist failed to update wlans (400)"]


@pytest.mark.usefixtures("executed")
async def test_a_compensation_stopped_by_an_unexpected_error_after_a_write_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _database_gone(*_args, **_kwargs) -> None:
        msg = "connection reset"
        raise RuntimeError(msg)

    monkeypatch.setattr(RestoreExecutor, "_record_result", _database_gone)
    operation = _operation([_reversal(0, RestoreActionType.UPDATE), _reversal(1, RestoreActionType.UPDATE)])
    store = await _compensating_store()
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True, store=store)

    result = await executor.execute(OPERATION_ID)

    assert client.writes == [("update", "mist-0")]
    assert result.actions[0].status is RestoreActionStatus.COMPLETED
    assert result.status is RestoreStatus.FAILED
    assert notifications.failed == ["Restore worker error (RuntimeError)"]


@pytest.mark.usefixtures("executed")
async def test_a_compensation_that_fails_verification_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    operation = _operation([_reversal(0, RestoreActionType.UPDATE)])
    store = await _compensating_store()
    executor, notifications, _, _ = _run(monkeypatch, operation, verified=False, store=store)

    result = await executor.execute(OPERATION_ID)

    assert result.actions[0].status is RestoreActionStatus.COMPLETED
    assert result.status is RestoreStatus.FAILED
    assert len(notifications.failed) == 1


@pytest.mark.usefixtures("executed")
async def test_a_fix_made_after_the_failed_restore_stops_its_compensation_before_any_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert WLAN_DEFINITION is not None
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_executor.capture_safety_snapshot", capture_safety_snapshot
    )
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version", AsyncMock(return_value=None)
    )
    monkeypatch.setattr(ObjectVersion, "find_one", AsyncMock(return_value=None))
    written = {"name": "wlan-0", "enabled": True}
    revert = _reversal(0, RestoreActionType.UPDATE, configuration={"name": "wlan-0", "enabled": False})
    revert.expected_current_hash = configuration_hash(written, ignored_fields=WLAN_DEFINITION.ignored_fields)
    # Someone repaired the object by hand after the restore failed.
    client = _FakeClient({"mist-0": {**written, "vlan": 30}})
    store = await _compensating_store()
    executor, notifications, _, _ = _run(monkeypatch, _operation([revert]), verified=True, store=store, client=client)

    result = await executor.execute(OPERATION_ID)

    assert client.writes == []
    assert client.state["mist-0"]["vlan"] == 30
    assert result.status is RestoreStatus.FAILED
    assert result.actions[0].status is RestoreActionStatus.PENDING
    assert notifications.failed == ["wlan-0 changed after this plan was reviewed"]


@pytest.mark.usefixtures("executed")
async def test_a_reversal_already_back_in_its_earlier_state_is_skipped_and_never_counted_as_applied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert WLAN_DEFINITION is not None

    async def _mark(_organization_id, _operation_id) -> None:
        return

    monkeypatch.setattr(RestoreExecutor, "_mark_compensated", staticmethod(_mark))
    revert = _reversal(0, RestoreActionType.UPDATE, configuration={"name": "wlan-0", "enabled": False})
    revert.expected_current_hash = configuration_hash(
        {"name": "wlan-0", "enabled": True}, ignored_fields=WLAN_DEFINITION.ignored_fields
    )
    store = await _compensating_store()
    # ``_run`` seeds Mist with the action's own configuration: the reversal has nothing left to write.
    executor, notifications, verifier, client = _run(monkeypatch, _operation([revert]), verified=True, store=store)

    result = await executor.execute(OPERATION_ID)

    assert client.writes == []
    assert result.actions[0].status is RestoreActionStatus.SKIPPED
    assert verifier.applied == {}
    assert notifications.completed == [0]
    assert result.status is RestoreStatus.COMPENSATED


class _StickyDeleteClient(_FakeClient):
    """Accepts every delete, yet the object still reads back afterwards."""

    async def delete(self, definition, object_id, *, org_id, site_id) -> None:  # noqa: ARG002
        self.writes.append(("delete", object_id))


@pytest.mark.usefixtures("executed")
async def test_a_delete_mist_still_shows_afterwards_is_left_unconfirmed(monkeypatch: pytest.MonkeyPatch) -> None:
    operation = _operation([_action(0, RestoreActionType.DELETE), _action(1, RestoreActionType.UPDATE)])
    client = _StickyDeleteClient()
    executor, notifications, _, _ = _run(monkeypatch, operation, verified=True, client=client)

    result = await executor.execute(OPERATION_ID)

    assert client.writes == [("delete", "mist-0")]
    assert result.actions[0].status is RestoreActionStatus.FAILED
    assert result.actions[0].outcome_unknown is True
    assert result.actions[1].status is RestoreActionStatus.PENDING
    assert result.status is RestoreStatus.COMPENSATION_AVAILABLE
    assert notifications.failed == ["wlan-0: wlan-0 still exists in Mist after the delete"]


@pytest.mark.usefixtures("executed")
async def test_the_worker_heartbeats_around_every_phase(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []

    async def _beat(self, operation) -> None:  # noqa: ARG001
        events.append("beat")

    async def _snapshot(client, _organization, operation, *_args, **_kwargs):
        return events.append("capture") or _snapshot_entries(client, operation)

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
    stored: _StoredOperation,
    credential_clears: list[tuple[list[dict[str, object]], dict[str, object]]],
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def _database_gone(*_args, **_kwargs) -> None:
        msg = "connection reset"
        raise RuntimeError(msg)

    def _terminal_write_lost(change: dict[str, object]) -> Exception | None:
        # Progress writes succeed; the terminal write in _close_failed is lost.
        if change["$set"].get("completed_at") is not None:
            return RuntimeError("primary stepped down")
        return None

    monkeypatch.setattr(RestoreExecutor, "_record_result", _database_gone)
    stored.fault = _terminal_write_lost
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


# ------------------------------------------------------------- per-write guard


@pytest.mark.usefixtures("executed")
async def test_an_object_changed_after_the_safety_snapshot_is_not_overwritten(monkeypatch: pytest.MonkeyPatch) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE), _action(1, RestoreActionType.UPDATE)])
    executor, _, _, client = _run(monkeypatch, operation, verified=True)
    original_update = client.update

    async def _update_while_someone_edits(definition, object_id, configuration, *, org_id, site_id):
        result = await original_update(definition, object_id, configuration, org_id=org_id, site_id=site_id)
        client.state["mist-1"] = {"name": "wlan-1", "enabled": False}
        return result

    client.update = _update_while_someone_edits

    result = await executor.execute(OPERATION_ID)

    assert client.writes == [("update", "mist-0")]
    assert result.status is RestoreStatus.COMPENSATION_AVAILABLE
    assert result.actions[1].status is RestoreActionStatus.FAILED
    assert "changed in Mist after the pre-restore safety snapshot" in (result.actions[1].error or "")


@pytest.mark.usefixtures("executed")
async def test_each_write_is_read_back_and_its_fingerprint_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    assert WLAN_DEFINITION is not None
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    executor, _, _, client = _run(monkeypatch, operation, verified=True)

    result = await executor.execute(OPERATION_ID)

    assert result.actions[0].applied_hash == configuration_hash(
        client.state["mist-0"], ignored_fields=WLAN_DEFINITION.ignored_fields
    )


@pytest.mark.usefixtures("executed")
async def test_a_write_mist_does_not_show_afterwards_stops_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE), _action(1, RestoreActionType.UPDATE)])
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True)
    original_update = client.update

    async def _update_then_vanish(definition, object_id, configuration, *, org_id, site_id):
        result = await original_update(definition, object_id, configuration, org_id=org_id, site_id=site_id)
        client.state.pop(object_id)
        return result

    client.update = _update_then_vanish

    result = await executor.execute(OPERATION_ID)

    assert client.writes == [("update", "mist-0")]
    assert result.actions[0].status is RestoreActionStatus.COMPLETED
    assert result.status is RestoreStatus.COMPENSATION_AVAILABLE
    assert "was not found in Mist after the write" in notifications.failed[0]


@pytest.mark.usefixtures("executed")
async def test_an_identity_conflict_after_the_write_stops_the_run_as_compensable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _conflict(*_args, **_kwargs) -> None:
        msg = "another recorded identity already owns this object's key; history needs manual review"
        raise RestoreIdentityConflictError(msg)

    monkeypatch.setattr(RestoreExecutor, "_record_result", _conflict)
    operation = _operation([_action(0, RestoreActionType.UPDATE), _action(1, RestoreActionType.UPDATE)])
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True)

    result = await executor.execute(OPERATION_ID)

    assert client.writes == [("update", "mist-0")]
    assert result.actions[0].status is RestoreActionStatus.COMPLETED
    assert "already owns" in (result.actions[0].error or "")
    assert result.actions[1].status is RestoreActionStatus.PENDING
    assert result.status is RestoreStatus.COMPENSATION_AVAILABLE
    assert result.encrypted_delegated_credential is None
    assert len(notifications.failed) == 1


@pytest.mark.usefixtures("executed")
async def test_a_deleted_site_is_restored_together_with_its_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """The settings cannot be read before the site exists, so they are read at the new site, right before the write."""
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_executor.capture_safety_snapshot",
        capture_safety_snapshot,
    )
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version",
        AsyncMock(return_value=None),
    )
    site = RestoreAction(
        logical_object_id=PydanticObjectId(),
        source_version_id=PydanticObjectId(),
        order=0,
        action=RestoreActionType.CREATE,
        scope="org",
        object_type="sites",
        object_name="Lab",
        current_mist_id="site-old",
        protected_configuration={"name": "Lab"},
    )
    settings = RestoreAction(
        logical_object_id=PydanticObjectId(),
        source_version_id=PydanticObjectId(),
        order=1,
        action=RestoreActionType.UPDATE,
        scope="site",
        object_type="settings",
        object_name="Lab settings",
        current_mist_id="site-old:settings",
        site_mist_id="site-old",
        protected_configuration={"vlan": 5},
        expected_current_hash="plan-time-hash-of-the-deleted-site",
    )
    store = _MemoryStateStore()
    operation = _operation([site, settings])
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True, store=store)

    result = await executor.execute(OPERATION_ID)

    assert notifications.failed == []
    assert result.status is RestoreStatus.COMPLETED
    assert client.writes == [("create", "Lab"), ("update", "site-old:settings")]
    # Before the write at the new site, then the read-back of that write.
    assert client.reads.count(("site-old:settings", "new-uuid")) == 2
    assert ("site-old:settings", "site-old") not in client.reads
    state = await store.load(ORGANIZATION_ID, OPERATION_ID)
    assert state is not None
    assert [(entry.order, entry.site_mist_id) for entry in state.safety_snapshot] == [(0, None), (1, "new-uuid")]


@pytest.mark.usefixtures("executed")
async def test_an_older_version_referencing_a_recreated_object_is_written_with_the_new_uuid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A version chosen for restore stays an ordinary update, yet still points at the object recreated before it."""
    old_network = "8aa21779-1178-4357-b3e0-42c02b93b870"
    network = RestoreAction(
        logical_object_id=PydanticObjectId(),
        source_version_id=PydanticObjectId(),
        order=0,
        action=RestoreActionType.CREATE,
        scope="org",
        object_type="networks",
        object_name="Corp",
        current_mist_id=old_network,
        protected_configuration={"name": "Corp"},
    )
    wlan = _action(1, RestoreActionType.UPDATE, configuration={"name": "wlan-1", "network_id": old_network})
    wlan.depends_on = [network.logical_object_id]
    operation = _operation([network, wlan])
    executor, notifications, verifier, client = _run(monkeypatch, operation, verified=True)

    result = await executor.execute(OPERATION_ID)

    assert notifications.failed == []
    assert result.status is RestoreStatus.COMPLETED
    assert wlan.reason is RestoreActionReason.RESTORE
    assert client.writes == [("create", "Corp"), ("update", "mist-1")]
    assert verifier.id_map == {old_network: "new-uuid"}
    assert verifier.applied[1] == {"name": "wlan-1", "network_id": "new-uuid"}
    assert client.state["mist-1"]["network_id"] == "new-uuid"


# ------------------------------------------------------------------- ownership

_EXECUTOR_LOGGER = "mist_config_guardian_backend.services.restore_executor"


class _ClosingClient(_FakeClient):
    """Applies the write while the janitor closes the run, as a slow Mist call allows."""

    def __init__(self, stored: _StoredOperation) -> None:
        super().__init__()
        self.stored = stored

    async def update(self, definition, object_id, configuration, *, org_id, site_id):
        self.stored.status = RestoreStatus.COMPENSATION_AVAILABLE
        return await super().update(definition, object_id, configuration, org_id=org_id, site_id=site_id)


@pytest.mark.usefixtures("executed")
async def test_the_heartbeat_writes_only_the_timestamp_of_a_run_it_still_owns(
    monkeypatch: pytest.MonkeyPatch,
    stored: _StoredOperation,
) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    executor, _, _, _ = _run(monkeypatch, operation, verified=True)

    await executor.execute(OPERATION_ID)

    beats = stored.heartbeats()
    assert len(beats) == 3
    for filters, change in beats:
        assert filters == [{"id": OPERATION_ID}, {"status": RestoreStatus.RUNNING}]
        assert isinstance(change["$set"]["updated_at"], datetime)


@pytest.mark.parametrize("closed_during", ["snapshot", "write"])
async def test_a_run_the_janitor_closed_stops_without_another_mist_write_or_notification(
    monkeypatch: pytest.MonkeyPatch,
    executed: list[tuple[RestoreStatus, tuple, tuple]],
    stored: _StoredOperation,
    caplog: pytest.LogCaptureFixture,
    closed_during: str,
) -> None:
    async def _snapshot(client, _organization, operation, *_args, **_kwargs):
        if closed_during == "snapshot":
            stored.status = RestoreStatus.COMPENSATION_AVAILABLE
        return _snapshot_entries(client, operation)

    monkeypatch.setattr("mist_config_guardian_backend.services.restore_executor.capture_safety_snapshot", _snapshot)
    operation = _operation([_action(0, RestoreActionType.UPDATE), _action(1, RestoreActionType.UPDATE)])
    client = _ClosingClient(stored) if closed_during == "write" else _FakeClient()
    executor, notifications, _, _ = _run(monkeypatch, operation, verified=True, client=client)

    with caplog.at_level(logging.WARNING, logger=_EXECUTOR_LOGGER):
        await executor.execute(OPERATION_ID)

    assert client.writes == ([] if closed_during == "snapshot" else [("update", "mist-0")])
    assert notifications.failed == []
    assert notifications.completed == []
    # Nothing after the close was accepted: every accepted write is still a running one.
    assert executed
    assert {entry[0] for entry in executed} == {RestoreStatus.RUNNING}
    assert stored.status is RestoreStatus.COMPENSATION_AVAILABLE
    assert stored.clears == [([{"id": OPERATION_ID}], _CREDENTIAL_CLEARED)]
    assert "restore_ownership_lost" in caplog.text


@pytest.mark.usefixtures("executed")
async def test_the_background_heartbeat_keeps_a_long_phase_alive_until_ownership_is_lost(
    monkeypatch: pytest.MonkeyPatch,
    stored: _StoredOperation,
    caplog: pytest.LogCaptureFixture,
) -> None:
    beats_while_owned = 0

    async def _long_snapshot(client, _organization, operation, *_args, **_kwargs):
        nonlocal beats_while_owned
        await asyncio.sleep(0.05)
        beats_while_owned = len(stored.heartbeats())
        stored.status = RestoreStatus.COMPENSATION_AVAILABLE
        await asyncio.sleep(0.05)
        return _snapshot_entries(client, operation)

    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_executor.capture_safety_snapshot", _long_snapshot
    )
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True, heartbeat_interval_seconds=0.01)

    with caplog.at_level(logging.WARNING, logger=_EXECUTOR_LOGGER):
        await executor.execute(OPERATION_ID)

    assert beats_while_owned >= 2
    # One beat finds the run closed and the beating stops; the flow's next write refuses without writing.
    assert len(stored.heartbeats()) == beats_while_owned + 1
    assert "restore_heartbeat_ownership_lost" in caplog.text
    assert client.writes == []
    assert notifications.failed == []


@pytest.mark.usefixtures("executed")
async def test_the_background_heartbeat_ends_with_the_run(
    monkeypatch: pytest.MonkeyPatch,
    stored: _StoredOperation,
) -> None:
    async def _long_snapshot(client, _organization, operation, *_args, **_kwargs):
        await asyncio.sleep(0.03)
        return _snapshot_entries(client, operation)

    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_executor.capture_safety_snapshot", _long_snapshot
    )
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    executor, _, _, _ = _run(monkeypatch, operation, verified=True, heartbeat_interval_seconds=0.01)

    result = await executor.execute(OPERATION_ID)
    after_run = len(stored.writes)
    await asyncio.sleep(0.05)

    assert result.status is RestoreStatus.COMPLETED
    assert len(stored.writes) == after_run


@pytest.mark.usefixtures("executed")
async def test_a_failing_background_heartbeat_is_logged_by_type_and_keeps_beating(
    monkeypatch: pytest.MonkeyPatch,
    stored: _StoredOperation,
    caplog: pytest.LogCaptureFixture,
) -> None:
    def _heartbeat_write_fails(change: dict[str, object]) -> Exception | None:
        if list(change["$set"]) == ["updated_at"]:
            return RuntimeError("configuration content in a driver message")
        return None

    async def _long_snapshot(client, _organization, operation, *_args, **_kwargs):
        stored.fault = _heartbeat_write_fails
        await asyncio.sleep(0.05)
        stored.fault = None
        return _snapshot_entries(client, operation)

    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_executor.capture_safety_snapshot", _long_snapshot
    )
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    executor, _, _, _ = _run(monkeypatch, operation, verified=True, heartbeat_interval_seconds=0.01)

    with caplog.at_level(logging.ERROR, logger=_EXECUTOR_LOGGER):
        result = await executor.execute(OPERATION_ID)

    assert result.status is RestoreStatus.COMPLETED
    assert caplog.text.count("restore_heartbeat_failed") >= 2
    assert "error_type=RuntimeError" in caplog.text
    assert "configuration content" not in caplog.text


# ----------------------------------------------------------------------- lease

_LEASE_TTL = timedelta(minutes=15)


class _RecordingLeases(MemoryRestoreLeaseStore):
    """Records each lease call with the stored status it found, so its order against the claim is visible."""

    def __init__(self, stored: _StoredOperation | None = None) -> None:
        super().__init__()
        self.stored = stored
        self.calls: list[tuple[str, RestoreStatus | None]] = []

    def _record(self, name: str) -> None:
        self.calls.append((name, None if self.stored is None else self.stored.status))

    async def acquire(self, organization_id, operation_id, *, ttl):
        self._record("acquire")
        return await super().acquire(organization_id, operation_id, ttl=ttl)

    async def renew(self, organization_id, operation_id, *, ttl):
        self._record("renew")
        return await super().renew(organization_id, operation_id, ttl=ttl)

    async def release(self, organization_id, operation_id):
        self._record("release")
        await super().release(organization_id, operation_id)


class _LostLeases(MemoryRestoreLeaseStore):
    """Another restore took the organization over: no renewal succeeds."""

    async def renew(self, organization_id, operation_id, *, ttl):  # noqa: ARG002
        return False


class _SessionClient(_FakeClient):
    """Counts closes, which is when a session credential is logged out of Mist."""

    def __init__(self) -> None:
        super().__init__()
        self.closed = 0

    async def __aexit__(self, *_args: object) -> None:
        self.closed += 1


@pytest.mark.usefixtures("executed")
async def test_a_second_restore_for_the_organization_fails_without_writing(monkeypatch: pytest.MonkeyPatch) -> None:
    leases = MemoryRestoreLeaseStore()
    running = PydanticObjectId()
    await leases.acquire(ORGANIZATION_ID, running, ttl=_LEASE_TTL)
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    client = _SessionClient()
    executor, notifications, _, _ = _run(monkeypatch, operation, verified=True, leases=leases, client=client)

    result = await executor.execute(OPERATION_ID)

    assert client.writes == []
    assert result.status is RestoreStatus.FAILED
    assert ANOTHER_RESTORE_RUNNING in result.preflight_errors
    assert result.encrypted_delegated_credential is None
    assert notifications.failed == [ANOTHER_RESTORE_RUNNING]
    # The refused credential is logged out, and the running restore keeps its lease.
    assert client.closed == 1
    assert await leases.renew(ORGANIZATION_ID, running, ttl=_LEASE_TTL) is True


@pytest.mark.parametrize("outcome", [RestoreStatus.COMPLETED, RestoreStatus.COMPENSATION_AVAILABLE])
@pytest.mark.usefixtures("executed")
async def test_the_lease_is_released_when_the_run_ends(monkeypatch: pytest.MonkeyPatch, outcome: RestoreStatus) -> None:
    leases = MemoryRestoreLeaseStore()
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    client = (
        _FakeClient()
        if outcome is RestoreStatus.COMPLETED
        else _FailingClient(MistMutationTransportError("Unable to reach Mist to update wlans", outcome_unknown=True))
    )
    executor, _, _, _ = _run(monkeypatch, operation, verified=True, leases=leases, client=client)

    result = await executor.execute(OPERATION_ID)

    assert result.status is outcome
    assert await leases.acquire(ORGANIZATION_ID, PydanticObjectId(), ttl=_LEASE_TTL) is True


@pytest.mark.usefixtures("executed")
async def test_the_lease_is_taken_after_the_claim_renewed_by_every_heartbeat_and_released_last(
    monkeypatch: pytest.MonkeyPatch,
    stored: _StoredOperation,
) -> None:
    leases = _RecordingLeases(stored)
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    executor, _, _, _ = _run(monkeypatch, operation, verified=True, leases=leases)

    result = await executor.execute(OPERATION_ID)

    assert result.status is RestoreStatus.COMPLETED
    assert len(stored.heartbeats()) == 3
    assert leases.calls == [
        ("acquire", RestoreStatus.RUNNING),
        ("renew", RestoreStatus.RUNNING),
        ("renew", RestoreStatus.RUNNING),
        ("renew", RestoreStatus.RUNNING),
        ("release", RestoreStatus.COMPLETED),
    ]


@pytest.mark.usefixtures("executed")
async def test_a_lost_lease_stops_before_the_next_write_and_leaves_the_close_to_the_janitor(
    monkeypatch: pytest.MonkeyPatch,
    stored: _StoredOperation,
    caplog: pytest.LogCaptureFixture,
) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True, leases=_LostLeases())

    with caplog.at_level(logging.WARNING, logger=_EXECUTOR_LOGGER):
        result = await executor.execute(OPERATION_ID)

    assert client.writes == []
    # No terminal write and no alert: the janitor, or the restore now holding
    # the organization, owns this run's close.
    assert result.status is RestoreStatus.RUNNING
    assert {entry[0] for entry in stored.saves} == {RestoreStatus.RUNNING}
    assert stored.status is RestoreStatus.RUNNING
    # The failed renewal does not refresh the run, so the janitor closes it on schedule.
    assert stored.heartbeats() == []
    assert notifications.failed == []
    assert notifications.completed == []
    assert stored.clears == [([{"id": OPERATION_ID}], _CREDENTIAL_CLEARED)]
    assert "restore_lease_lost" in caplog.text


@pytest.mark.usefixtures("executed")
async def test_a_lease_taken_over_during_a_long_phase_stops_the_run_and_spares_the_new_holder(
    monkeypatch: pytest.MonkeyPatch,
    stored: _StoredOperation,
    caplog: pytest.LogCaptureFixture,
) -> None:
    leases = MemoryRestoreLeaseStore()
    successor = PydanticObjectId()
    beats_while_held = 0

    async def _long_snapshot(client, _organization, operation, *_args, **_kwargs):
        nonlocal beats_while_held
        await asyncio.sleep(0.05)
        beats_while_held = len(stored.heartbeats())
        # The lease lapsed while this worker was silent, and the next restore took it.
        await leases.release(ORGANIZATION_ID, OPERATION_ID)
        await leases.acquire(ORGANIZATION_ID, successor, ttl=_LEASE_TTL)
        await asyncio.sleep(0.05)
        return _snapshot_entries(client, operation)

    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_executor.capture_safety_snapshot", _long_snapshot
    )
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    executor, notifications, _, client = _run(
        monkeypatch, operation, verified=True, leases=leases, heartbeat_interval_seconds=0.01
    )

    with caplog.at_level(logging.WARNING, logger=_EXECUTOR_LOGGER):
        await executor.execute(OPERATION_ID)

    assert beats_while_held >= 2
    # The beat that finds the lease gone writes nothing and stops; the flow's next write refuses.
    assert len(stored.heartbeats()) == beats_while_held
    assert "restore_heartbeat_lease_lost" in caplog.text
    assert client.writes == []
    assert notifications.failed == []
    assert {entry[0] for entry in stored.saves} == {RestoreStatus.RUNNING}
    assert await leases.renew(ORGANIZATION_ID, successor, ttl=_LEASE_TTL) is True


@pytest.mark.parametrize("lost_at", ["claim", "preparation"])
async def test_a_delivery_another_delivery_beat_to_the_operation_touches_nothing(
    monkeypatch: pytest.MonkeyPatch,
    persisted: list[dict[str, object]],
    stored: _StoredOperation,
    credential_clears: list[tuple[list[dict[str, object]], dict[str, object]]],
    lost_at: str,
) -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE)])
    if lost_at == "preparation":
        # This delivery ran just past the credential's expiry; the other claimed the run just before it.
        operation.delegated_credential_expires_at = datetime.now(UTC) - timedelta(minutes=1)
    leases = _RecordingLeases()
    executor, notifications, _, client = _run(monkeypatch, operation, verified=True, leases=leases)
    # Both deliveries loaded the operation while it was queued; the other one claimed it first.
    stored.status = RestoreStatus.RUNNING

    if lost_at == "claim":
        await executor.execute(OPERATION_ID)
    else:
        with pytest.raises(RestoreExecutionError, match="expired before execution"):
            await executor.execute(OPERATION_ID)

    # The winner's run, lease, credential and alerts are all left to the winner.
    assert client.writes == []
    assert persisted == []
    assert credential_clears == []
    assert leases.calls == []
    assert notifications.failed == []
    assert notifications.completed == []
    assert stored.status is RestoreStatus.RUNNING
