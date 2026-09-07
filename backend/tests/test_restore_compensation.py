"""Safety snapshots, compensating plans, and their credential requirements."""

from datetime import UTC, datetime

import httpx
import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.api.dependencies import get_current_user, require_organization
from mist_config_guardian_backend.api.routes.approvals import get_approval_service
from mist_config_guardian_backend.api.routes.restores import (
    get_plan_state_store,
    get_restore_compensation_service,
    get_restore_plans,
)
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.integrations.mist_mutation import MistMutationError
from mist_config_guardian_backend.main import create_app
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
from mist_config_guardian_backend.models.snapshot import ObjectVersion
from mist_config_guardian_backend.models.user import User, UserRole
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.approvals import ApprovalService, compute_plan_hash
from mist_config_guardian_backend.services.mfa import require_fresh_mfa
from mist_config_guardian_backend.services.restore_compensation import (
    RestoreCompensationError,
    RestoreCompensationService,
    capture_safety_snapshot,
)
from mist_config_guardian_backend.services.restore_planner import RestoreOperationState
from mist_config_guardian_backend.snapshots.canonical import configuration_hash
from mist_config_guardian_backend.snapshots.secrets import is_protected

ORGANIZATION_ID = PydanticObjectId()
OPERATION_ID = PydanticObjectId()
COMPENSATION_ID = PydanticObjectId()
ADMINISTRATOR_ID = PydanticObjectId()

CORP_WLAN = {"name": "Corp", "psk": "super-secret", "enabled": True}
GUEST_WLAN = {"name": "Guest", "enabled": False}


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
    expected_current_hash: str | None = None,
    resulting_mist_id: str | None = None,
    status: RestoreActionStatus = RestoreActionStatus.PENDING,
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
        protected_configuration={"name": f"wlan-{order}"},
        expected_current_hash=expected_current_hash,
        status=status,
        resulting_mist_id=resulting_mist_id,
    )


def _operation(
    actions: list[RestoreAction],
    *,
    status: RestoreStatus = RestoreStatus.COMPENSATION_AVAILABLE,
    identifier: PydanticObjectId = OPERATION_ID,
) -> RestoreOperation:
    return RestoreOperation.model_construct(
        id=identifier,
        organization_id=ORGANIZATION_ID,
        requested_by=ADMINISTRATOR_ID,
        mode=RestoreMode.NON_DESTRUCTIVE,
        include_dependencies=True,
        target_at=datetime(2026, 1, 1, tzinfo=UTC),
        status=status,
        actions=actions,
        warnings=[],
        preflight_errors=[],
        credential_actor="admin@example.com",
        started_at=None,
        completed_at=None,
        failure_action_order=None,
        task_id=None,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        updated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


class _FakeMistClient:
    """Returns canned live state for every plan target."""

    def __init__(self, live: dict[str, dict[str, object] | None]) -> None:
        self.live = live
        self.reads: list[str] = []

    async def get_current(self, definition, object_id, *, org_id, site_id):  # noqa: ARG002
        self.reads.append(object_id)
        return self.live.get(object_id)


class _MemoryStateStore:
    """In-memory plan-lifecycle state keyed the same way MongoDB keys it."""

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


@pytest.fixture
def offline_documents(monkeypatch: pytest.MonkeyPatch) -> None:
    """Let restore documents be built and inserted without a live MongoDB."""
    monkeypatch.setattr(RestoreOperation, "get_pymongo_collection", classmethod(lambda cls: None))  # noqa: ARG005

    async def _insert(self, *_args, **_kwargs):
        self.id = COMPENSATION_ID
        return self

    monkeypatch.setattr(RestoreOperation, "insert", _insert)

    async def _version(_document_id, *_args, **_kwargs):
        return None

    monkeypatch.setattr(ObjectVersion, "get", _version)


# ------------------------------------------------------------- safety snapshot


async def test_safety_snapshot_records_the_pre_restore_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version",
        _no_stored_version,
    )
    corp_hash = configuration_hash(CORP_WLAN, ignored_fields=frozenset({"created_time", "modified_time", "last_seen"}))
    operation = _operation(
        [
            _action(0, RestoreActionType.CREATE),
            _action(1, RestoreActionType.UPDATE, expected_current_hash=corp_hash),
        ]
    )
    client = _FakeMistClient({"mist-1": dict(CORP_WLAN)})

    entries = await capture_safety_snapshot(client, _organization(), operation, _vault())

    assert [entry.existed for entry in entries] == [False, True]
    assert entries[0].configuration == {}
    assert entries[1].configuration["name"] == "Corp"
    assert is_protected(entries[1].configuration["psk"])
    assert "super-secret" not in str(entries[1].configuration)
    assert entries[1].configuration_hash == corp_hash


async def test_a_changed_live_object_aborts_before_any_write(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version",
        _no_stored_version,
    )
    operation = _operation([_action(0, RestoreActionType.UPDATE, expected_current_hash="stale-hash")])
    client = _FakeMistClient({"mist-0": dict(CORP_WLAN)})

    with pytest.raises(MistMutationError, match="changed after this plan was reviewed"):
        await capture_safety_snapshot(client, _organization(), operation, _vault())


async def test_a_deleted_live_object_aborts_before_any_write(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version",
        _no_stored_version,
    )
    operation = _operation([_action(0, RestoreActionType.UPDATE, expected_current_hash="any")])

    with pytest.raises(MistMutationError, match="no longer exists"):
        await capture_safety_snapshot(_FakeMistClient({}), _organization(), operation, _vault())


async def test_relaxed_capture_accepts_the_state_a_restore_already_replaced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version",
        _no_stored_version,
    )
    operation = _operation([_action(0, RestoreActionType.UPDATE, expected_current_hash=None)])
    client = _FakeMistClient({"mist-0": dict(GUEST_WLAN)})

    entries = await capture_safety_snapshot(client, _organization(), operation, _vault(), relaxed=True)

    assert entries[0].existed is True


async def _no_stored_version(_logical_id):
    return None


# --------------------------------------------------------------- compensation


def _snapshot_state(entries) -> RestoreOperationState:
    return RestoreOperationState(
        organization_id=ORGANIZATION_ID,
        operation_id=OPERATION_ID,
        plan_hash="plan-hash",
        safety_snapshot=entries,
    )


async def _applied_plan(monkeypatch: pytest.MonkeyPatch) -> tuple[RestoreOperation, _MemoryStateStore]:
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version",
        _no_stored_version,
    )
    actions = [
        _action(0, RestoreActionType.CREATE, status=RestoreActionStatus.COMPLETED, resulting_mist_id="new-uuid"),
        _action(1, RestoreActionType.UPDATE, status=RestoreActionStatus.COMPLETED, resulting_mist_id="mist-1"),
        _action(2, RestoreActionType.DELETE, status=RestoreActionStatus.COMPLETED, resulting_mist_id=None),
        _action(3, RestoreActionType.UPDATE, status=RestoreActionStatus.PENDING),
    ]
    operation = _operation(actions)
    client = _FakeMistClient({"mist-1": dict(CORP_WLAN), "mist-2": dict(GUEST_WLAN), "mist-3": dict(GUEST_WLAN)})
    for action in actions:
        if action.action is not RestoreActionType.CREATE:
            action.expected_current_hash = None
    entries = await capture_safety_snapshot(client, _organization(), operation, _vault(), relaxed=True)
    store = _MemoryStateStore()
    await store.save(_snapshot_state(entries))
    return operation, store


@pytest.mark.usefixtures("offline_documents")
async def test_compensation_inverts_applied_actions_in_reverse_order(monkeypatch: pytest.MonkeyPatch) -> None:
    operation, store = await _applied_plan(monkeypatch)

    plan = await RestoreCompensationService(store).create_compensation_plan(
        operation=operation,
        requested_by=ADMINISTRATOR_ID,
    )

    assert [action.order for action in plan.actions] == [0, 1, 2]
    assert [action.object_name for action in plan.actions] == ["wlan-2", "wlan-1", "wlan-0"]
    assert [action.action for action in plan.actions] == [
        RestoreActionType.CREATE,
        RestoreActionType.UPDATE,
        RestoreActionType.DELETE,
    ]
    assert plan.actions[0].current_mist_id == "mist-2"
    assert plan.actions[2].current_mist_id == "new-uuid"
    assert plan.status is RestoreStatus.PLANNED


@pytest.mark.usefixtures("offline_documents")
async def test_compensation_replays_the_captured_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    operation, store = await _applied_plan(monkeypatch)

    plan = await RestoreCompensationService(store).create_compensation_plan(
        operation=operation,
        requested_by=ADMINISTRATOR_ID,
    )
    recreate = plan.actions[0]
    revert = plan.actions[1]

    assert recreate.protected_configuration["name"] == "Guest"
    assert revert.protected_configuration["name"] == "Corp"
    assert is_protected(revert.protected_configuration["psk"])
    assert plan.actions[2].protected_configuration == {}


@pytest.mark.usefixtures("offline_documents")
async def test_compensation_links_both_directions(monkeypatch: pytest.MonkeyPatch) -> None:
    operation, store = await _applied_plan(monkeypatch)
    service = RestoreCompensationService(store)

    plan = await service.create_compensation_plan(operation=operation, requested_by=ADMINISTRATOR_ID)

    linked = await store.find_compensation_of(ORGANIZATION_ID, OPERATION_ID)
    assert linked is not None
    assert linked.operation_id == COMPENSATION_ID
    assert linked.plan_hash == compute_plan_hash(plan.actions)
    source = await store.load(ORGANIZATION_ID, OPERATION_ID)
    assert source is not None
    assert source.compensation_operation_id == COMPENSATION_ID


async def test_compensation_refuses_a_restore_that_did_not_fail_midway() -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE)], status=RestoreStatus.COMPLETED)

    with pytest.raises(RestoreCompensationError, match="nothing to compensate"):
        await RestoreCompensationService(_MemoryStateStore()).create_compensation_plan(
            operation=operation,
            requested_by=ADMINISTRATOR_ID,
        )


async def test_compensation_refuses_a_restore_without_a_safety_snapshot() -> None:
    operation = _operation(
        [_action(0, RestoreActionType.UPDATE, status=RestoreActionStatus.COMPLETED)],
    )

    with pytest.raises(RestoreCompensationError, match="No safety snapshot"):
        await RestoreCompensationService(_MemoryStateStore()).create_compensation_plan(
            operation=operation,
            requested_by=ADMINISTRATOR_ID,
        )


# ------------------------------------------------------------------------ api


class _RecordingAuthorization:
    """Captures the delegated credential the route hands to authorization."""

    def __init__(self) -> None:
        self.credentials: list[str] = []
        self.operations: list[PydanticObjectId] = []

    async def authorize(self, organization_id, operation_id, credential, task_id):  # noqa: ARG002
        self.credentials.append(credential)
        self.operations.append(operation_id)
        return _operation([], status=RestoreStatus.QUEUED, identifier=operation_id)

    async def release(self, operation_id, task_id) -> None:  # noqa: ARG002
        return


class _StubCompensation:
    """Returns a fixed compensating plan for the failed restore."""

    def __init__(self, plan: RestoreOperation | None) -> None:
        self.plan = plan

    async def compensation_for(self, operation):  # noqa: ARG002
        return self.plan


def _administrator() -> User:
    return User.model_construct(
        id=ADMINISTRATOR_ID,
        email="admin@example.com",
        display_name="Admin",
        password_hash="unused",
        role=UserRole.ADMINISTRATOR,
        is_active=True,
        totp=None,
    )


def _app(compensation: _StubCompensation, authorization: _RecordingAuthorization):
    from mist_config_guardian_backend.api.dependencies import (  # noqa: PLC0415
        get_restore_authorization_service,
    )

    app = create_app(Settings(environment="test", database_enabled=False))
    app.dependency_overrides[get_current_user] = _administrator
    app.dependency_overrides[require_organization] = _organization
    app.dependency_overrides[get_restore_compensation_service] = lambda: compensation
    app.dependency_overrides[get_restore_authorization_service] = lambda: authorization
    app.dependency_overrides[get_plan_state_store] = _MemoryStateStore
    app.dependency_overrides[get_restore_plans] = lambda: _MemoryPlans(
        [_operation([_action(0, RestoreActionType.UPDATE, status=RestoreActionStatus.COMPLETED)])]
    )
    app.dependency_overrides[get_approval_service] = lambda: ApprovalService(_NoApprovals())
    return app


class _NoApprovals:
    """An approval store with nothing in it."""

    async def find_by_id(self, organization_id, approval_id):  # noqa: ARG002
        return None

    async def find_by_operation(self, organization_id, restore_operation_id):  # noqa: ARG002
        return None

    async def insert(self, draft):
        raise NotImplementedError

    async def save(self, approval) -> None:  # noqa: ARG002
        return

    async def page(self, organization_id, status, *, skip, limit):  # noqa: ARG002
        return [], 0

    async def load_operation(self, organization_id, restore_operation_id):  # noqa: ARG002
        return None


class _MemoryPlans:
    """Restore plans keyed by identifier, scoped by organization."""

    def __init__(self, plans: list[RestoreOperation]) -> None:
        self.plans = plans

    async def load(self, organization_id, operation_id):
        return next(
            (plan for plan in self.plans if plan.id == operation_id and plan.organization_id == organization_id),
            None,
        )

    async def page(self, organization_id, *, skip, limit):
        matched = [plan for plan in self.plans if plan.organization_id == organization_id]
        return matched[skip : skip + limit], len(matched)


@pytest.fixture(name="routed")
def _routed(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace task dispatch for restore route tests."""
    dispatched: list[str] = []
    monkeypatch.setattr(
        "mist_config_guardian_backend.api.routes.restores.celery_app.send_task",
        lambda *args, **kwargs: dispatched.append(kwargs.get("task_id", "")),  # noqa: ARG005
    )
    return dispatched


@pytest.mark.usefixtures("routed")
async def test_compensation_execution_requires_a_fresh_step_up() -> None:
    plan = _operation([], status=RestoreStatus.PLANNED, identifier=COMPENSATION_ID)
    authorization = _RecordingAuthorization()
    app = _app(_StubCompensation(plan), authorization)

    def _deny() -> User:
        from fastapi import HTTPException, status  # noqa: PLC0415

        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Confirm your authenticator code")

    app.dependency_overrides[require_fresh_mfa] = _deny
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            f"/api/v1/organizations/{ORGANIZATION_ID}/restores/{OPERATION_ID}/compensation/execute",
            json={"administrator_token": "fresh-admin-token"},
        )

    assert response.status_code == 403
    assert authorization.credentials == []


async def test_compensation_execution_uses_the_delegated_administrator_credential(routed: list[str]) -> None:
    plan = _operation([], status=RestoreStatus.PLANNED, identifier=COMPENSATION_ID)
    authorization = _RecordingAuthorization()
    transport = httpx.ASGITransport(app=_app(_StubCompensation(plan), authorization))

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            f"/api/v1/organizations/{ORGANIZATION_ID}/restores/{OPERATION_ID}/compensation/execute",
            json={"administrator_token": "fresh-admin-token"},
        )

    assert response.status_code == 202
    assert authorization.credentials == ["fresh-admin-token"]
    assert authorization.operations == [COMPENSATION_ID]
    assert len(routed) == 1
    assert "fresh-admin-token" not in response.text


@pytest.mark.usefixtures("routed")
async def test_compensation_execution_refuses_a_plan_that_was_never_created() -> None:
    authorization = _RecordingAuthorization()
    transport = httpx.ASGITransport(app=_app(_StubCompensation(None), authorization))

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            f"/api/v1/organizations/{ORGANIZATION_ID}/restores/{OPERATION_ID}/compensation/execute",
            json={"administrator_token": "fresh-admin-token"},
        )

    assert response.status_code == 409
    assert authorization.credentials == []
