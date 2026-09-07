"""Plan hashing, approval policy, two-person enforcement, and role checks."""

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.api.dependencies import get_current_user, require_organization
from mist_config_guardian_backend.api.routes.approvals import get_approval_service
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.main import create_app
from mist_config_guardian_backend.models.approval import (
    ApprovalPolicy,
    ApprovalRule,
    ApprovalStatus,
    RestoreApproval,
)
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
from mist_config_guardian_backend.models.user import User, UserRole
from mist_config_guardian_backend.services.approvals import (
    ApprovalRequiredError,
    ApprovalService,
    SelfApprovalError,
    compute_plan_hash,
    evaluate_approval_policy,
    organization_policy,
)

ORGANIZATION_ID = PydanticObjectId()
OPERATION_ID = PydanticObjectId()
REQUESTER_ID = PydanticObjectId()
APPROVER_ID = PydanticObjectId()


# ------------------------------------------------------------------- fixtures


def _action(  # noqa: PLR0913 - one keyword per action field a test varies
    *,
    order: int = 0,
    action: RestoreActionType = RestoreActionType.UPDATE,
    scope: str = "site",
    object_type: str = "wlans",
    logical_id: PydanticObjectId | None = None,
    source_version_id: PydanticObjectId | None = None,
    expected_current_hash: str | None = "hash-1",
) -> RestoreAction:
    identifier = logical_id or PydanticObjectId()
    return RestoreAction(
        logical_object_id=identifier,
        source_version_id=source_version_id or PydanticObjectId(),
        order=order,
        action=action,
        scope=scope,
        object_type=object_type,
        object_name=f"object-{order}",
        current_mist_id=f"mist-{order}",
        site_mist_id="site-1" if scope == "site" else None,
        protected_configuration={"ssid": "Corp"},
        expected_current_hash=expected_current_hash,
    )


def _operation(
    actions: list[RestoreAction],
    *,
    mode: RestoreMode = RestoreMode.NON_DESTRUCTIVE,
    status: RestoreStatus = RestoreStatus.PLANNED,
) -> RestoreOperation:
    return RestoreOperation.model_construct(
        id=OPERATION_ID,
        organization_id=ORGANIZATION_ID,
        requested_by=REQUESTER_ID,
        mode=mode,
        include_dependencies=True,
        target_at=datetime(2026, 1, 1, tzinfo=UTC),
        status=status,
        actions=actions,
        warnings=[],
        preflight_errors=[],
        credential_actor=None,
        started_at=None,
        completed_at=None,
        failure_action_order=None,
        task_id=None,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        updated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _organization(policy: ApprovalPolicy | None = None) -> Organization:
    return Organization.model_construct(
        id=ORGANIZATION_ID,
        mist_org_id="org-1",
        name="Lab",
        cloud_region=MistCloudRegion.GLOBAL_01,
        status=OrganizationStatus.VERIFIED,
        encrypted_service_token="v1:encrypted-value",
        service_token_last_four="alue",
        approval_policy=policy or ApprovalPolicy(),
    )


def _user(role: UserRole, *, identifier: PydanticObjectId, email: str) -> User:
    return User.model_construct(
        id=identifier,
        email=email,
        display_name=email,
        password_hash="unused",
        role=role,
        is_active=True,
        totp=None,
    )


class _StubNotifications:
    """Records approval announcements instead of writing notification rows."""

    def __init__(self) -> None:
        self.requested: list[tuple[str, str]] = []

    async def notify_approval_requested(
        self,
        *,
        organization_id: PydanticObjectId,
        restore_id: str,
        approval_id: str,
        requested_by: str,
        user_id: PydanticObjectId | None = None,
    ) -> None:
        assert organization_id == ORGANIZATION_ID
        assert user_id is None
        self.requested.append((restore_id, approval_id))
        assert requested_by


class _MemoryApprovalStore:
    """In-memory approval persistence with the same organization scoping."""

    def __init__(self, operation: RestoreOperation | None = None) -> None:
        self.items: list[RestoreApproval] = []
        self.operations: dict[PydanticObjectId, RestoreOperation] = {}
        if operation is not None and operation.id is not None:
            self.operations[operation.id] = operation

    async def find_by_id(self, organization_id, approval_id):
        return next(
            (item for item in self.items if item.id == approval_id and item.organization_id == organization_id),
            None,
        )

    async def find_by_operation(self, organization_id, restore_operation_id):
        return next(
            (
                item
                for item in self.items
                if item.restore_operation_id == restore_operation_id and item.organization_id == organization_id
            ),
            None,
        )

    async def insert(self, draft):
        now = datetime.now(UTC)
        approval = RestoreApproval.model_construct(
            id=PydanticObjectId(),
            organization_id=draft.organization_id,
            restore_operation_id=draft.restore_operation_id,
            requested_by=draft.requested_by,
            requested_by_email=draft.requested_by_email,
            plan_hash=draft.plan_hash,
            triggered_rules=list(draft.triggered_rules),
            status=ApprovalStatus.PENDING,
            decided_by=None,
            decided_by_email=None,
            decided_at=None,
            decision_reason=None,
            expires_at=draft.expires_at,
            summary=draft.summary,
            object_count=draft.object_count,
            delete_count=draft.delete_count,
            created_at=now,
            updated_at=now,
        )
        self.items.append(approval)
        return approval

    async def save(self, approval):
        approval.touch()

    async def page(self, organization_id, status, *, skip, limit):
        matched = [
            item
            for item in self.items
            if item.organization_id == organization_id and (status is None or item.status is status)
        ]
        ordered = sorted(matched, key=lambda item: item.created_at, reverse=True)
        return ordered[skip : skip + limit], len(matched)

    async def load_operation(self, organization_id, restore_operation_id):
        operation = self.operations.get(restore_operation_id)
        if operation is None or operation.organization_id != organization_id:
            return None
        return operation


def _service(operation: RestoreOperation) -> tuple[ApprovalService, _MemoryApprovalStore, _StubNotifications]:
    store = _MemoryApprovalStore(operation)
    notifications = _StubNotifications()
    return ApprovalService(store, notifications), store, notifications


# ------------------------------------------------------------------ plan hash


def test_plan_hash_is_stable_for_the_same_reviewed_plan() -> None:
    actions = [_action(order=0), _action(order=1, action=RestoreActionType.DELETE)]

    assert compute_plan_hash(actions) == compute_plan_hash(list(reversed(actions)))


def test_plan_hash_ignores_execution_progress() -> None:
    actions = [_action(order=0)]
    before = compute_plan_hash(actions)

    actions[0].status = RestoreActionStatus.COMPLETED
    actions[0].resulting_mist_id = "new-uuid"
    actions[0].error = None

    assert compute_plan_hash(actions) == before


@pytest.mark.parametrize(
    "mutate",
    [
        lambda action: setattr(action, "action", RestoreActionType.DELETE),
        lambda action: setattr(action, "source_version_id", PydanticObjectId()),
        lambda action: setattr(action, "expected_current_hash", "hash-2"),
        lambda action: setattr(action, "logical_object_id", PydanticObjectId()),
        lambda action: setattr(action, "order", 7),
    ],
)
def test_any_plan_change_changes_the_hash(mutate) -> None:
    actions = [_action(order=0)]
    before = compute_plan_hash(actions)

    mutate(actions[0])

    assert compute_plan_hash(actions) != before


# --------------------------------------------------------------------- policy


def test_disabled_policy_never_requires_approval() -> None:
    actions = [_action(order=index, scope="org") for index in range(50)]

    assert evaluate_approval_policy(ApprovalPolicy(enabled=False), actions, RestoreMode.EXACT) == []


def test_organization_scope_rule_triggers() -> None:
    triggered = evaluate_approval_policy(
        ApprovalPolicy(enabled=True, object_count_threshold=None),
        [_action(scope="org")],
        RestoreMode.NON_DESTRUCTIVE,
    )

    assert [rule.rule for rule in triggered] == [ApprovalRule.ORGANIZATION_SCOPE]
    assert "organization-scope" in triggered[0].detail


def test_exact_mode_delete_rule_triggers_only_in_exact_mode() -> None:
    policy = ApprovalPolicy(
        enabled=True,
        require_for_organization_scope=False,
        object_count_threshold=None,
    )
    deletes = [_action(action=RestoreActionType.DELETE)]

    exact = evaluate_approval_policy(policy, deletes, RestoreMode.EXACT)
    non_destructive = evaluate_approval_policy(policy, deletes, RestoreMode.NON_DESTRUCTIVE)

    assert [rule.rule for rule in exact] == [ApprovalRule.EXACT_MODE_DELETES]
    assert non_destructive == []


def test_object_count_threshold_rule_triggers_above_the_threshold() -> None:
    policy = ApprovalPolicy(
        enabled=True,
        require_for_organization_scope=False,
        require_for_exact_deletes=False,
        object_count_threshold=2,
    )

    at_threshold = evaluate_approval_policy(policy, [_action(order=i) for i in range(2)], RestoreMode.NON_DESTRUCTIVE)
    above = evaluate_approval_policy(policy, [_action(order=i) for i in range(3)], RestoreMode.NON_DESTRUCTIVE)

    assert at_threshold == []
    assert [rule.rule for rule in above] == [ApprovalRule.OBJECT_COUNT_THRESHOLD]


def test_sensitive_object_type_rule_triggers() -> None:
    policy = ApprovalPolicy(
        enabled=True,
        require_for_organization_scope=False,
        require_for_exact_deletes=False,
        object_count_threshold=None,
        sensitive_object_types=["WLANS"],
    )

    triggered = evaluate_approval_policy(policy, [_action(object_type="wlans")], RestoreMode.NON_DESTRUCTIVE)

    assert [rule.rule for rule in triggered] == [ApprovalRule.SENSITIVE_OBJECT_TYPE]
    assert "wlans" in triggered[0].detail


def test_every_rule_can_trigger_at_once() -> None:
    policy = ApprovalPolicy(enabled=True, object_count_threshold=1, sensitive_object_types=["wlans"])
    actions = [
        _action(order=0, scope="org", object_type="wlans"),
        _action(order=1, action=RestoreActionType.DELETE),
    ]

    triggered = evaluate_approval_policy(policy, actions, RestoreMode.EXACT)

    assert [rule.rule for rule in triggered] == [
        ApprovalRule.ORGANIZATION_SCOPE,
        ApprovalRule.EXACT_MODE_DELETES,
        ApprovalRule.OBJECT_COUNT_THRESHOLD,
        ApprovalRule.SENSITIVE_OBJECT_TYPE,
    ]


def test_organization_policy_falls_back_to_defaults() -> None:
    assert organization_policy(_organization()) == ApprovalPolicy()
    assert organization_policy(_organization(ApprovalPolicy(enabled=True))).enabled is True


# -------------------------------------------------------------- two-person


async def test_request_binds_the_approval_to_the_plan_hash() -> None:
    operation = _operation([_action()])
    service, _, notifications = _service(operation)

    approval = await service.request(_organization(), operation, _requester())

    assert approval.status is ApprovalStatus.PENDING
    assert approval.plan_hash == compute_plan_hash(operation.actions)
    assert approval.requested_by == REQUESTER_ID
    assert approval.object_count == 1
    assert len(notifications.requested) == 1


async def test_requester_cannot_approve_or_reject_their_own_request() -> None:
    operation = _operation([_action()])
    service, _, _ = _service(operation)
    approval = await service.request(_organization(), operation, _requester())
    assert approval.id is not None

    with pytest.raises(SelfApprovalError, match="cannot approve or reject their own"):
        await service.decide(ORGANIZATION_ID, approval.id, _requester(), approved=True)
    with pytest.raises(SelfApprovalError):
        await service.decide(ORGANIZATION_ID, approval.id, _requester(), approved=False)
    assert approval.status is ApprovalStatus.PENDING


async def test_a_second_administrator_can_approve() -> None:
    operation = _operation([_action()])
    service, _, _ = _service(operation)
    approval = await service.request(_organization(), operation, _requester())
    assert approval.id is not None

    decided = await service.decide(
        ORGANIZATION_ID,
        approval.id,
        _approver(),
        approved=True,
        reason="Reviewed the diff",
    )

    assert decided.status is ApprovalStatus.APPROVED
    assert decided.decided_by_email == "approver@example.com"
    assert decided.decision_reason == "Reviewed the diff"


async def test_changing_the_plan_invalidates_an_approval() -> None:
    operation = _operation([_action()])
    service, _, _ = _service(operation)
    approval = await service.request(_organization(), operation, _requester())
    assert approval.id is not None
    await service.decide(ORGANIZATION_ID, approval.id, _approver(), approved=True)

    operation.actions.append(_action(order=1))
    refreshed = await service.get(ORGANIZATION_ID, approval.id)

    assert refreshed is not None
    assert refreshed.status is ApprovalStatus.INVALIDATED
    with pytest.raises(ApprovalRequiredError, match="changed after it was approved"):
        await service.assert_execution_allowed(_organization(), operation)


async def test_an_expired_approval_blocks_execution() -> None:
    policy = ApprovalPolicy(enabled=True)
    operation = _operation([_action(scope="org")])
    service, _, _ = _service(operation)
    approval = await service.request(_organization(policy), operation, _requester())
    assert approval.id is not None
    await service.decide(ORGANIZATION_ID, approval.id, _approver(), approved=True)

    approval.expires_at = datetime.now(UTC) - timedelta(minutes=1)

    with pytest.raises(ApprovalRequiredError, match="expired"):
        await service.assert_execution_allowed(_organization(policy), operation)
    assert approval.status is ApprovalStatus.EXPIRED


async def test_execution_is_blocked_when_policy_requires_an_absent_approval() -> None:
    policy = ApprovalPolicy(enabled=True)
    operation = _operation([_action(scope="org")])
    service, _, _ = _service(operation)

    with pytest.raises(ApprovalRequiredError, match="second administrator"):
        await service.assert_execution_allowed(_organization(policy), operation)


async def test_execution_is_allowed_without_approval_when_no_rule_triggers() -> None:
    operation = _operation([_action()])
    service, _, _ = _service(operation)

    assert await service.assert_execution_allowed(_organization(), operation) is None


async def test_a_pending_approval_blocks_execution_even_without_a_triggered_rule() -> None:
    operation = _operation([_action()])
    service, _, _ = _service(operation)
    await service.request(_organization(), operation, _requester())

    with pytest.raises(ApprovalRequiredError, match="waiting for approval"):
        await service.assert_execution_allowed(_organization(), operation)


async def test_a_rejected_plan_cannot_be_resubmitted_for_approval() -> None:
    operation = _operation([_action()])
    service, _, _ = _service(operation)
    approval = await service.request(_organization(), operation, _requester())
    assert approval.id is not None
    await service.decide(ORGANIZATION_ID, approval.id, _approver(), approved=False, reason="Too broad")

    with pytest.raises(ApprovalRequiredError, match="rejected"):
        await service.assert_execution_allowed(_organization(), operation)


def _requester() -> User:
    return _user(UserRole.OPERATOR, identifier=REQUESTER_ID, email="operator@example.com")


def _approver() -> User:
    return _user(UserRole.ADMINISTRATOR, identifier=APPROVER_ID, email="approver@example.com")


# ------------------------------------------------------------------------ api


def _app(service: ApprovalService, user: User):
    app = create_app(Settings(environment="test", database_enabled=False))
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[require_organization] = _organization
    app.dependency_overrides[get_approval_service] = lambda: service
    return app


def _client(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def test_viewer_is_refused_restore_planning() -> None:
    operation = _operation([_action()])
    service, _, _ = _service(operation)
    viewer = _user(UserRole.VIEWER, identifier=PydanticObjectId(), email="viewer@example.com")

    async with _client(_app(service, viewer)) as client:
        response = await client.post(
            f"/api/v1/organizations/{ORGANIZATION_ID}/restores/plans",
            json={"version_ids": [str(PydanticObjectId())], "mode": "non_destructive"},
        )

    assert response.status_code == 403
    assert response.json()["detail"] == "Operator role required"


async def test_operator_is_refused_restore_execution() -> None:
    operation = _operation([_action()])
    service, _, _ = _service(operation)

    async with _client(_app(service, _requester())) as client:
        response = await client.post(
            f"/api/v1/organizations/{ORGANIZATION_ID}/restores/{OPERATION_ID}/execute",
            json={"administrator_token": "secret-token"},
        )

    assert response.status_code == 403
    assert response.json()["detail"] == "Administrator role required"


async def test_operator_can_request_approval_and_viewer_can_read_it() -> None:
    operation = _operation([_action()])
    service, store, _ = _service(operation)

    async with _client(_app(service, _requester())) as client:
        created = await client.post(
            f"/api/v1/organizations/{ORGANIZATION_ID}/approvals",
            json={"restore_operation_id": str(OPERATION_ID)},
        )

    assert created.status_code == 201
    payload = created.json()
    assert payload["status"] == "pending"
    assert payload["restore_operation_id"] == str(OPERATION_ID)
    assert payload["requested_by_email"] == "operator@example.com"
    assert payload["plan_hash"] == compute_plan_hash(operation.actions)
    assert payload["triggered_rules"] == []

    viewer = _user(UserRole.VIEWER, identifier=PydanticObjectId(), email="viewer@example.com")
    async with _client(_app(service, viewer)) as client:
        listed = await client.get(f"/api/v1/organizations/{ORGANIZATION_ID}/approvals")
        single = await client.get(f"/api/v1/organizations/{ORGANIZATION_ID}/approvals/{store.items[0].id}")

    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert single.status_code == 200


async def test_self_approval_is_refused_with_a_conflict() -> None:
    operation = _operation([_action()])
    service, store, _ = _service(operation)
    requester = _user(UserRole.ADMINISTRATOR, identifier=REQUESTER_ID, email="operator@example.com")
    await service.request(_organization(), operation, requester)
    approval_id = store.items[0].id

    async with _client(_app(service, requester)) as client:
        refused = await client.post(
            f"/api/v1/organizations/{ORGANIZATION_ID}/approvals/{approval_id}/approve",
            json={},
        )

    assert refused.status_code == 409
    assert "own restore request" in refused.json()["detail"]


async def test_a_second_administrator_approves_over_the_api() -> None:
    operation = _operation([_action()])
    service, store, _ = _service(operation)
    await service.request(_organization(), operation, _requester())
    approval_id = store.items[0].id

    async with _client(_app(service, _approver())) as client:
        approved = await client.post(
            f"/api/v1/organizations/{ORGANIZATION_ID}/approvals/{approval_id}/approve",
            json={"reason": "Checked with the site owner"},
        )
        replayed = await client.post(
            f"/api/v1/organizations/{ORGANIZATION_ID}/approvals/{approval_id}/reject",
            json={},
        )

    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    assert approved.json()["decided_by_email"] == "approver@example.com"
    assert replayed.status_code == 409


async def test_viewer_cannot_decide_an_approval() -> None:
    operation = _operation([_action()])
    service, store, _ = _service(operation)
    await service.request(_organization(), operation, _requester())
    viewer = _user(UserRole.VIEWER, identifier=PydanticObjectId(), email="viewer@example.com")

    async with _client(_app(service, viewer)) as client:
        response = await client.post(
            f"/api/v1/organizations/{ORGANIZATION_ID}/approvals/{store.items[0].id}/approve",
            json={},
        )

    assert response.status_code == 403
