"""Plan hashing, approval policy, two-person enforcement, and role checks."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from beanie import PydanticObjectId
from beanie.odm.fields import ExpressionField
from structlog.testing import capture_logs

from mist_config_guardian_backend.api.dependencies import (
    get_current_user,
    get_restore_authorization_service,
    require_organization,
)
from mist_config_guardian_backend.api.routes.approvals import get_approval_service
from mist_config_guardian_backend.api.routes.restores import get_plan_state_store, get_restore_plans
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
    RestoreActionReason,
    RestoreActionStatus,
    RestoreActionType,
    RestoreMode,
    RestoreOperation,
    RestoreStatus,
)
from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectReference, ObjectVersion, VersionEvent
from mist_config_guardian_backend.models.user import User, UserRole
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services import restore_baseline as baseline_module
from mist_config_guardian_backend.services.approvals import (
    APPROVAL_NOT_CARRIED,
    ApprovalRequiredError,
    ApprovalService,
    SelfApprovalError,
    _digest,
    compute_intent_hash,
    compute_plan_hash,
    evaluate_approval_policy,
    organization_policy,
    payload_digest,
)
from mist_config_guardian_backend.services.restore_baseline import RestoreBaselineService
from mist_config_guardian_backend.services.restore_planner import (
    RestorePlanner,
    RestorePlanningError,
    assert_plan_current,
)
from mist_config_guardian_backend.snapshots.fingerprint import fingerprint
from mist_config_guardian_backend.snapshots.registry import get_definition
from mist_config_guardian_backend.snapshots.secrets import protect_configuration

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
    reason: RestoreActionReason = RestoreActionReason.RESTORE,
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
        reason=reason,
    )


def _operation(
    actions: list[RestoreAction],
    *,
    mode: RestoreMode = RestoreMode.NON_DESTRUCTIVE,
    status: RestoreStatus = RestoreStatus.PLANNED,
    identifier: PydanticObjectId = OPERATION_ID,
    requested_version_ids: list[PydanticObjectId] | None = None,
) -> RestoreOperation:
    return RestoreOperation.model_construct(
        id=identifier,
        organization_id=ORGANIZATION_ID,
        requested_by=REQUESTER_ID,
        requested_version_ids=requested_version_ids or [],
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
            intent_hash=draft.intent_hash,
            action_signature=draft.action_signature,
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


def test_a_plan_without_a_written_payload_hashes_as_plans_stored_before_it_existed() -> None:
    """Only a reversal of an unread write carries the payload, so every stored plan keeps its reviewed hash."""
    actions = [_action(order=0), _action(order=1, action=RestoreActionType.DELETE)]
    before = _digest(
        [
            [
                action.order,
                str(action.logical_object_id),
                str(action.action),
                str(action.source_version_id),
                action.expected_current_hash,
                action.current_mist_id,
                action.site_mist_id,
                str(action.reason),
                payload_digest(action.protected_configuration),
            ]
            for action in actions
        ]
    )

    assert compute_plan_hash(actions) == before


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
        lambda action: setattr(action, "current_mist_id", "mist-other"),
        lambda action: setattr(action, "site_mist_id", "site-other"),
        lambda action: setattr(action, "protected_configuration", {"ssid": "Guest"}),
        lambda action: setattr(action, "reason", RestoreActionReason.REFERENCE_REWRITE),
        lambda action: setattr(action, "written_configuration", {"ssid": "Corp"}),
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


PREPARED_ID = PydanticObjectId()


def _prepared_from(draft: RestoreOperation, actions: list[RestoreAction] | None = None, **changes) -> RestoreOperation:
    """The plan a fresh backup produces: new id, new baseline hashes, same intent."""
    prepared = draft.model_copy(update={"id": PREPARED_ID, "baseline_snapshot_id": PydanticObjectId(), **changes})
    prepared.warnings = list(draft.warnings)
    prepared.actions = (
        actions
        if actions is not None
        else [action.model_copy(update={"expected_current_hash": "fresh-backup-hash"}) for action in draft.actions]
    )
    return prepared


async def _approved_draft(policy: ApprovalPolicy, actions: list[RestoreAction], *, decide: bool = True):
    version = PydanticObjectId()
    draft = _operation(actions, requested_version_ids=[version])
    service, store, _ = _service(draft)
    approval = await service.request(_organization(policy), draft, _requester())
    assert approval.id is not None
    if decide:
        await service.decide(ORGANIZATION_ID, approval.id, _approver(), approved=True)
    return draft, service, store, approval


def test_payload_digest_is_blind_to_encryption_nonces_but_not_to_secrets() -> None:
    vault = CredentialVault(Settings(environment="test", credential_encryption_key="test-key"))
    sensitive = frozenset({"psk"})
    first = protect_configuration({"ssid": "Corp", "psk": "correct-horse"}, vault, sensitive_fields=sensitive)
    second = protect_configuration({"ssid": "Corp", "psk": "correct-horse"}, vault, sensitive_fields=sensitive)
    other = protect_configuration({"ssid": "Corp", "psk": "battery-staple"}, vault, sensitive_fields=sensitive)

    assert first != second
    assert payload_digest(first) == payload_digest(second)
    assert payload_digest(first) != payload_digest(other)


def test_payload_digest_of_a_protected_value_without_a_fingerprint_follows_its_ciphertext() -> None:
    """A value protected before fingerprints existed has nothing else to compare, so it is not treated as equal."""
    assert payload_digest({"psk": {"$encrypted": "v1:one"}}) != payload_digest({"psk": {"$encrypted": "v1:two"}})


async def test_an_approval_carries_to_the_prepared_plan_of_the_same_intent() -> None:
    policy = ApprovalPolicy(enabled=True)
    draft, service, store, approval = await _approved_draft(policy, [_action(scope="org")])
    prepared = _prepared_from(draft)
    store.operations[PREPARED_ID] = prepared

    assert await service.carry_to_prepared(draft, prepared) == "carried"
    assert approval.restore_operation_id == PREPARED_ID
    assert await service.assert_execution_allowed(_organization(policy), prepared) is approval


async def test_an_approval_carries_to_a_plan_prepared_by_another_administrator() -> None:
    """Operators draft and administrators prepare; who asked is not part of what was asked for."""
    policy = ApprovalPolicy(enabled=True)
    draft, service, store, approval = await _approved_draft(policy, [_action(scope="org")])
    expires_at, decided_at = approval.expires_at, approval.decided_at
    prepared = _prepared_from(draft, requested_by=PydanticObjectId())
    store.operations[PREPARED_ID] = prepared

    assert await service.carry_to_prepared(draft, prepared) == "carried"
    assert approval.restore_operation_id == PREPARED_ID
    assert approval.requested_by == REQUESTER_ID
    assert approval.status is ApprovalStatus.APPROVED
    assert approval.decided_by == APPROVER_ID
    assert approval.decided_at == decided_at
    assert approval.expires_at == expires_at
    assert approval.plan_hash == compute_plan_hash(prepared.actions)


async def test_the_requester_cannot_decide_an_approval_carried_to_the_prepared_plan() -> None:
    draft, service, store, approval = await _approved_draft(
        ApprovalPolicy(enabled=True), [_action(scope="org")], decide=False
    )
    prepared = _prepared_from(draft)
    store.operations[PREPARED_ID] = prepared
    assert await service.carry_to_prepared(draft, prepared) == "carried"
    assert approval.id is not None

    with pytest.raises(SelfApprovalError):
        await service.decide(ORGANIZATION_ID, approval.id, _requester(), approved=True)
    assert approval.status is ApprovalStatus.PENDING


async def test_an_approval_does_not_carry_when_the_backup_changes_the_actions() -> None:
    policy = ApprovalPolicy(enabled=True)
    draft, service, store, approval = await _approved_draft(policy, [_action(scope="org")])
    prepared = _prepared_from(draft, actions=[*draft.actions, _action(order=1, action=RestoreActionType.DELETE)])
    store.operations[PREPARED_ID] = prepared

    assert await service.carry_to_prepared(draft, prepared) == "not_carried"
    assert approval.restore_operation_id == OPERATION_ID
    # The draft was not superseded (another preparation may have won), so its approval is left as it was.
    assert approval.status is ApprovalStatus.APPROVED
    with pytest.raises(ApprovalRequiredError):
        await service.assert_execution_allowed(_organization(policy), prepared)


@pytest.mark.parametrize("decide", [True, False], ids=["approved", "pending"])
async def test_an_approval_left_on_a_superseded_draft_is_invalidated(decide: bool) -> None:  # noqa: FBT001 - pytest parameter
    draft, service, store, approval = await _approved_draft(
        ApprovalPolicy(enabled=True), [_action(scope="org")], decide=decide
    )
    prepared = _prepared_from(draft, actions=[*draft.actions, _action(order=1, action=RestoreActionType.DELETE)])
    store.operations[PREPARED_ID] = prepared
    # Superseding writes the stored draft; the copy the route loaded earlier still says planned.
    store.operations[OPERATION_ID] = draft.model_copy(update={"status": RestoreStatus.SUPERSEDED})

    assert await service.carry_to_prepared(draft, prepared) == "not_carried"
    assert approval.status is ApprovalStatus.INVALIDATED
    assert approval.restore_operation_id == OPERATION_ID


async def test_an_approval_does_not_carry_to_a_plan_in_another_mode() -> None:
    draft, service, store, _approval = await _approved_draft(ApprovalPolicy(enabled=True), [_action(scope="org")])
    prepared = _prepared_from(draft, mode=RestoreMode.EXACT)
    store.operations[PREPARED_ID] = prepared

    assert await service.carry_to_prepared(draft, prepared) == "not_carried"


async def test_a_reference_rewrite_whose_source_moved_still_carries() -> None:
    rewrite = _action(scope="org", reason=RestoreActionReason.REFERENCE_REWRITE)
    draft, service, store, _approval = await _approved_draft(ApprovalPolicy(enabled=True), [rewrite])
    prepared = _prepared_from(
        draft,
        actions=[rewrite.model_copy(update={"source_version_id": PydanticObjectId(), "expected_current_hash": "x"})],
    )
    store.operations[PREPARED_ID] = prepared

    assert await service.carry_to_prepared(draft, prepared) == "carried"


async def test_an_approval_recorded_before_intents_were_bound_does_not_carry() -> None:
    assert RestoreApproval.model_fields["intent_hash"].default is None
    assert RestoreApproval.model_fields["action_signature"].default is None
    draft, service, store, approval = await _approved_draft(ApprovalPolicy(enabled=True), [_action(scope="org")])
    approval.intent_hash = None
    approval.action_signature = None
    prepared = _prepared_from(draft)
    store.operations[PREPARED_ID] = prepared

    assert await service.carry_to_prepared(draft, prepared) == "not_carried"
    assert approval.restore_operation_id == OPERATION_ID


class _NoStates:
    async def load(self, organization_id, operation_id):  # noqa: ARG002
        return None


async def test_a_plan_without_a_reviewed_record_is_not_current() -> None:
    with pytest.raises(RestorePlanningError, match="no reviewed plan record"):
        await assert_plan_current(_NoStates(), _operation([_action()]))


class _PreparingAuthorization:
    def __init__(self, prepared: RestoreOperation, *, superseded_by: PydanticObjectId | None = None) -> None:
        self.prepared = prepared
        self.superseded_by = superseded_by

    async def prepare(self, organization, operation, requested_by, credential, store):  # noqa: ARG002
        # As a real preparation leaves the draft: retired in favour of its
        # replacement, or of another plan when that preparation got there first.
        operation.status = RestoreStatus.SUPERSEDED
        operation.superseded_by = self.superseded_by or self.prepared.id
        return self.prepared


class _Plans:
    def __init__(self, *plans: RestoreOperation) -> None:
        self.plans = {plan.id: plan for plan in plans}

    async def load(self, organization_id, operation_id):  # noqa: ARG002
        return self.plans.get(operation_id)

    async def page(self, organization_id, *, skip, limit):  # noqa: ARG002
        return list(self.plans.values()), len(self.plans)


async def test_preparing_an_approved_draft_carries_its_approval_over_the_api() -> None:
    draft, service, store, _approval = await _approved_draft(ApprovalPolicy(), [_action()])
    prepared = _prepared_from(draft, requested_by=APPROVER_ID)
    store.operations[PREPARED_ID] = prepared
    administrator = _user(UserRole.ADMINISTRATOR, identifier=APPROVER_ID, email="approver@example.com")
    app = _app(service, administrator)
    app.dependency_overrides[get_restore_authorization_service] = lambda: _PreparingAuthorization(prepared)
    app.dependency_overrides[get_restore_plans] = lambda: _Plans(draft)
    app.dependency_overrides[get_plan_state_store] = _NoStates

    async with _client(app) as client:
        response = await client.post(
            f"/api/v1/organizations/{ORGANIZATION_ID}/restores/{OPERATION_ID}/prepare",
            json={"administrator_token": "fresh-admin-token"},
        )

    assert response.status_code == 201
    body = response.json()
    assert body["id"] == str(PREPARED_ID)
    assert body["approval"]["status"] == "approved"
    assert body["approval_required"] is False
    assert APPROVAL_NOT_CARRIED not in body["warnings"]


def _preparing_app(
    service: ApprovalService,
    draft: RestoreOperation,
    prepared: RestoreOperation,
    *,
    superseded_by: PydanticObjectId | None = None,
):
    """The prepare route with a fresh backup that returns ``prepared`` and no reviewed-state record."""
    administrator = _user(UserRole.ADMINISTRATOR, identifier=APPROVER_ID, email="approver@example.com")
    app = _app(service, administrator)
    app.dependency_overrides[get_restore_authorization_service] = lambda: _PreparingAuthorization(
        prepared, superseded_by=superseded_by
    )
    app.dependency_overrides[get_restore_plans] = lambda: _Plans(draft)
    app.dependency_overrides[get_plan_state_store] = _NoStates
    return app


async def _post_prepare(app) -> httpx.Response:
    async with _client(app) as client:
        return await client.post(
            f"/api/v1/organizations/{ORGANIZATION_ID}/restores/{OPERATION_ID}/prepare",
            json={"administrator_token": "fresh-admin-token"},
        )


async def test_preparing_a_draft_whose_backup_changed_the_actions_warns_over_the_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    draft, service, store, approval = await _approved_draft(ApprovalPolicy(), [_action()])
    prepared = _prepared_from(draft, actions=[*draft.actions, _action(order=1, action=RestoreActionType.DELETE)])
    store.operations[PREPARED_ID] = prepared
    saved = AsyncMock()
    monkeypatch.setattr(RestoreOperation, "save", saved)

    response = await _post_prepare(_preparing_app(service, draft, prepared))

    assert response.status_code == 201
    body = response.json()
    assert body["id"] == str(PREPARED_ID)
    assert APPROVAL_NOT_CARRIED in body["warnings"]
    assert body["approval"] is None
    saved.assert_awaited_once()
    assert approval.restore_operation_id == OPERATION_ID


async def test_a_carry_that_fails_still_returns_the_prepared_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    """The plan and its session already exist; failing the request would hide them."""
    draft, service, store, approval = await _approved_draft(ApprovalPolicy(), [_action()])
    prepared = _prepared_from(draft)
    store.operations[PREPARED_ID] = prepared
    monkeypatch.setattr(service, "carry_to_prepared", AsyncMock(side_effect=RuntimeError("database detail")))

    with capture_logs() as logs:
        response = await _post_prepare(_preparing_app(service, draft, prepared))

    assert response.status_code == 201
    body = response.json()
    assert body["id"] == str(PREPARED_ID)
    assert APPROVAL_NOT_CARRIED not in body["warnings"]
    # The approval stayed on the draft, and the response says so rather than guessing.
    assert body["approval"] is None
    assert approval.restore_operation_id == OPERATION_ID
    assert logs == [
        {
            "event": "restore_approval_carry_failed",
            "log_level": "warning",
            "operation_id": str(PREPARED_ID),
            "error_type": "RuntimeError",
        }
    ]


async def test_an_approval_stays_on_a_draft_another_preparation_superseded(monkeypatch: pytest.MonkeyPatch) -> None:
    """The plan that retired the draft is where its approval belongs, not a plan that lost the race."""
    draft, service, store, approval = await _approved_draft(ApprovalPolicy(), [_action()])
    prepared = _prepared_from(draft)
    store.operations[PREPARED_ID] = prepared
    saved = AsyncMock()
    monkeypatch.setattr(RestoreOperation, "save", saved)

    with capture_logs() as logs:
        response = await _post_prepare(_preparing_app(service, draft, prepared, superseded_by=PydanticObjectId()))

    assert response.status_code == 201
    body = response.json()
    assert body["id"] == str(PREPARED_ID)
    assert body["approval"] is None
    assert APPROVAL_NOT_CARRIED not in body["warnings"]
    assert approval.restore_operation_id == OPERATION_ID
    assert approval.status is ApprovalStatus.APPROVED
    saved.assert_not_awaited()
    assert logs == [
        {
            "event": "restore_approval_carry_skipped",
            "log_level": "info",
            "operation_id": str(OPERATION_ID),
            "prepared_id": str(PREPARED_ID),
        }
    ]


async def test_a_not_carried_warning_that_cannot_be_saved_still_returns_the_prepared_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    draft, service, store, _approval = await _approved_draft(ApprovalPolicy(), [_action()])
    prepared = _prepared_from(draft, actions=[*draft.actions, _action(order=1, action=RestoreActionType.DELETE)])
    store.operations[PREPARED_ID] = prepared
    monkeypatch.setattr(RestoreOperation, "save", AsyncMock(side_effect=RuntimeError("database detail")))

    with capture_logs() as logs:
        response = await _post_prepare(_preparing_app(service, draft, prepared))

    assert response.status_code == 201
    assert response.json()["id"] == str(PREPARED_ID)
    assert logs == [
        {
            "event": "restore_approval_carry_failed",
            "log_level": "warning",
            "operation_id": str(PREPARED_ID),
            "error_type": "RuntimeError",
        }
    ]


# ------------------------------------------------- preparing the same plan again

_BEFORE_TARGET = datetime(2026, 1, 1, tzinfo=UTC)
_AFTER_TARGET = datetime(2026, 2, 1, tzinfo=UTC)
_PREPARING_VAULT = CredentialVault(Settings(environment="test", credential_encryption_key="test-key"))


class _PreparedHistory:
    """Stored history as the planner reads it and every fresh backup extends it, beside Mist's live answers.

    Each preparation runs the real planner and the real baseline capture; only
    the database and Mist are replaced, so a second preparation sees exactly
    the history the first one left behind.
    """

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.objects: dict[PydanticObjectId, LogicalObject] = {}
        self.versions: dict[PydanticObjectId, list[ObjectVersion]] = {}
        self.live: dict[str, dict[str, object] | None] = {}
        self.related: dict[PydanticObjectId, list[LogicalObject]] = {}
        history = self

        async def _get_version(version_id, *_args, **_kwargs):
            return next((item for items in history.versions.values() for item in items if item.id == version_id), None)

        async def _get_logical(logical_id, *_args, **_kwargs):
            return history.objects.get(logical_id)

        async def _latest(logical_id):
            stored = history.versions.get(logical_id)
            return stored[-1] if stored else None

        async def _version_at(logical_id, target_at):
            earlier = [item for item in history.versions.get(logical_id, []) if item.observed_at <= target_at]
            return earlier[-1] if earlier else None

        async def _related(_planner, _organization_id, logical, _version, *, include_contained):
            return history.related.get(logical.id, []) if include_contained else []

        async def _insert_version(version, *_args, **_kwargs):
            history.versions[version.logical_object_id].append(version)
            return version

        async def _insert_operation(operation, *_args, **_kwargs):
            operation.id = PydanticObjectId()
            return operation

        monkeypatch.setattr(ObjectVersion, "get", _get_version)
        monkeypatch.setattr(ObjectVersion, "insert", _insert_version)
        monkeypatch.setattr(LogicalObject, "get", _get_logical)
        monkeypatch.setattr(RestoreOperation, "insert", _insert_operation)
        monkeypatch.setattr(RestoreOperation, "get_pymongo_collection", classmethod(lambda _cls: None))
        monkeypatch.setattr(RestorePlanner, "_latest_version", staticmethod(_latest))
        monkeypatch.setattr(RestorePlanner, "_version_at", staticmethod(_version_at))
        monkeypatch.setattr(RestorePlanner, "_related_logical_objects", _related)
        monkeypatch.setattr(RestorePlanner, "_action_dependencies", AsyncMock(return_value=[]))
        monkeypatch.setattr(baseline_module, "latest_version", _latest)
        monkeypatch.setattr(
            baseline_module,
            "ObjectVersion",
            lambda **fields: ObjectVersion.model_construct(id=PydanticObjectId(), **fields),
        )
        monkeypatch.setattr(
            baseline_module,
            "LogicalObject",
            SimpleNamespace(
                id=ExpressionField("id"),
                find_one=MagicMock(return_value=SimpleNamespace(update=AsyncMock())),
            ),
        )

    def add(self, scope: str, object_type: str, mist_id: str, *, site_mist_id: str | None = None) -> LogicalObject:
        logical = LogicalObject.model_construct(
            id=PydanticObjectId(),
            organization_id=ORGANIZATION_ID,
            scope=scope,
            object_type=object_type,
            source_key=mist_id,
            current_mist_id=mist_id,
            site_mist_id=site_mist_id,
            name=mist_id,
            is_deleted=False,
            current_version=1,
        )
        assert logical.id is not None
        self.objects[logical.id] = logical
        self.versions[logical.id] = []
        return logical

    def record(
        self,
        logical: LogicalObject,
        configuration: dict[str, object],
        *,
        observed_at: datetime,
        is_deleted: bool = False,
        references: list[ObjectReference] | None = None,
    ) -> ObjectVersion:
        """What the collector stores for one read of the object."""
        assert logical.id is not None
        definition = get_definition(logical.scope, logical.object_type)
        assert definition is not None
        version = ObjectVersion.model_construct(
            id=PydanticObjectId(),
            organization_id=ORGANIZATION_ID,
            logical_object_id=logical.id,
            incarnation_id=PydanticObjectId(),
            version=len(self.versions[logical.id]) + 1,
            event=VersionEvent.DELETED if is_deleted else VersionEvent.UPDATED,
            configuration=protect_configuration(
                configuration, _PREPARING_VAULT, sensitive_fields=definition.sensitive_fields
            ),
            configuration_hash=fingerprint(definition, configuration),
            changed_fields=[],
            references=references or [],
            is_deleted=is_deleted,
            observed_at=observed_at,
        )
        self.versions[logical.id].append(version)
        logical.is_deleted = is_deleted
        return version

    async def plan(
        self,
        version_ids: list[PydanticObjectId],
        *,
        mode: RestoreMode,
        include_dependencies: bool,
        prepared: bool,
    ) -> RestoreOperation:
        """Build a draft, or prepare a plan against a fresh backup of what Mist holds now."""
        reader = None
        if prepared:
            manifest = SimpleNamespace(id=PydanticObjectId(), created_versions=0, unchanged_objects=0)
            client = SimpleNamespace(
                get_current=AsyncMock(side_effect=lambda _definition, mist_id, **_kwargs: self.live[mist_id])
            )
            baseline = RestoreBaselineService(_PREPARING_VAULT, AsyncMock())

            async def reader(objects):
                # The capture alone: the manifest and Mist session around it are not under test.
                return await baseline._capture(client, _organization(), objects, manifest, "admin")  # noqa: SLF001

        planner = RestorePlanner(AsyncMock(), ApprovalPolicy(enabled=True), _PREPARING_VAULT, baseline_reader=reader)
        return await planner.create_plan(
            organization_id=ORGANIZATION_ID,
            requested_by=REQUESTER_ID,
            version_ids=version_ids,
            mode=mode,
            include_dependencies=include_dependencies,
        )


async def _approve(draft: RestoreOperation) -> tuple[ApprovalService, _MemoryApprovalStore, RestoreApproval]:
    service, store, _ = _service(draft)
    approval = await service.request(_organization(ApprovalPolicy(enabled=True)), draft, _requester())
    assert approval.id is not None
    await service.decide(ORGANIZATION_ID, approval.id, _approver(), approved=True)
    return service, store, approval


# The collector's last read of an object either matches what an administrator
# reads now, or masks a secret the administrator's read returns.
_COLLECTED = pytest.mark.parametrize("collected_secret", ["guest-secret", "********"], ids=["same", "masked"])


@_COLLECTED
async def test_an_approval_carries_across_every_preparation_of_an_exact_plan_that_force_deletes(
    monkeypatch: pytest.MonkeyPatch,
    collected_secret: str,
) -> None:
    history = _PreparedHistory(monkeypatch)
    site = history.add("org", "sites", "site-1")
    site_target = history.record(site, {"id": "site-1", "name": "Seattle"}, observed_at=_BEFORE_TARGET)
    # Created after the target moment, so an exact restore deletes it.
    late = history.add("site", "wlans", "wlan-late", site_mist_id="site-1")
    history.record(late, {"id": "wlan-late", "ssid": "Late", "psk": collected_secret}, observed_at=_AFTER_TARGET)
    history.related[site.id] = [late]
    history.live = {
        "site-1": {"id": "site-1", "name": "Seattle"},
        "wlan-late": {"id": "wlan-late", "ssid": "Late", "psk": "guest-secret"},
    }
    inputs = {"mode": RestoreMode.EXACT, "include_dependencies": True}

    draft = await history.plan([site_target.id], prepared=False, **inputs)
    service, store, approval = await _approve(draft)
    source = draft
    for _ in range(2):
        prepared = await history.plan([site_target.id], prepared=True, **inputs)
        assert prepared.id is not None
        store.operations[prepared.id] = prepared
        assert [(action.logical_object_id, action.action) for action in prepared.actions] == [
            (late.id, RestoreActionType.DELETE)
        ]
        assert await service.carry_to_prepared(source, prepared) == "carried"
        source = prepared

    assert approval.restore_operation_id == source.id
    assert await service.assert_execution_allowed(_organization(ApprovalPolicy(enabled=True)), source) is approval
    # A backup that read what history already held records nothing new.
    assert len(history.versions[late.id]) == (1 if collected_secret == "guest-secret" else 2)


@_COLLECTED
async def test_an_object_repointed_at_its_current_version_stays_a_rewrite_across_preparations(
    monkeypatch: pytest.MonkeyPatch,
    collected_secret: str,
) -> None:
    history = _PreparedHistory(monkeypatch)
    network = history.add("org", "networks", "net-old")
    network_target = history.record(network, {"id": "net-old", "name": "Corp"}, observed_at=_BEFORE_TARGET)
    history.record(network, {"id": "net-old", "name": "Corp"}, observed_at=_AFTER_TARGET, is_deleted=True)
    wlan = history.add("site", "wlans", "wlan-1", site_mist_id="site-1")
    wlan_current = history.record(
        wlan,
        {"id": "wlan-1", "ssid": "Guest", "network_id": "net-old", "psk": collected_secret},
        observed_at=_AFTER_TARGET,
        references=[ObjectReference(target_mist_id="net-old", field_path="network_id")],
    )
    history.live = {
        "net-old": None,
        "wlan-1": {"id": "wlan-1", "ssid": "Guest", "network_id": "net-old", "psk": "guest-secret"},
    }
    requested = [network_target.id, wlan_current.id]
    inputs = {"mode": RestoreMode.NON_DESTRUCTIVE, "include_dependencies": False}
    expected = [
        (network.id, RestoreActionType.CREATE, RestoreActionReason.RESTORE),
        (wlan.id, RestoreActionType.UPDATE, RestoreActionReason.REFERENCE_REWRITE),
    ]

    draft = await history.plan(requested, prepared=False, **inputs)
    assert [(action.logical_object_id, action.action, action.reason) for action in draft.actions] == expected
    service, store, approval = await _approve(draft)
    source = draft
    for _ in range(2):
        prepared = await history.plan(requested, prepared=True, **inputs)
        assert prepared.id is not None
        store.operations[prepared.id] = prepared
        assert [(action.logical_object_id, action.action, action.reason) for action in prepared.actions] == expected
        assert prepared.preflight_errors == []
        assert await service.carry_to_prepared(source, prepared) == "carried"
        source = prepared

    assert approval.restore_operation_id == source.id
    assert approval.status is ApprovalStatus.APPROVED


def test_a_naive_target_moment_hashes_as_the_same_utc_moment() -> None:
    """A datetime read back without a timezone names the UTC moment it was stored as."""
    aware = _operation([_action()])
    naive = aware.model_copy(update={"target_at": datetime(2026, 1, 1)})  # noqa: DTZ001 - the naive value under test

    assert naive.target_at.tzinfo is None
    assert compute_intent_hash(naive) == compute_intent_hash(aware)


async def test_a_plan_says_when_policy_needs_an_approval_nobody_asked_for() -> None:
    policy = ApprovalPolicy(enabled=True)
    operation = _operation([_action(scope="org")])
    service, _, _ = _service(operation)
    app = _app(service, _requester())
    app.dependency_overrides[require_organization] = lambda: _organization(policy)
    app.dependency_overrides[get_restore_plans] = lambda: _Plans(operation)

    async with _client(app) as client:
        single = await client.get(f"/api/v1/organizations/{ORGANIZATION_ID}/restores/{OPERATION_ID}")
        listed = await client.get(f"/api/v1/organizations/{ORGANIZATION_ID}/restores")

    assert single.status_code == 200
    assert single.json()["approval"] is None
    assert single.json()["approval_required"] is True
    assert listed.json()["items"][0]["approval_required"] is True


async def test_a_new_draft_says_it_will_need_an_approval(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = ApprovalPolicy(enabled=True)
    operation = _operation([_action(scope="org")])
    service, _, _ = _service(operation)

    class _Planner:
        def __init__(self, *_args: object) -> None:
            pass

        async def create_plan(self, **_kwargs: object) -> RestoreOperation:
            return operation

    monkeypatch.setattr("mist_config_guardian_backend.api.routes.restores.RestorePlanner", _Planner)
    app = _app(service, _requester())
    app.dependency_overrides[require_organization] = lambda: _organization(policy)
    app.dependency_overrides[get_plan_state_store] = _NoStates

    async with _client(app) as client:
        response = await client.post(
            f"/api/v1/organizations/{ORGANIZATION_ID}/restores/plans",
            json={"version_ids": [str(PydanticObjectId())], "mode": "non_destructive"},
        )

    assert response.status_code == 201
    assert response.json()["approval_required"] is True


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
