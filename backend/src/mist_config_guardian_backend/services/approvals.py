"""Two-person approval policy evaluation and enforcement for restore plans.

The plan hash is the contract between a review and an execution: an approval is
bound to the exact ordered action list that was reviewed, so any change to the
plan invalidates the decision instead of silently carrying it forward. The one
move an approval makes is from a draft to the plan its fresh backup produced,
and only when what was asked for and which changes it makes are the same.
"""

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol

from beanie import PydanticObjectId

from mist_config_guardian_backend.models.approval import (
    ApprovalPolicy,
    ApprovalRule,
    ApprovalStatus,
    RestoreApproval,
    TriggeredRule,
)
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.restore import (
    RestoreAction,
    RestoreActionReason,
    RestoreActionType,
    RestoreMode,
    RestoreOperation,
    RestoreStatus,
)
from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.services.notifications import NotificationService
from mist_config_guardian_backend.snapshots.secrets import is_protected, protected_fingerprint

_MAX_SUMMARY_TYPES = 4

CarryOutcome = Literal["carried", "not_carried", "no_approval"]

APPROVAL_NOT_CARRIED = (
    "The fresh backup changed what this restore would do, so the approval of the earlier plan does not apply; "
    "request approval for this plan"
)


class ApprovalError(ValueError):
    """Raised when an approval cannot be created or decided."""


class SelfApprovalError(ApprovalError):
    """Raised when the requester tries to decide their own request."""


class ApprovalRequiredError(ApprovalError):
    """Raised when execution is blocked pending a second administrator."""


def _digest(value: object) -> str:
    serialized = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(serialized.encode()).hexdigest()


def payload_digest(configuration: Mapping[str, object]) -> str:
    """Digest a protected configuration without its ciphertext, which changes on every planning.

    A protected secret contributes its keyed fingerprint, so the same secret
    encrypted twice digests the same and a different secret does not. A value
    protected before fingerprints were stored contributes its ciphertext
    instead: nothing else tells two of them apart, and treating them as equal
    would let a changed secret pass as reviewed.
    """

    def stable(value: object) -> object:
        if isinstance(value, Mapping):
            if is_protected(value):
                fingerprint = protected_fingerprint(value)
                return {"$fingerprint": fingerprint} if fingerprint is not None else {"$encrypted": value["$encrypted"]}
            return {str(key): stable(child) for key, child in value.items()}
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [stable(child) for child in value]
        return value

    return _digest(stable(configuration))


def compute_plan_hash(actions: Sequence[RestoreAction]) -> str:
    """Hash the reviewed plan so any change to it invalidates an approval.

    The reviewed intent is hashed - object identity, target ids, action type,
    why the action exists, source version, expected live hash, and what would
    be written. Execution progress is excluded so a running restore never
    invalidates its own approval. Plans hashed before the target ids and the
    payload were covered no longer match and must be planned again.

    A reversal of a write that was never read back is also bound to the payload
    that write sent, which is what it expects to find. It is hashed only when
    present, so every plan stored without one keeps the hash it was reviewed at.
    """
    return _digest(
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
                *(() if action.written_configuration is None else (payload_digest(action.written_configuration),)),
            ]
            for action in sorted(actions, key=lambda item: item.order)
        ]
    )


def compute_intent_hash(operation: RestoreOperation) -> str:
    """Hash what was asked for, which a fresh backup does not change.

    The requester is deliberately left out: operators build drafts and an
    administrator prepares them, which makes the administrator the prepared
    plan's requester. Who may decide is still enforced on the approval itself.
    """
    target_at = (
        operation.target_at if operation.target_at.tzinfo is not None else operation.target_at.replace(tzinfo=UTC)
    )
    return _digest(
        {
            "organization_id": str(operation.organization_id),
            "requested_version_ids": sorted(str(version_id) for version_id in operation.requested_version_ids),
            "mode": str(operation.mode),
            "target_at": target_at.astimezone(UTC).isoformat(),
        }
    )


def compute_action_signature(actions: Sequence[RestoreAction]) -> str:
    """Hash which objects the plan changes and how, ignoring the backup-specific details.

    A reference rewrite has no target of its own: its source is whatever the
    fresh backup just captured, so it always moves and is left out. A delete
    has none either: it removes the object whichever version recorded it last,
    and a preparation that records the object again must not turn the same
    delete into a different change.
    """
    return _digest(
        sorted(
            [
                str(action.logical_object_id),
                str(action.action),
                ""
                if action.reason is RestoreActionReason.REFERENCE_REWRITE or action.action is RestoreActionType.DELETE
                else str(action.source_version_id),
                str(action.reason),
            ]
            for action in actions
        )
    )


def organization_policy(organization: Organization) -> ApprovalPolicy:
    """Read an organization's approval policy, defaulting when unconfigured."""
    policy = getattr(organization, "approval_policy", None)
    if isinstance(policy, ApprovalPolicy):
        return policy
    if isinstance(policy, Mapping):
        return ApprovalPolicy.model_validate(dict(policy))
    return ApprovalPolicy()


def evaluate_approval_policy(
    policy: ApprovalPolicy,
    actions: Sequence[RestoreAction],
    mode: RestoreMode,
) -> list[TriggeredRule]:
    """Return every approval rule this plan triggers, in declaration order."""
    if not policy.enabled or not actions:
        return []

    triggered: list[TriggeredRule] = []
    organization_scoped = [action for action in actions if action.scope == "org"]
    if policy.require_for_organization_scope and organization_scoped:
        triggered.append(
            TriggeredRule(
                rule=ApprovalRule.ORGANIZATION_SCOPE,
                detail=f"{len(organization_scoped)} organization-scope objects are affected",
            )
        )

    deletes = [action for action in actions if action.action is RestoreActionType.DELETE]
    if policy.require_for_exact_deletes and mode is RestoreMode.EXACT and deletes:
        triggered.append(
            TriggeredRule(
                rule=ApprovalRule.EXACT_MODE_DELETES,
                detail=f"Exact mode deletes {len(deletes)} objects",
            )
        )

    threshold = policy.object_count_threshold
    if threshold is not None and len(actions) > threshold:
        triggered.append(
            TriggeredRule(
                rule=ApprovalRule.OBJECT_COUNT_THRESHOLD,
                detail=f"{len(actions)} objects exceed the threshold of {threshold}",
            )
        )

    sensitive_types = {item.lower() for item in policy.sensitive_object_types}
    sensitive = sorted({action.object_type for action in actions if action.object_type.lower() in sensitive_types})
    if sensitive:
        triggered.append(
            TriggeredRule(
                rule=ApprovalRule.SENSITIVE_OBJECT_TYPE,
                detail="Sensitive object types: " + ", ".join(sensitive),
            )
        )
    return triggered


def plan_summary(operation: RestoreOperation) -> str:
    """Describe a plan in one line for approval queues and notifications."""
    counts: dict[str, int] = {}
    for action in operation.actions:
        counts[action.object_type] = counts.get(action.object_type, 0) + 1
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    listed = ", ".join(f"{count} {object_type}" for object_type, count in ordered[:_MAX_SUMMARY_TYPES])
    if len(ordered) > _MAX_SUMMARY_TYPES:
        listed = f"{listed}, +{len(ordered) - _MAX_SUMMARY_TYPES} more"
    mode = "exact" if operation.mode is RestoreMode.EXACT else "non-destructive"
    return f"{len(operation.actions)} actions ({mode}): {listed}" if listed else f"{mode} restore with no actions"


def delete_count(operation: RestoreOperation) -> int:
    """Count the deletes a plan performs."""
    return sum(1 for action in operation.actions if action.action is RestoreActionType.DELETE)


@dataclass(frozen=True, slots=True)
class ApprovalDraft:
    """A fully resolved approval request the store has not yet persisted."""

    organization_id: PydanticObjectId
    restore_operation_id: PydanticObjectId
    requested_by: PydanticObjectId
    requested_by_email: str
    plan_hash: str
    intent_hash: str
    action_signature: str
    triggered_rules: tuple[TriggeredRule, ...]
    expires_at: datetime
    summary: str
    object_count: int
    delete_count: int


class ApprovalStore(Protocol):
    """Persistence operations the approval service depends on."""

    async def find_by_id(
        self,
        organization_id: PydanticObjectId,
        approval_id: PydanticObjectId,
    ) -> RestoreApproval | None:
        """Return one organization-scoped approval by identifier."""

    async def find_by_operation(
        self,
        organization_id: PydanticObjectId,
        restore_operation_id: PydanticObjectId,
    ) -> RestoreApproval | None:
        """Return the approval bound to one restore plan."""

    async def insert(self, draft: ApprovalDraft) -> RestoreApproval:
        """Persist a new approval request."""

    async def save(self, approval: RestoreApproval) -> None:
        """Persist changes to an existing approval request."""

    async def page(
        self,
        organization_id: PydanticObjectId,
        status: ApprovalStatus | None,
        *,
        skip: int,
        limit: int,
    ) -> tuple[list[RestoreApproval], int]:
        """Return one newest-first page of approvals and the matching total."""

    async def load_operation(
        self,
        organization_id: PydanticObjectId,
        restore_operation_id: PydanticObjectId,
    ) -> RestoreOperation | None:
        """Return the restore plan an approval is bound to."""


class BeanieApprovalStore:
    """MongoDB-backed approval storage, scoped by organization everywhere."""

    async def find_by_id(
        self,
        organization_id: PydanticObjectId,
        approval_id: PydanticObjectId,
    ) -> RestoreApproval | None:
        """Return one organization-scoped approval by identifier."""
        return await RestoreApproval.find_one(
            RestoreApproval.id == approval_id,
            RestoreApproval.organization_id == organization_id,
        )

    async def find_by_operation(
        self,
        organization_id: PydanticObjectId,
        restore_operation_id: PydanticObjectId,
    ) -> RestoreApproval | None:
        """Return the approval bound to one restore plan."""
        return await RestoreApproval.find_one(
            RestoreApproval.restore_operation_id == restore_operation_id,
            RestoreApproval.organization_id == organization_id,
        )

    async def insert(self, draft: ApprovalDraft) -> RestoreApproval:
        """Persist a new approval request."""
        approval = RestoreApproval(
            organization_id=draft.organization_id,
            restore_operation_id=draft.restore_operation_id,
            requested_by=draft.requested_by,
            requested_by_email=draft.requested_by_email,
            plan_hash=draft.plan_hash,
            intent_hash=draft.intent_hash,
            action_signature=draft.action_signature,
            triggered_rules=list(draft.triggered_rules),
            expires_at=draft.expires_at,
            summary=draft.summary,
            object_count=draft.object_count,
            delete_count=draft.delete_count,
        )
        return await approval.insert()

    async def save(self, approval: RestoreApproval) -> None:
        """Persist changes to an existing approval request."""
        approval.touch()
        await approval.save()

    async def page(
        self,
        organization_id: PydanticObjectId,
        status: ApprovalStatus | None,
        *,
        skip: int,
        limit: int,
    ) -> tuple[list[RestoreApproval], int]:
        """Return one newest-first page of approvals and the matching total."""
        criteria: dict[str, object] = {"organization_id": organization_id}
        if status is not None:
            criteria["status"] = status
        query = RestoreApproval.find(criteria)
        total = await query.count()
        items = await query.sort("-created_at").skip(skip).limit(limit).to_list()
        return items, total

    async def load_operation(
        self,
        organization_id: PydanticObjectId,
        restore_operation_id: PydanticObjectId,
    ) -> RestoreOperation | None:
        """Return the restore plan an approval is bound to."""
        return await RestoreOperation.find_one(
            RestoreOperation.id == restore_operation_id,
            RestoreOperation.organization_id == organization_id,
        )


class ApprovalService:
    """Create, decide, and enforce two-person restore approvals."""

    def __init__(
        self,
        store: ApprovalStore | None = None,
        notifications: NotificationService | None = None,
    ) -> None:
        self._store: ApprovalStore = store or BeanieApprovalStore()
        self._notifications = notifications or NotificationService()

    # ----------------------------------------------------------------- write
    async def request(
        self,
        organization: Organization,
        operation: RestoreOperation,
        requester: User,
    ) -> RestoreApproval:
        """Open, or return, the approval request bound to this plan hash."""
        if operation.id is None or requester.id is None or organization.id is None:
            msg = "Approval requires persisted organization, plan, and requester identifiers"
            raise ApprovalError(msg)
        if operation.status is not RestoreStatus.PLANNED:
            msg = "This restore plan is no longer awaiting approval"
            raise ApprovalError(msg)

        policy = organization_policy(organization)
        triggered = evaluate_approval_policy(policy, operation.actions, operation.mode)
        plan_hash = compute_plan_hash(operation.actions)
        existing = await self.for_operation(operation)
        if existing is not None:
            return await self._reopen(existing, policy, triggered, plan_hash, operation)

        approval = await self._store.insert(
            ApprovalDraft(
                organization_id=organization.id,
                restore_operation_id=operation.id,
                requested_by=requester.id,
                requested_by_email=requester.email,
                plan_hash=plan_hash,
                intent_hash=compute_intent_hash(operation),
                action_signature=compute_action_signature(operation.actions),
                triggered_rules=tuple(triggered),
                expires_at=utc_now() + timedelta(hours=policy.expiry_hours),
                summary=plan_summary(operation),
                object_count=len(operation.actions),
                delete_count=delete_count(operation),
            )
        )
        await self._announce(approval)
        return approval

    async def decide(
        self,
        organization_id: PydanticObjectId,
        approval_id: PydanticObjectId,
        decider: User,
        *,
        approved: bool,
        reason: str | None = None,
    ) -> RestoreApproval:
        """Record a second administrator's decision on one approval."""
        approval = await self.get(organization_id, approval_id)
        if approval is None:
            msg = "Approval request not found"
            raise ApprovalError(msg)
        if decider.id is not None and approval.requested_by == decider.id:
            msg = "The requester cannot approve or reject their own restore request"
            raise SelfApprovalError(msg)
        if approval.status is not ApprovalStatus.PENDING:
            msg = f"This approval request is already {approval.status}"
            raise ApprovalError(msg)

        approval.status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
        approval.decided_by = decider.id
        approval.decided_by_email = decider.email
        approval.decided_at = utc_now()
        approval.decision_reason = reason
        await self._store.save(approval)
        return approval

    async def carry_to_prepared(self, source: RestoreOperation, prepared: RestoreOperation) -> CarryOutcome:
        """Move a draft's approval onto the plan its fresh backup produced, when nothing that was reviewed changed.

        A prepared session lasts minutes and an approver may take hours, so the
        decision is made on the draft. It stays valid for the prepared plan only
        when the request and the set of changes are the same; the plan hash is
        rebound because the baseline hashes necessarily differ. The requester,
        decision and expiry travel unchanged, so the requester still cannot
        decide it and it expires when it would have.
        """
        if prepared.id is None:
            return "no_approval"
        approval = await self.for_operation(source)
        if approval is None or approval.status not in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}:
            return "no_approval"
        if approval.intent_hash != compute_intent_hash(
            prepared
        ) or approval.action_signature != compute_action_signature(prepared.actions):
            await self._invalidate_if_superseded(approval, source)
            return "not_carried"
        approval.restore_operation_id = prepared.id
        approval.plan_hash = compute_plan_hash(prepared.actions)
        approval.summary = plan_summary(prepared)
        approval.object_count = len(prepared.actions)
        approval.delete_count = delete_count(prepared)
        await self._store.save(approval)
        return "carried"

    # ------------------------------------------------------------------ read
    async def get(
        self,
        organization_id: PydanticObjectId,
        approval_id: PydanticObjectId,
    ) -> RestoreApproval | None:
        """Return one organization-scoped approval with a refreshed status."""
        approval = await self._store.find_by_id(organization_id, approval_id)
        return None if approval is None else await self._refresh(approval)

    async def load_plan(
        self,
        organization_id: PydanticObjectId,
        restore_operation_id: PydanticObjectId,
    ) -> RestoreOperation | None:
        """Return one organization-scoped restore plan for review."""
        return await self._store.load_operation(organization_id, restore_operation_id)

    async def for_operation(self, operation: RestoreOperation) -> RestoreApproval | None:
        """Return the approval bound to one restore plan, status refreshed."""
        if operation.id is None:
            return None
        approval = await self._store.find_by_operation(operation.organization_id, operation.id)
        return None if approval is None else await self._refresh(approval, operation)

    async def list(
        self,
        organization_id: PydanticObjectId,
        *,
        status: ApprovalStatus | None = None,
        skip: int = 0,
        limit: int = 25,
    ) -> tuple[list[RestoreApproval], int]:
        """Return one newest-first page of approvals and its total."""
        approvals, total = await self._store.page(organization_id, status, skip=skip, limit=limit)
        return [await self._refresh(approval) for approval in approvals], total

    # -------------------------------------------------------------- enforce
    async def assert_execution_allowed(
        self,
        organization: Organization,
        operation: RestoreOperation,
    ) -> RestoreApproval | None:
        """Block execution unless policy-required approval is in force."""
        approval = await self.for_operation(operation)
        required = bool(
            evaluate_approval_policy(
                organization_policy(organization),
                operation.actions,
                operation.mode,
            )
        )
        if approval is None:
            if required:
                msg = "This restore requires approval by a second administrator before execution"
                raise ApprovalRequiredError(msg)
            return None
        if approval.status is ApprovalStatus.APPROVED:
            return approval
        raise ApprovalRequiredError(_BLOCKED_MESSAGES[approval.status])

    # -------------------------------------------------------------- internal
    async def _reopen(
        self,
        approval: RestoreApproval,
        policy: ApprovalPolicy,
        triggered: Sequence[TriggeredRule],
        plan_hash: str,
        operation: RestoreOperation,
    ) -> RestoreApproval:
        if approval.status in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}:
            return approval
        if approval.status is ApprovalStatus.REJECTED:
            msg = "This restore plan was rejected; create a new plan to request approval again"
            raise ApprovalError(msg)
        approval.status = ApprovalStatus.PENDING
        approval.plan_hash = plan_hash
        approval.intent_hash = compute_intent_hash(operation)
        approval.action_signature = compute_action_signature(operation.actions)
        approval.triggered_rules = list(triggered)
        approval.decided_by = None
        approval.decided_by_email = None
        approval.decided_at = None
        approval.decision_reason = None
        approval.expires_at = utc_now() + timedelta(hours=policy.expiry_hours)
        approval.summary = plan_summary(operation)
        approval.object_count = len(operation.actions)
        approval.delete_count = delete_count(operation)
        await self._store.save(approval)
        await self._announce(approval)
        return approval

    async def _invalidate_if_superseded(self, approval: RestoreApproval, source: RestoreOperation) -> None:
        """Retire an approval its superseded draft can no longer use.

        A superseded draft is never prepared or executed again, so a pending or
        granted decision left on it would sit in the queue with nothing to
        apply to. The stored draft is read rather than the copy the caller
        loaded before preparing: that copy predates the supersede. A draft that
        was not superseded, because another preparation got there first, keeps
        its approval.
        """
        if source.id is None:
            return
        stored = await self._store.load_operation(source.organization_id, source.id)
        if stored is None or stored.status != RestoreStatus.SUPERSEDED:
            return
        approval.status = ApprovalStatus.INVALIDATED
        await self._store.save(approval)

    async def _announce(self, approval: RestoreApproval) -> None:
        if approval.id is None:
            return
        await self._notifications.notify_approval_requested(
            organization_id=approval.organization_id,
            restore_id=str(approval.restore_operation_id),
            approval_id=str(approval.id),
            requested_by=approval.requested_by_email,
        )

    async def _refresh(
        self,
        approval: RestoreApproval,
        operation: RestoreOperation | None = None,
    ) -> RestoreApproval:
        """Fold plan staleness and expiry into the persisted status."""
        if approval.status not in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}:
            return approval
        plan = operation or await self._store.load_operation(
            approval.organization_id,
            approval.restore_operation_id,
        )
        resolved = approval.status
        if plan is None or compute_plan_hash(plan.actions) != approval.plan_hash:
            resolved = ApprovalStatus.INVALIDATED
        elif approval.expires_at <= utc_now():
            resolved = ApprovalStatus.EXPIRED
        if resolved is approval.status:
            return approval
        approval.status = resolved
        await self._store.save(approval)
        return approval


_BLOCKED_MESSAGES: dict[ApprovalStatus, str] = {
    ApprovalStatus.PENDING: "This restore is waiting for approval by a second administrator",
    ApprovalStatus.REJECTED: "This restore was rejected by an administrator",
    ApprovalStatus.EXPIRED: "This restore approval expired; request approval again",
    ApprovalStatus.INVALIDATED: "The plan changed after it was approved; request approval again",
    ApprovalStatus.APPROVED: "This restore is approved",
}


async def expire_pending_approvals() -> int:
    """Mark every pending approval past its expiry window as expired."""
    result = await RestoreApproval.find(
        RestoreApproval.status == ApprovalStatus.PENDING,
        {"expires_at": {"$lte": utc_now()}},
    ).update_many(
        {
            "$set": {
                "status": ApprovalStatus.EXPIRED,
                "updated_at": utc_now(),
            }
        }
    )
    return int(result.modified_count)
