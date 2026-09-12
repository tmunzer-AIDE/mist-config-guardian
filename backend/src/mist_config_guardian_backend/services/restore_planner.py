"""Dependency-aware immutable restore planning and plan-lifecycle state.

Plan hashes, safety snapshots, verification results, and the link between a
failed restore and its compensation live in a sidecar collection keyed by
operation id. They are deliberately not attributes of ``RestoreOperation``:
:meth:`beanie.Document.save` replaces the whole document, so state written
outside the model would be erased by the executor's own progress writes.
"""

from collections import deque
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol

from beanie import PydanticObjectId
from pydantic import BaseModel, Field

from mist_config_guardian_backend.config import get_settings
from mist_config_guardian_backend.models.approval import ApprovalPolicy, TriggeredRule
from mist_config_guardian_backend.models.restore import (
    RestoreAction,
    RestoreActionType,
    RestoreMode,
    RestoreOperation,
    RestoreOperationStateRecord,
)
from mist_config_guardian_backend.models.snapshot import (
    LogicalObject,
    ObjectIncarnation,
    ObjectVersion,
)
from mist_config_guardian_backend.security.credentials import CredentialDecryptionError, CredentialVault
from mist_config_guardian_backend.services.approvals import (
    compute_plan_hash,
    evaluate_approval_policy,
)
from mist_config_guardian_backend.snapshots.registry import get_definition
from mist_config_guardian_backend.snapshots.secrets import (
    find_unavailable_secrets,
    format_secret_path,
    protect_configuration,
    reveal_configuration,
)

VerificationStatus = Literal["ok", "failed", "skipped"]


class RestorePlanningError(ValueError):
    """Raised when selected history cannot form a safe restore plan."""


class SafetySnapshotEntry(BaseModel):
    """The pre-restore state of one object a plan may modify."""

    logical_object_id: PydanticObjectId
    order: int
    action: RestoreActionType
    scope: Literal["org", "site"]
    object_type: str
    object_name: str
    mist_object_id: str
    site_mist_id: str | None = None
    existed: bool = False
    configuration: dict[str, object] = Field(default_factory=dict)
    configuration_hash: str | None = None
    pre_version_id: PydanticObjectId | None = None


class VerificationCheck(BaseModel):
    """One named post-restore check and its outcome."""

    label: str
    status: VerificationStatus
    detail: str | None = None


class RestoreVerificationResult(BaseModel):
    """Everything the post-restore verification pass established."""

    verified: bool = False
    checks: list[VerificationCheck] = Field(default_factory=list)
    post_snapshot_id: str | None = None
    monitoring_session_ids: list[str] = Field(default_factory=list)


class RestoreOperationState(BaseModel):
    """Lifecycle state that belongs to a plan but not to its action list."""

    organization_id: PydanticObjectId
    operation_id: PydanticObjectId
    plan_hash: str
    triggered_rules: list[TriggeredRule] = Field(default_factory=list)
    safety_snapshot: list[SafetySnapshotEntry] = Field(default_factory=list)
    verification: RestoreVerificationResult | None = None
    compensates_operation_id: PydanticObjectId | None = None
    compensation_operation_id: PydanticObjectId | None = None


class RestoreStateStore(Protocol):
    """Persistence for plan-lifecycle state outside the operation document."""

    async def load(
        self,
        organization_id: PydanticObjectId,
        operation_id: PydanticObjectId,
    ) -> RestoreOperationState | None:
        """Return the stored state for one operation, if any."""

    async def save(self, state: RestoreOperationState) -> None:
        """Insert or replace the state for one operation."""

    async def find_compensation_of(
        self,
        organization_id: PydanticObjectId,
        operation_id: PydanticObjectId,
    ) -> RestoreOperationState | None:
        """Return the state of the plan that compensates this operation."""


class MongoRestoreStateStore:
    """Plan-lifecycle state backed by the registered state document.

    Going through Beanie rather than the raw collection is what gives the
    collection its unique and lookup indexes at start-up; the raw handle it used
    before left every load scanning.
    """

    async def load(
        self,
        organization_id: PydanticObjectId,
        operation_id: PydanticObjectId,
    ) -> RestoreOperationState | None:
        """Return the stored state for one operation, if any."""
        record = await RestoreOperationStateRecord.find_one(
            RestoreOperationStateRecord.organization_id == organization_id,
            RestoreOperationStateRecord.operation_id == operation_id,
        )
        return None if record is None else _state_from_record(record)

    async def save(self, state: RestoreOperationState) -> None:
        """Insert or replace the state for one operation."""
        record = await RestoreOperationStateRecord.find_one(
            RestoreOperationStateRecord.organization_id == state.organization_id,
            RestoreOperationStateRecord.operation_id == state.operation_id,
        )
        fields = state.model_dump(mode="json")
        triggered_rules = list(fields["triggered_rules"])
        safety_snapshot = list(fields["safety_snapshot"])
        verification = fields["verification"]
        if record is None:
            record = RestoreOperationStateRecord(
                organization_id=state.organization_id,
                operation_id=state.operation_id,
                plan_hash=state.plan_hash,
                triggered_rules=triggered_rules,
                safety_snapshot=safety_snapshot,
                verification=verification,
                compensates_operation_id=state.compensates_operation_id,
                compensation_operation_id=state.compensation_operation_id,
            )
            await record.insert()
            return
        record.plan_hash = state.plan_hash
        record.triggered_rules = triggered_rules
        record.safety_snapshot = safety_snapshot
        record.verification = verification
        record.compensates_operation_id = state.compensates_operation_id
        record.compensation_operation_id = state.compensation_operation_id
        record.touch()
        await record.save()

    async def find_compensation_of(
        self,
        organization_id: PydanticObjectId,
        operation_id: PydanticObjectId,
    ) -> RestoreOperationState | None:
        """Return the state of the plan that compensates this operation."""
        record = await RestoreOperationStateRecord.find_one(
            RestoreOperationStateRecord.organization_id == organization_id,
            RestoreOperationStateRecord.compensates_operation_id == operation_id,
        )
        return None if record is None else _state_from_record(record)


def _state_from_record(record: RestoreOperationStateRecord) -> RestoreOperationState:
    """Rebuild the transfer model from a stored document."""
    return RestoreOperationState.model_validate(
        {
            "organization_id": record.organization_id,
            "operation_id": record.operation_id,
            "plan_hash": record.plan_hash,
            "triggered_rules": record.triggered_rules,
            "safety_snapshot": record.safety_snapshot,
            "verification": record.verification,
            "compensates_operation_id": record.compensates_operation_id,
            "compensation_operation_id": record.compensation_operation_id,
        }
    )


class RestorePlanRepository(Protocol):
    """Organization-scoped reads of persisted restore plans."""

    async def load(
        self,
        organization_id: PydanticObjectId,
        operation_id: PydanticObjectId,
    ) -> RestoreOperation | None:
        """Return one restore operation belonging to this organization."""

    async def page(
        self,
        organization_id: PydanticObjectId,
        *,
        skip: int,
        limit: int,
    ) -> tuple[list[RestoreOperation], int]:
        """Return one newest-first page of restore operations and its total."""


class BeanieRestorePlanRepository:
    """MongoDB-backed restore plan reads."""

    async def load(
        self,
        organization_id: PydanticObjectId,
        operation_id: PydanticObjectId,
    ) -> RestoreOperation | None:
        """Return one restore operation belonging to this organization."""
        return await RestoreOperation.find_one(
            RestoreOperation.id == operation_id,
            RestoreOperation.organization_id == organization_id,
        )

    async def page(
        self,
        organization_id: PydanticObjectId,
        *,
        skip: int,
        limit: int,
    ) -> tuple[list[RestoreOperation], int]:
        """Return one newest-first page of restore operations and its total."""
        query = RestoreOperation.find(RestoreOperation.organization_id == organization_id)
        total = await query.count()
        items = await query.sort("-created_at").skip(skip).limit(limit).to_list()
        return items, total


def get_restore_plan_repository() -> RestorePlanRepository:
    """Build the default MongoDB restore plan repository."""
    return BeanieRestorePlanRepository()


def get_restore_state_store() -> RestoreStateStore:
    """Build the default MongoDB plan-state store."""
    return MongoRestoreStateStore()


async def load_or_build_state(
    store: RestoreStateStore,
    operation: RestoreOperation,
) -> RestoreOperationState:
    """Return the persisted plan state, materializing it when absent."""
    if operation.id is None:
        msg = "Persisted restore operation is missing an identifier"
        raise RestorePlanningError(msg)
    state = await store.load(operation.organization_id, operation.id)
    if state is not None:
        return state
    return RestoreOperationState(
        organization_id=operation.organization_id,
        operation_id=operation.id,
        plan_hash=compute_plan_hash(operation.actions),
    )


async def assert_plan_current(
    store: RestoreStateStore,
    operation: RestoreOperation,
) -> str:
    """Fail closed when the persisted plan no longer hashes as reviewed."""
    if operation.id is None:
        msg = "Persisted restore operation is missing an identifier"
        raise RestorePlanningError(msg)
    current = compute_plan_hash(operation.actions)
    state = await store.load(operation.organization_id, operation.id)
    if state is not None and state.plan_hash != current:
        msg = "This restore plan changed after it was reviewed; create a new plan"
        raise RestorePlanningError(msg)
    return current


def validate_action_capabilities(actions: Sequence[RestoreAction]) -> list[str]:
    """Return one preflight error per action the registry cannot perform."""
    errors: list[str] = []
    for action in actions:
        definition = get_definition(action.scope, action.object_type)
        if definition is None or not definition.supports_restore_action(action.action):
            errors.append(
                f"{action.object_name}: {action.action} is not supported for {action.scope}:{action.object_type}"
            )
    return errors


def unavailable_secret_errors(
    actions: Sequence[RestoreAction],
    vault: CredentialVault,
) -> list[str]:
    """Return one preflight error per action carrying a secret Mist never returned.

    Mist masks values such as a RADIUS shared secret on read, so the snapshot
    holds the mask and not the secret. The executor writes a version back
    verbatim, which would replace a working credential with asterisks, so such
    an action cannot run. Naming it here rather than at authorization is the
    point: the reviewer sees it beside the plan, before an administrator
    credential has been entered for a restore that was never going to run.
    """
    errors: list[str] = []
    for action in actions:
        if action.action is RestoreActionType.DELETE:
            # A delete sends no configuration, so a mask cannot reach Mist.
            continue
        definition = get_definition(action.scope, action.object_type)
        if definition is None:
            errors.append(f"Unsupported restore type: {action.scope}:{action.object_type}")
            continue
        try:
            configuration = reveal_configuration(action.protected_configuration, vault)
        except CredentialDecryptionError:
            # A version whose secrets will not decrypt cannot be replayed
            # either, and this is where that is said. Letting it propagate
            # would fail the whole planning request rather than describing the
            # one action that cannot run.
            errors.append(f"{action.object_name} has secrets that cannot be decrypted with the current key")
            continue
        missing = find_unavailable_secrets(configuration, definition.sensitive_fields)
        if missing:
            fields = ", ".join(sorted(format_secret_path(path) for path in missing))
            errors.append(f"{action.object_name} requires unavailable secret values: {fields}")
    return errors


async def latest_version(logical_id: PydanticObjectId) -> ObjectVersion | None:
    """Return the newest immutable version recorded for a logical object."""
    return await ObjectVersion.find(ObjectVersion.logical_object_id == logical_id).sort("-version").first_or_none()


@dataclass
class PlanningContext:
    """Mutable target set while dependencies are expanded."""

    organization_id: PydanticObjectId
    selected: dict[PydanticObjectId, ObjectVersion]
    logical_objects: dict[PydanticObjectId, LogicalObject]
    force_delete: set[PydanticObjectId]
    target_at: datetime
    mode: RestoreMode


class RestorePlanner:
    """Build reviewable plans without making Mist API writes."""

    def __init__(
        self,
        store: RestoreStateStore | None = None,
        policy: ApprovalPolicy | None = None,
        vault: CredentialVault | None = None,
        baseline_reader: Callable[
            [dict[PydanticObjectId, LogicalObject]], Awaitable[dict[PydanticObjectId, ObjectVersion]]
        ]
        | None = None,
    ) -> None:
        self._store = store or get_restore_state_store()
        self._policy = policy
        # Reading a version's secrets is what decides whether it can be
        # replayed at all, so planning needs the vault the snapshot was
        # written with.
        self._vault = vault or CredentialVault(get_settings())
        self._baseline_reader = baseline_reader
        self._baselines: dict[PydanticObjectId, ObjectVersion] = {}

    async def create_plan(
        self,
        *,
        organization_id: PydanticObjectId,
        requested_by: PydanticObjectId,
        version_ids: list[PydanticObjectId],
        mode: RestoreMode,
        include_dependencies: bool,
    ) -> RestoreOperation:
        """Build and persist a dependency-ordered multi-object plan."""
        if not version_ids:
            msg = "At least one version is required"
            raise RestorePlanningError(msg)

        selected: dict[PydanticObjectId, ObjectVersion] = {}
        logical_objects: dict[PydanticObjectId, LogicalObject] = {}
        force_delete: set[PydanticObjectId] = set()
        for version_id in version_ids:
            version = await ObjectVersion.get(version_id)
            if version is None or version.organization_id != organization_id:
                msg = "One or more selected versions were not found"
                raise RestorePlanningError(msg)
            if version.logical_object_id in selected:
                msg = "Only one target version may be selected per object"
                raise RestorePlanningError(msg)
            logical = await LogicalObject.get(version.logical_object_id)
            if logical is None:
                msg = "A selected version has no logical object"
                raise RestorePlanningError(msg)
            selected[version.logical_object_id] = version
            logical_objects[version.logical_object_id] = logical

        target_at = min(version.observed_at for version in selected.values())
        if include_dependencies:
            await self._expand_dependencies(
                PlanningContext(
                    organization_id=organization_id,
                    selected=selected,
                    logical_objects=logical_objects,
                    force_delete=force_delete,
                    target_at=target_at,
                    mode=mode,
                )
            )

        if self._baseline_reader is not None:
            self._baselines = await self._baseline_reader(logical_objects)
        actions = await self._build_actions(
            organization_id,
            selected,
            logical_objects,
            force_delete,
        )
        self._add_containment_delete_dependencies(actions)
        actions = order_restore_actions(actions)
        preflight_errors = validate_action_capabilities(actions) + unavailable_secret_errors(actions, self._vault)
        triggered = evaluate_approval_policy(self._policy or ApprovalPolicy(), actions, mode)
        warnings = [] if actions else ["Selected versions already match the recorded current state"]
        if triggered:
            rules = ", ".join(rule.detail for rule in triggered)
            warnings.append(f"Approval by a second administrator is required before execution: {rules}")
        operation = RestoreOperation(
            organization_id=organization_id,
            requested_by=requested_by,
            mode=mode,
            include_dependencies=include_dependencies,
            requested_version_ids=list(version_ids),
            target_at=target_at,
            actions=actions,
            warnings=warnings,
            preflight_errors=preflight_errors,
        )
        await operation.insert()
        if operation.id is not None:
            await self._store.save(
                RestoreOperationState(
                    organization_id=organization_id,
                    operation_id=operation.id,
                    plan_hash=compute_plan_hash(actions),
                    triggered_rules=triggered,
                )
            )
        return operation

    async def _expand_dependencies(self, context: PlanningContext) -> None:
        pending = deque(context.selected.values())
        while pending:
            version = pending.popleft()
            logical = context.logical_objects[version.logical_object_id]
            related = await self._related_logical_objects(
                context.organization_id,
                logical,
                version,
            )
            for related_logical in related:
                if related_logical.id is None or related_logical.id in context.selected:
                    continue
                target_version = await self._version_at(
                    related_logical.id,
                    context.target_at,
                )
                if target_version is None:
                    if context.mode is RestoreMode.NON_DESTRUCTIVE:
                        continue
                    target_version = await self._latest_version(related_logical.id)
                    if target_version is None:
                        continue
                    context.force_delete.add(related_logical.id)
                context.selected[related_logical.id] = target_version
                context.logical_objects[related_logical.id] = related_logical
                pending.append(target_version)
            if logical.is_deleted and not version.is_deleted:
                reverse_dependents = await self._reverse_dependents(
                    context.organization_id,
                    logical,
                )
                for dependent, current_version in reverse_dependents:
                    if dependent.id is None or dependent.id in context.selected:
                        continue
                    context.selected[dependent.id] = current_version
                    context.logical_objects[dependent.id] = dependent
                    pending.append(current_version)

    async def _related_logical_objects(
        self,
        organization_id: PydanticObjectId,
        logical: LogicalObject,
        version: ObjectVersion,
    ) -> list[LogicalObject]:
        related: dict[PydanticObjectId, LogicalObject] = {}
        if logical.object_type == "data":
            candidates = await LogicalObject.find(LogicalObject.organization_id == organization_id).to_list()
            related.update({item.id: item for item in candidates if item.id is not None})
        elif logical.object_type == "sites":
            candidates = await LogicalObject.find(
                LogicalObject.organization_id == organization_id,
                LogicalObject.site_mist_id == logical.current_mist_id,
            ).to_list()
            related.update({item.id: item for item in candidates if item.id is not None})

        for reference in version.references:
            incarnation = await ObjectIncarnation.find_one(
                ObjectIncarnation.organization_id == organization_id,
                ObjectIncarnation.mist_object_id == reference.target_mist_id,
            )
            if incarnation is None:
                continue
            referenced = await LogicalObject.get(incarnation.logical_object_id)
            if referenced is not None and referenced.id is not None:
                related[referenced.id] = referenced
        return list(related.values())

    async def _reverse_dependents(
        self,
        organization_id: PydanticObjectId,
        logical: LogicalObject,
    ) -> list[tuple[LogicalObject, ObjectVersion]]:
        candidates = await ObjectVersion.find(
            ObjectVersion.organization_id == organization_id,
            {"references.target_mist_id": logical.current_mist_id},
        ).to_list()
        dependents: list[tuple[LogicalObject, ObjectVersion]] = []
        seen: set[PydanticObjectId] = set()
        for candidate in candidates:
            if candidate.logical_object_id in seen:
                continue
            current = await self._latest_version(candidate.logical_object_id)
            if current is None or current.id != candidate.id or current.is_deleted:
                continue
            dependent = await LogicalObject.get(candidate.logical_object_id)
            if dependent is None or dependent.id is None:
                continue
            seen.add(dependent.id)
            dependents.append((dependent, current))
        return dependents

    async def _build_actions(
        self,
        organization_id: PydanticObjectId,
        selected: dict[PydanticObjectId, ObjectVersion],
        logical_objects: dict[PydanticObjectId, LogicalObject],
        force_delete: set[PydanticObjectId],
    ) -> list[RestoreAction]:
        actions: list[RestoreAction] = []
        for logical_id, target in selected.items():
            logical = logical_objects[logical_id]
            latest = self._baselines.get(logical_id) or await self._latest_version(logical_id)
            if latest is None or target.id is None:
                continue
            definition = get_definition(logical.scope, logical.object_type)
            if (
                logical_id in self._baselines
                and not logical.is_deleted
                and not target.is_deleted
                and logical_id not in force_delete
                and definition is not None
                and target.configuration_hash == latest.configuration_hash
            ):
                continue
            action_type = self._action_type(
                logical,
                target,
                latest,
                force_delete=logical_id in force_delete,
            )
            if action_type is None:
                continue
            dependencies = await self._action_dependencies(
                organization_id,
                target,
                selected,
                logical_objects,
                action_type,
            )
            actions.append(
                RestoreAction(
                    logical_object_id=logical_id,
                    source_version_id=target.id,
                    baseline_version_id=latest.id if logical_id in self._baselines else None,
                    order=0,
                    action=action_type,
                    scope=logical.scope,
                    object_type=logical.object_type,
                    object_name=logical.name,
                    current_mist_id=logical.current_mist_id,
                    site_mist_id=logical.site_mist_id,
                    protected_configuration=protect_configuration(
                        target.configuration,
                        self._vault,
                        sensitive_fields=definition.sensitive_fields,
                    )
                    if definition is not None
                    else target.configuration,
                    expected_current_hash=(None if logical.is_deleted else latest.configuration_hash),
                    depends_on=dependencies,
                )
            )
        return actions

    @staticmethod
    def _add_containment_delete_dependencies(actions: list[RestoreAction]) -> None:
        delete_actions = {
            action.logical_object_id: action for action in actions if action.action is RestoreActionType.DELETE
        }
        for parent in delete_actions.values():
            if parent.object_type == "sites":
                children = [
                    action.logical_object_id
                    for action in delete_actions.values()
                    if action.site_mist_id == parent.current_mist_id
                ]
                parent.depends_on = sorted(set(parent.depends_on) | set(children), key=str)
            elif parent.object_type == "data":
                children = [
                    action.logical_object_id
                    for action in delete_actions.values()
                    if action.logical_object_id != parent.logical_object_id
                ]
                parent.depends_on = sorted(set(parent.depends_on) | set(children), key=str)

    async def _action_dependencies(
        self,
        organization_id: PydanticObjectId,
        target: ObjectVersion,
        selected: dict[PydanticObjectId, ObjectVersion],
        logical_objects: dict[PydanticObjectId, LogicalObject],
        action_type: RestoreActionType,
    ) -> list[PydanticObjectId]:
        dependencies: set[PydanticObjectId] = set()
        if action_type is not RestoreActionType.DELETE:
            for reference in target.references:
                incarnation = await ObjectIncarnation.find_one(
                    ObjectIncarnation.organization_id == organization_id,
                    ObjectIncarnation.mist_object_id == reference.target_mist_id,
                )
                if (
                    incarnation is not None
                    and incarnation.logical_object_id in selected
                    and logical_objects[incarnation.logical_object_id].is_deleted
                ):
                    dependencies.add(incarnation.logical_object_id)

            logical = logical_objects[target.logical_object_id]
            if logical.site_mist_id:
                site = await LogicalObject.find_one(
                    LogicalObject.organization_id == organization_id,
                    LogicalObject.object_type == "sites",
                    LogicalObject.current_mist_id == logical.site_mist_id,
                )
                if site is not None and site.id in selected and site.is_deleted:
                    dependencies.add(site.id)
        return sorted(dependencies, key=str)

    @staticmethod
    def _action_type(
        logical: LogicalObject,
        target: ObjectVersion,
        latest: ObjectVersion,
        *,
        force_delete: bool,
    ) -> RestoreActionType | None:
        if force_delete:
            return None if logical.is_deleted else RestoreActionType.DELETE
        if target.is_deleted:
            return None if logical.is_deleted else RestoreActionType.DELETE
        if logical.is_deleted:
            definition = get_definition(logical.scope, logical.object_type)
            if definition is not None and not definition.is_list:
                return RestoreActionType.UPDATE
            return RestoreActionType.CREATE
        if target.id == latest.id:
            return None
        return RestoreActionType.UPDATE

    @staticmethod
    async def _version_at(
        logical_id: PydanticObjectId,
        target_at: datetime,
    ) -> ObjectVersion | None:
        return (
            await ObjectVersion.find(
                ObjectVersion.logical_object_id == logical_id,
                {"observed_at": {"$lte": target_at}},
            )
            .sort("-observed_at")
            .first_or_none()
        )

    @staticmethod
    async def _latest_version(logical_id: PydanticObjectId) -> ObjectVersion | None:
        return await latest_version(logical_id)


def order_restore_actions(actions: list[RestoreAction]) -> list[RestoreAction]:
    """Topologically order actions and fail closed on dependency cycles."""
    by_id = {action.logical_object_id: action for action in actions}
    dependencies = {
        action.logical_object_id: {item for item in action.depends_on if item in by_id} for action in actions
    }
    ordered: list[RestoreAction] = []
    while dependencies:
        ready = sorted(
            (object_id for object_id, values in dependencies.items() if not values),
            key=lambda object_id: (
                _action_priority(by_id[object_id].action),
                by_id[object_id].object_type,
                by_id[object_id].object_name,
            ),
        )
        if not ready:
            msg = "Restore dependency graph contains a cycle"
            raise RestorePlanningError(msg)
        for object_id in ready:
            action = by_id[object_id]
            action.order = len(ordered)
            ordered.append(action)
            dependencies.pop(object_id)
            for remaining in dependencies.values():
                remaining.discard(object_id)
    return ordered


def _action_priority(action: RestoreActionType) -> int:
    return {
        RestoreActionType.CREATE: 0,
        RestoreActionType.UPDATE: 1,
        RestoreActionType.DELETE: 2,
    }[action]
