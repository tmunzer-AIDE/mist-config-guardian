"""Pre-restore safety snapshots and the compensating plans built from them.

Mist has no transactional multi-object write, so the only way to undo a partly
applied restore is to record what every object looked like immediately before
the first write and replay that state in reverse. The snapshot is captured in
the same pass that revalidates live state, so nothing is written before the
inverse of every planned write is known.
"""

import logging

from beanie import PydanticObjectId

from mist_config_guardian_backend.config import get_settings
from mist_config_guardian_backend.integrations.mist_mutation import (
    MistMutationClient,
    MistMutationError,
)
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.restore import (
    RestoreAction,
    RestoreActionStatus,
    RestoreActionType,
    RestoreOperation,
    RestoreStatus,
)
from mist_config_guardian_backend.models.snapshot import ObjectVersion
from mist_config_guardian_backend.security.credentials import (
    CredentialDecryptionError,
    CredentialVault,
)
from mist_config_guardian_backend.services.approvals import compute_plan_hash
from mist_config_guardian_backend.services.restore_planner import (
    RestoreOperationState,
    RestoreStateStore,
    SafetySnapshotEntry,
    get_restore_state_store,
    latest_version,
    load_or_build_state,
    validate_action_capabilities,
)
from mist_config_guardian_backend.snapshots.canonical import (
    configuration_hash,
    configuration_hash_matches,
)
from mist_config_guardian_backend.snapshots.registry import get_definition
from mist_config_guardian_backend.snapshots.secrets import protect_configuration, reveal_configuration

logger = logging.getLogger(__name__)


class RestoreCompensationError(ValueError):
    """Raised when a compensating plan cannot be built or executed."""


async def capture_safety_snapshot(
    client: MistMutationClient,
    organization: Organization,
    operation: RestoreOperation,
    vault: CredentialVault,
    *,
    relaxed: bool = False,
) -> list[SafetySnapshotEntry]:
    """Revalidate live state and record the pre-restore state of every target.

    ``relaxed`` is used when executing a compensating plan. The plan-time hash
    of a compensation describes state Mist has already replaced, so existence
    is enforced but equality is not: the safety snapshot, not the hash, is the
    authority on what must be put back.
    """
    entries: list[SafetySnapshotEntry] = []
    for action in operation.actions:
        definition = get_definition(action.scope, action.object_type)
        if definition is None:
            msg = f"Unsupported restore type: {action.scope}:{action.object_type}"
            raise MistMutationError(msg)
        current = await client.get_current(
            definition,
            action.current_mist_id,
            org_id=organization.mist_org_id,
            site_id=action.site_mist_id,
        )
        _validate_live_state(action, current, relaxed=relaxed)

        stored = await latest_version(action.logical_object_id)
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
                existed=current is not None,
                configuration=(
                    {}
                    if current is None
                    else protect_configuration(
                        current,
                        vault,
                        sensitive_fields=definition.sensitive_fields,
                    )
                ),
                configuration_hash=(
                    None if current is None else configuration_hash(current, ignored_fields=definition.ignored_fields)
                ),
                pre_version_id=(None if stored is None or stored.is_deleted else stored.id),
            )
        )
    return entries


def _validate_live_state(
    action: RestoreAction,
    current: dict[str, object] | None,
    *,
    relaxed: bool,
) -> None:
    """Abort before writes when live state differs from the reviewed plan."""
    if action.action is RestoreActionType.CREATE:
        if current is not None:
            msg = f"{action.object_name} was recreated after this plan was reviewed"
            raise MistMutationError(msg)
        return
    if current is None:
        msg = f"{action.object_name} no longer exists"
        raise MistMutationError(msg)
    if relaxed:
        return
    if action.expected_current_hash is None:
        msg = f"{action.object_name} was recreated after this plan was reviewed"
        raise MistMutationError(msg)
    definition = get_definition(action.scope, action.object_type)
    ignored = frozenset() if definition is None else definition.ignored_fields
    if not configuration_hash_matches(action.expected_current_hash, current, ignored_fields=ignored):
        msg = f"{action.object_name} changed after this plan was reviewed"
        raise MistMutationError(msg)


class RestoreCompensationService:
    """Build the inverse of a partly applied restore from its safety snapshot."""

    def __init__(
        self,
        store: RestoreStateStore | None = None,
        vault: CredentialVault | None = None,
    ) -> None:
        self._store = store or get_restore_state_store()
        self._vault = vault or CredentialVault(get_settings())

    async def create_compensation_plan(
        self,
        *,
        operation: RestoreOperation,
        requested_by: PydanticObjectId,
    ) -> RestoreOperation:
        """Plan the reversal of every action a failed restore actually applied."""
        if operation.id is None:
            msg = "Persisted restore operation is missing an identifier"
            raise RestoreCompensationError(msg)
        if operation.status is not RestoreStatus.COMPENSATION_AVAILABLE:
            msg = "This restore has nothing to compensate"
            raise RestoreCompensationError(msg)

        state = await self._store.load(operation.organization_id, operation.id)
        if state is None or not state.safety_snapshot:
            msg = "No safety snapshot was captured for this restore, so it cannot be reversed automatically"
            raise RestoreCompensationError(msg)

        existing = await self._store.find_compensation_of(operation.organization_id, operation.id)
        if existing is not None:
            plan = await RestoreOperation.find_one(
                RestoreOperation.id == existing.operation_id,
                RestoreOperation.organization_id == operation.organization_id,
            )
            if plan is not None and plan.status is RestoreStatus.PLANNED:
                return plan

        snapshot = {entry.order: entry for entry in state.safety_snapshot}
        applied = sorted(
            (action for action in operation.actions if action.status is RestoreActionStatus.COMPLETED),
            key=lambda action: action.order,
            reverse=True,
        )
        if not applied:
            msg = "This restore applied no changes, so there is nothing to reverse"
            raise RestoreCompensationError(msg)

        actions: list[RestoreAction] = []
        for index, action in enumerate(applied):
            entry = snapshot.get(action.order)
            if entry is None:
                msg = f"{action.object_name} has no safety snapshot entry, so it cannot be reversed"
                raise RestoreCompensationError(msg)
            actions.append(await self._invert(action, entry, index))

        compensation = RestoreOperation(
            organization_id=operation.organization_id,
            requested_by=requested_by,
            mode=operation.mode,
            include_dependencies=False,
            target_at=operation.target_at,
            actions=actions,
            warnings=[
                (
                    f"Compensating plan for restore {operation.id}: reverses "
                    f"{len(actions)} applied actions in reverse dependency order"
                ),
            ],
            preflight_errors=validate_action_capabilities(actions),
        )
        await compensation.insert()
        if compensation.id is None:
            msg = "Persisted compensation plan is missing an identifier"
            raise RestoreCompensationError(msg)

        await self._store.save(
            RestoreOperationState(
                organization_id=operation.organization_id,
                operation_id=compensation.id,
                plan_hash=compute_plan_hash(actions),
                compensates_operation_id=operation.id,
            )
        )
        state.compensation_operation_id = compensation.id
        await self._store.save(state)
        return compensation

    async def compensation_for(self, operation: RestoreOperation) -> RestoreOperation | None:
        """Return the compensating plan already built for this restore."""
        if operation.id is None:
            return None
        state = await self._store.find_compensation_of(operation.organization_id, operation.id)
        if state is None:
            return None
        return await RestoreOperation.find_one(
            RestoreOperation.id == state.operation_id,
            RestoreOperation.organization_id == operation.organization_id,
        )

    async def compensated_operation(self, compensation: RestoreOperation) -> RestoreOperation | None:
        """Return the failed restore a compensating plan reverses."""
        state = await load_or_build_state(self._store, compensation)
        if state.compensates_operation_id is None:
            return None
        return await RestoreOperation.find_one(
            RestoreOperation.id == state.compensates_operation_id,
            RestoreOperation.organization_id == compensation.organization_id,
        )

    def _describes(
        self,
        entry: SafetySnapshotEntry,
        action: RestoreAction,
        stored: ObjectVersion,
    ) -> bool:
        """Whether the stored version is the configuration the snapshot recorded.

        The snapshot's digest is compared with the stored version's *contents*,
        not with the digest written beside them. Those two digests can belong
        to different generations through no fault of either: the keyed hash is
        migrated in the background, and a version referenced by a snapshot may
        be rewritten between the restore failing and its reversal being built.
        Comparing digest to digest read that as a changed configuration and
        fell back to the live values — which for a secret is the mask Mist
        returns, and writing that back would set the secret to `********`.
        """
        if entry.configuration_hash is None:
            return False
        definition = get_definition(action.scope, action.object_type)
        ignored = frozenset() if definition is None else definition.ignored_fields
        try:
            plaintext = reveal_configuration(stored.configuration, self._vault)
        except CredentialDecryptionError:
            # Nothing can be said about a version whose secrets will not
            # decrypt, and guessing is how masked values get written back.
            logger.warning(
                "Cannot confirm stored version %s against its safety snapshot: its secrets do not decrypt",
                stored.id,
            )
            return False
        return configuration_hash_matches(entry.configuration_hash, plaintext, ignored_fields=ignored)

    async def _invert(
        self,
        action: RestoreAction,
        entry: SafetySnapshotEntry,
        order: int,
    ) -> RestoreAction:
        """Build the single action that undoes one applied action."""
        configuration = dict(entry.configuration)
        source_version_id = entry.pre_version_id or action.source_version_id
        if entry.pre_version_id is not None:
            stored = await ObjectVersion.get(entry.pre_version_id)
            # The stored version carries the real protected secrets; the live
            # read that produced the snapshot only ever sees masked values.
            if stored is not None and self._describes(entry, action, stored):
                configuration = dict(stored.configuration)

        if action.action is RestoreActionType.CREATE:
            inverse = RestoreActionType.DELETE
            target = action.resulting_mist_id or action.current_mist_id
            configuration = {}
        elif action.action is RestoreActionType.UPDATE:
            inverse = RestoreActionType.UPDATE
            target = action.resulting_mist_id or action.current_mist_id
        else:
            inverse = RestoreActionType.CREATE
            target = action.current_mist_id

        return RestoreAction(
            logical_object_id=action.logical_object_id,
            source_version_id=source_version_id,
            order=order,
            action=inverse,
            scope=action.scope,
            object_type=action.object_type,
            object_name=action.object_name,
            current_mist_id=target,
            site_mist_id=action.site_mist_id,
            protected_configuration=configuration,
            expected_current_hash=None,
            depends_on=[],
        )
