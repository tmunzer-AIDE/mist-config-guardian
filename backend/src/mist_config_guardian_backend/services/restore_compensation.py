"""Pre-restore safety snapshots and the compensating plans built from them.

Mist has no transactional multi-object write, so the only way to undo a partly
applied restore is to record what every object looked like immediately before
the first write and replay that state in reverse. The snapshot is captured in
the same pass that revalidates live state, so nothing is written before the
inverse of every planned write is known.
"""

import logging
from collections.abc import Mapping, Sequence

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
    unavailable_secret_errors,
    validate_action_capabilities,
)
from mist_config_guardian_backend.snapshots.canonical import (
    canonicalize,
    configuration_hash,
    configuration_hash_matches,
)
from mist_config_guardian_backend.snapshots.registry import get_definition
from mist_config_guardian_backend.snapshots.secrets import (
    SecretPath,
    find_unavailable_secrets,
    format_secret_path,
    protect_configuration,
    reveal_configuration,
)

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


_MISSING = object()


def _at_path(value: object, path: SecretPath) -> object:
    """Read one of the locations :func:`find_unavailable_secrets` reports.

    A step is a mapping key or a sequence position, and only the matching kind
    of container answers to it: a mapping is not indexed by number, and a list
    is not keyed by name. Anything else means the location is not there, and a
    location that is not there supplies nothing.
    """
    for step in path:
        if isinstance(step, str) and isinstance(value, Mapping):
            if step not in value:
                return _MISSING
            value = value[step]
        elif isinstance(step, int) and isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            if not -len(value) <= step < len(value):
                return _MISSING
            value = value[step]
        else:
            return _MISSING
    return value


def _usable_secret(value: object) -> bool:
    """Whether a value is a secret that could actually be written back.

    The same three things :func:`find_unavailable_secrets` calls unusable —
    absent, empty, or all asterisks — plus the one it cannot see, a field that
    is not there at all.
    """
    if value is _MISSING or value is None or value == "":
        return False
    return not (isinstance(value, str) and set(value) == {"*"})


def _without_paths(value: object, paths: frozenset[SecretPath], *, path: SecretPath = ()) -> object:
    """Drop exactly those locations, leaving same-named fields elsewhere.

    The paths are the ones :func:`find_unavailable_secrets` reports, so this
    walks a configuration the same way it does and removes only what it named
    — step for step, so a key that happens to spell another location's path
    does not stand in for it.
    """
    if isinstance(value, Mapping):
        kept: dict[str, object] = {}
        for key, child in value.items():
            child_path = (*path, str(key))
            if child_path in paths:
                continue
            kept[str(key)] = _without_paths(child, paths, path=child_path)
        return kept
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_without_paths(child, paths, path=(*path, index)) for index, child in enumerate(value)]
    return value


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
            # A compensation plan is reviewed like any other. It keeps a masked
            # secret on purpose when no stored version can supply one, so it is
            # exactly the plan most likely to carry one into authorization.
            preflight_errors=(validate_action_capabilities(actions) + unavailable_secret_errors(actions, self._vault)),
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
        """Whether the stored version is the object the snapshot recorded.

        The two configurations are compared field by field, which is the only
        comparison that can answer this. A digest could not: the snapshot holds
        what Mist returned, and Mist returns some secrets as `********`, so a
        digest of the live read never matches a digest of the stored plaintext
        for exactly the objects whose secret the stored version is the only
        source of. Compensation then carried the mask forward, and the plan it
        built was refused at authorization for requiring a secret it did not
        have — the safety net failing in the one case it exists for.

        So the masked locations are the ones left out, and everything else has
        to agree: the ordinary fields, and any secret Mist did return. A secret
        that came back real and differs is a genuine difference, and the stored
        version does not describe what was live.

        Left out by exact location, not by name. An object can carry the same
        secret field in more than one place — a primary key and a backup one —
        and excluding the name would let a mask over the first suppress the
        comparison of the second. The stored version would then be accepted
        over a backup key that had been rotated since, and put the old one
        back: no mask, nothing for authorization to catch, and a working
        credential overwritten with a stale one.

        And left out only where the stored version actually holds the secret
        the live read could not give. Dropping a masked location from both
        sides makes "the stored version has this secret" and "the stored
        version has no such field" look alike, and the second is not a source
        of anything: preferring it writes the object back without the field at
        all, through a replacement `PUT`, with nothing masked for
        authorization to refuse. Where the stored version cannot supply a
        masked secret the live snapshot is kept instead, mask and all, so the
        plan is refused rather than quietly dropping a credential.
        """
        definition = get_definition(action.scope, action.object_type)
        if definition is None:
            return False
        try:
            live = reveal_configuration(entry.configuration, self._vault)
            plaintext = reveal_configuration(stored.configuration, self._vault)
        except CredentialDecryptionError:
            # Nothing can be said about a version whose secrets will not
            # decrypt, and guessing is how masked values get written back.
            logger.warning(
                "Cannot confirm stored version %s against its safety snapshot: its secrets do not decrypt",
                stored.id,
            )
            return False
        masked = frozenset(find_unavailable_secrets(live, definition.sensitive_fields))
        unsourced = sorted(format_secret_path(path) for path in masked if not _usable_secret(_at_path(plaintext, path)))
        if unsourced:
            logger.warning(
                "Stored version %s cannot supply the masked secrets %s, so the live snapshot is kept",
                stored.id,
                ", ".join(unsourced),
            )
            return False
        ignored = definition.ignored_fields
        return canonicalize(_without_paths(live, masked), ignored_fields=ignored) == canonicalize(
            _without_paths(plaintext, masked), ignored_fields=ignored
        )

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
            # The stored version is where a secret Mist masked on read still
            # exists, and the snapshot is where everything else was as it stood.
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
