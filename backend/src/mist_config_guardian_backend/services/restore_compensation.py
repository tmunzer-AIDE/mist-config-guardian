"""Pre-restore safety snapshots and the compensating plans built from them.

Mist has no transactional multi-object write, so the only way to undo a partly
applied restore is to record what every object looked like immediately before
the first write and replay that state in reverse. The snapshot is captured in
the same pass that revalidates live state, so nothing is written before the
inverse of every planned write is known.
"""

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal, cast

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
from mist_config_guardian_backend.services.restore_outcome import possibly_applied, unconfirmed_write
from mist_config_guardian_backend.services.restore_planner import (
    RestoreOperationState,
    RestorePlanRepository,
    RestoreStateStore,
    SafetySnapshotEntry,
    get_restore_plan_repository,
    get_restore_state_store,
    latest_version,
    load_or_build_state,
    unavailable_secret_errors,
    validate_action_capabilities,
)
from mist_config_guardian_backend.snapshots.canonical import canonicalize, configuration_hash_matches
from mist_config_guardian_backend.snapshots.fingerprint import (
    MISSING,
    at_path,
    equivalent,
    fingerprint,
    fingerprint_matches,
    normalize,
    without_paths,
)
from mist_config_guardian_backend.snapshots.registry import ObjectDefinition, explicit_name, get_definition
from mist_config_guardian_backend.snapshots.secrets import (
    find_unavailable_secrets,
    format_secret_path,
    is_protected,
    protect_configuration,
    reveal_configuration,
)

logger = logging.getLogger(__name__)
_DEBUG_MAX_FIELDS = 20
_DEBUG_MAX_FIELD_LENGTH = 64


class RestoreCompensationError(ValueError):
    """Raised when a compensating plan cannot be built or executed."""


class RestoreDriftError(MistMutationError):
    """Live state no longer matches what the plan was validated against.

    A Mist error, so the executor fails the action and the run the same way it
    does for a refused write. The message names the object, never its values.
    """


def recreated_site_ids(actions: Sequence[RestoreAction]) -> frozenset[str]:
    """Site ids that do not exist in Mist until this plan creates them."""
    return frozenset(
        action.current_mist_id
        for action in actions
        if action.object_type == "sites" and action.action is RestoreActionType.CREATE
    )


async def build_snapshot_entry(  # noqa: PLR0913 - the identifiers differ from the action's once remapped
    action: RestoreAction,
    definition: ObjectDefinition,
    vault: CredentialVault,
    current: dict[str, object] | None,
    *,
    mist_object_id: str,
    site_mist_id: str | None,
) -> SafetySnapshotEntry:
    """Record what one object looked like immediately before this plan touched it.

    Shared by the up-front capture and the deferred reads under a recreated
    site, so an entry means the same thing whenever it was taken.
    """
    stored = await latest_version(action.logical_object_id)
    return SafetySnapshotEntry(
        logical_object_id=action.logical_object_id,
        order=action.order,
        action=action.action,
        scope=action.scope,
        object_type=action.object_type,
        object_name=action.object_name,
        mist_object_id=mist_object_id,
        site_mist_id=site_mist_id,
        existed=current is not None,
        configuration=(
            {}
            if current is None
            else protect_configuration(current, vault, sensitive_fields=definition.sensitive_fields)
        ),
        configuration_hash=None if current is None else fingerprint(definition, current),
        pre_version_id=None if stored is None or stored.is_deleted else stored.id,
    )


async def capture_safety_snapshot(
    client: MistMutationClient,
    organization: Organization,
    operation: RestoreOperation,
    vault: CredentialVault,
) -> list[SafetySnapshotEntry]:
    """Revalidate live state and record the pre-restore state of every target.

    A compensating plan is held to the same standard: each reversal expects
    exactly what the restore it undoes wrote, so a fix made by hand after the
    restore failed stops the compensation instead of being overwritten.

    A CREATE is also refused when Mist already holds an object of its type and
    name under another UUID: the old UUID being gone does not mean the object
    is, and creating it again would leave two. Each type is listed once per
    site however many CREATEs share it.
    """
    entries: list[SafetySnapshotEntry] = []
    listings: dict[tuple[str, str | None], list[dict[str, object]]] = {}
    recreated = recreated_site_ids(operation.actions)
    for action in operation.actions:
        if action.site_mist_id is not None and action.site_mist_id in recreated:
            # Nothing exists under a site this plan has not created yet. The
            # executor reads these right before their writes, at the new site.
            continue
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
        try:
            verdict = assess_live_state(action, current, vault)
            # A reversal that finds its work already done is skipped at
            # execution, so it creates nothing that could collide.
            if action.action is RestoreActionType.CREATE and verdict == "proceed":
                await _refuse_name_collision(client, organization, action, definition, listings)
        except MistMutationError:
            await _log_preflight_diagnostics(operation, action, current, vault)
            raise
        entries.append(
            await build_snapshot_entry(
                action,
                definition,
                vault,
                current,
                mist_object_id=action.current_mist_id,
                site_mist_id=action.site_mist_id,
            )
        )
    return entries


def restore_name(definition: ObjectDefinition, configuration: Mapping[str, object]) -> str | None:
    """The explicit display name a configuration carries, if any.

    The collector's own reading of a name, so a collision is judged by the name
    a backup shows. ``None`` means there is nothing to compare a live object
    against, so no collision can be established and none is claimed.
    """
    return explicit_name(configuration, definition)


def _same_name_group(
    definition: ObjectDefinition,
    configuration: Mapping[str, object],
    item: Mapping[str, object],
) -> bool:
    """Whether a live object shares the namespace a created object's name must be unique in.

    Organization WLANs belong to a WLAN template, and the same SSID in several
    templates is ordinary. A WLAN without a template is grouped only with other
    WLANs without one.
    """
    if definition.scope == "org" and definition.key == "wlans":
        return configuration.get("template_id") == item.get("template_id")
    return True


async def _refuse_name_collision(
    client: MistMutationClient,
    organization: Organization,
    action: RestoreAction,
    definition: ObjectDefinition,
    listings: dict[tuple[str, str | None], list[dict[str, object]]],
) -> None:
    """Refuse to create an object Mist already holds under a new UUID with the same name.

    Someone who recreated the object by hand gave it a new UUID, so the old one
    reading as missing proves nothing. ``listings`` is shared across the pass so
    each type is listed once per site; narrower groups are filtered in memory.
    The name is read as stored: no name field is ever a sensitive one, so
    nothing is decrypted to read it.
    """
    configuration = action.protected_configuration
    name = restore_name(definition, configuration)
    if name is None:
        return
    scope = (definition.key, action.site_mist_id)
    if scope not in listings:
        listings[scope] = await client.list_objects(
            definition, org_id=organization.mist_org_id, site_id=action.site_mist_id
        )
    for item in listings[scope]:
        if (
            item.get("id") != action.current_mist_id
            and _same_name_group(definition, configuration, item)
            and restore_name(definition, item) == name
        ):
            # A compensation is rebuilt from the restore it reverses, not re-prepared.
            then = "plan the compensation again" if action.compensates_action_order is not None else "rebuild the plan"
            msg = (
                f"{action.object_name}: a {definition.key} named '{name}' already exists in Mist; "
                f"it may have been recreated manually. Rename or remove it, then {then}"
            )
            raise MistMutationError(msg)


def _switch_management_differences(before: object, after: object) -> list[str]:
    """Describe only fixed schema paths and value categories, never values."""
    if not isinstance(before, dict) or not isinstance(after, dict):
        return []
    fields = (
        "config_revert_timer",
        "root_password",
        "local_accounts",
        "protect_re",
        "tacacs",
        "radius",
        "dhcp_option_fqdn",
    )

    def category(value: object) -> str:
        if value is MISSING:
            return "missing"
        if value is None:
            return "null"
        if isinstance(value, str):
            if not value:
                return "empty-string"
            return "masked-string" if set(value) == {"*"} else "nonempty-string"
        return type(value).__name__

    differences = []
    for key in fields:
        old = before.get(key, MISSING)
        new = after.get(key, MISSING)
        if old != new:
            differences.append(f"switch_mgmt.{key}:stored={category(old)},live={category(new)}")
    if any(before.get(key, MISSING) != after.get(key, MISSING) for key in (before.keys() | after.keys()) - set(fields)):
        differences.append("switch_mgmt.<other-field>:different")
    return differences


async def _log_preflight_diagnostics(
    operation: RestoreOperation,
    action: RestoreAction,
    current: dict[str, object] | None,
    vault: CredentialVault,
) -> None:
    """Log bounded, value-free evidence without replacing the original failure."""
    try:
        definition = get_definition(action.scope, action.object_type)

        def normalized(configuration: dict[str, object]) -> object:
            # An unsupported type is refused before any live check, but the
            # diagnostic must still describe one rather than fail on it.
            return canonicalize(configuration) if definition is None else normalize(definition, configuration)

        def expected_by_plan(configuration: dict[str, object] | None) -> bool:
            if configuration is None:
                return False
            if definition is None:
                return configuration_hash_matches(action.expected_current_hash, configuration)
            return fingerprint_matches(definition, action.expected_current_hash, configuration)

        baseline = await ObjectVersion.find_one(
            ObjectVersion.logical_object_id == action.logical_object_id,
            ObjectVersion.configuration_hash == action.expected_current_hash,
        )
        stored = None if baseline is None else reveal_configuration(baseline.configuration, vault)
        before = None if stored is None else normalized(stored)
        after = None if current is None else normalized(current)
        changed = []
        if isinstance(before, dict) and isinstance(after, dict):
            changed = sorted(
                key
                for key in before.keys() | after.keys()
                if key not in before or key not in after or before[key] != after[key]
            )
        # Only schema-shaped top-level keys; never descend into user-named maps
        # or emit configuration values, credentials, or secret fingerprints.
        fields = [
            key if key.isidentifier() and len(key) <= _DEBUG_MAX_FIELD_LENGTH else "<custom-field>"
            for key in changed[:_DEBUG_MAX_FIELDS]
        ]
        logger.warning(
            "restore_preflight_debug operation=%s action=%s baseline_found=%s "
            "baseline_hash_matches=%s live_hash_matches=%s live_exists=%s "
            "changed_field_count=%s changed_fields=%s switch_mgmt_differences=%s",
            operation.id,
            action.order,
            baseline is not None,
            expected_by_plan(stored),
            expected_by_plan(current),
            current is not None,
            len(changed),
            fields,
            _switch_management_differences(
                before.get("switch_mgmt") if isinstance(before, dict) else None,
                after.get("switch_mgmt") if isinstance(after, dict) else None,
            ),
        )
    except Exception as exc:  # noqa: BLE001 — diagnostics must not replace the safety failure.
        logger.warning(
            "restore_preflight_debug operation=%s action=%s diagnostics_unavailable=%s",
            operation.id,
            action.order,
            type(exc).__name__,
        )


def _usable_secret(value: object) -> bool:
    """Whether a value is a secret that could actually be written back.

    :func:`find_unavailable_secrets` reports only all-asterisk masks. To replace
    one of those masks during compensation, a stored version must provide a
    concrete, nonempty value; missing, null, empty, or masked values cannot
    supply the secret.
    """
    if value is MISSING or value is None or value == "":
        return False
    return not (isinstance(value, str) and set(value) == {"*"})


LiveAssessment = Literal["proceed", "already_reversed"]


def _supported_definition(action: RestoreAction) -> ObjectDefinition:
    """The registry definition live state is judged under; without one, nothing can be judged."""
    definition = get_definition(action.scope, action.object_type)
    if definition is None:
        msg = f"Unsupported restore type: {action.scope}:{action.object_type}"
        raise RestoreDriftError(msg)
    return definition


def assess_live_state(
    action: RestoreAction,
    current: dict[str, object] | None,
    vault: CredentialVault,
) -> LiveAssessment:
    """Decide whether live state still allows this action, raising ``RestoreDriftError`` when it does not.

    A reversal is held to the same standard as a restore: it may only replace
    what the restore wrote. Finding the object already in the state the
    reversal would leave it in is not drift; it is a reversal with nothing left
    to do. A missing expected state never counts as a match. Messages name the
    object, never its values.

    Digests and comparisons follow the collector's field policy, so a state
    recorded from one Mist read matches the next read of the same object.
    """
    definition = _supported_definition(action)
    reversal = action.compensates_action_order is not None
    if action.action is RestoreActionType.CREATE:
        if current is None:
            return "proceed"
        if action.outcome_unknown:
            # The delete this CREATE reverses may never have happened.
            return "already_reversed"
        msg = f"{action.object_name} was recreated after this plan was reviewed"
        raise RestoreDriftError(msg)
    if current is None:
        if reversal and action.action is RestoreActionType.DELETE:
            return "already_reversed"
        msg = f"{action.object_name} no longer exists"
        raise RestoreDriftError(msg)
    if action.expected_current_hash is None:
        return _assess_without_expected_hash(action, current, vault, definition)
    if fingerprint_matches(definition, action.expected_current_hash, current):
        return "proceed"
    if reversal and action.action is RestoreActionType.UPDATE and _already_written(action, current, vault, definition):
        return "already_reversed"
    msg = f"{action.object_name} changed after this plan was reviewed"
    raise RestoreDriftError(msg)


def _already_written(
    action: RestoreAction,
    current: dict[str, object],
    vault: CredentialVault,
    definition: ObjectDefinition,
) -> bool:
    """Whether live state already equals what this action would write.

    Mist returns a secret it holds as a mask, so a masked location is not a
    difference; any other field, and a secret that came back real, has to
    agree. A payload whose secrets no longer decrypt cannot be compared, so it
    is never taken as already written.
    """
    try:
        payload = reveal_configuration(action.protected_configuration, vault)
    except CredentialDecryptionError:
        return False
    return equivalent(definition, payload, current)


def _assess_without_expected_hash(
    action: RestoreAction,
    current: dict[str, object],
    vault: CredentialVault,
    definition: ObjectDefinition,
) -> LiveAssessment:
    """Judge an existing object whose restore recorded no fingerprint of what it wrote.

    A write that may never have happened recorded nothing to expect; the plan
    warns that its reversal cannot check for changes. A write Mist accepted but
    that was never read back is held to the payload it sent instead: live
    state must still show that payload, masked secrets aside, before the
    reversal replaces it. Anything else has nothing to compare, so it is never
    taken as unchanged.
    """
    reversal = action.compensates_action_order is not None
    if reversal and action.outcome_unknown:
        return "proceed"
    written = _written_payload(action, vault) if reversal else None
    if written is not None:
        # Only what was written has to agree: Mist echoes fields a payload never carried.
        if equivalent(definition, written, current, fields=written.keys()):
            return "proceed"
        if action.action is RestoreActionType.UPDATE and _already_written(action, current, vault, definition):
            return "already_reversed"
        msg = f"{action.object_name} changed after this plan was reviewed"
        raise RestoreDriftError(msg)
    msg = (
        f"{action.object_name} has no record of what the restore wrote, "
        "so its reversal cannot check for changes made since"
        if reversal
        else f"{action.object_name} was recreated after this plan was reviewed"
    )
    raise RestoreDriftError(msg)


def _written_payload(action: RestoreAction, vault: CredentialVault) -> dict[str, object] | None:
    """The payload an unread write sent, decrypted in memory only; ``None`` when there is none to compare.

    A payload whose secrets no longer decrypt proves nothing, so it is treated
    as absent and the reversal refuses rather than guesses.
    """
    if action.written_configuration is None:
        return None
    try:
        return reveal_configuration(action.written_configuration, vault)
    except CredentialDecryptionError:
        return None


def _validate_live_state(action: RestoreAction, current: dict[str, object] | None, vault: CredentialVault) -> None:
    """Abort before writes when live state differs from the reviewed plan."""
    assess_live_state(action, current, vault)


def _sent_payload(operation: RestoreOperation, action: RestoreAction) -> dict[str, object] | None:
    """Rebuild, still protected, the payload the executor sent for one applied action.

    The executor drops the fields Mist manages and rewrites every id that an
    earlier CREATE of the same run replaced, then writes. The same steps over
    the stored configuration give what it sent without decrypting a secret.
    ``None`` for a type the registry no longer supports, which leaves the
    reversal nothing to compare, so it refuses.
    """
    definition = get_definition(action.scope, action.object_type)
    if definition is None:
        return None
    id_map: dict[str, str] = {}
    for earlier in operation.actions:
        if (
            earlier.order < action.order
            and earlier.action is RestoreActionType.CREATE
            and earlier.resulting_mist_id is not None
        ):
            id_map[earlier.current_mist_id] = earlier.resulting_mist_id
    return {
        key: _remapped(value, id_map)
        for key, value in action.protected_configuration.items()
        if key not in definition.restore_excluded_fields
    }


def _remapped(value: object, id_map: Mapping[str, str]) -> object:
    """Rewrite replaced ids the way the executor's payload does, leaving each protected secret as stored."""
    if is_protected(value):
        return value
    if isinstance(value, Mapping):
        return {str(key): _remapped(child, id_map) for key, child in value.items()}
    if isinstance(value, list):
        return [_remapped(child, id_map) for child in value]
    if isinstance(value, str):
        return id_map.get(value, value)
    return value


@dataclass
class _Reversal:
    """The inverse actions of one restore, and what must be said about them before they run."""

    actions: list[RestoreAction] = field(default_factory=list)
    follow_ups: list[str] = field(default_factory=list)


class RestoreCompensationService:
    """Build the inverse of a partly applied restore from its safety snapshot."""

    def __init__(
        self,
        store: RestoreStateStore | None = None,
        vault: CredentialVault | None = None,
        *,
        plans: RestorePlanRepository | None = None,
    ) -> None:
        self._store = store or get_restore_state_store()
        self._vault = vault or CredentialVault(get_settings())
        self._plans = plans or get_restore_plan_repository()

    async def create_compensation_plan(
        self,
        *,
        operation: RestoreOperation,
        requested_by: PydanticObjectId,
    ) -> RestoreOperation:
        """Plan the reversal of every write a failed restore applied that no earlier compensation undid.

        A compensation still awaiting review is returned rather than planned
        twice, and none is planned while one is queued or running: both would
        reverse the same writes. After a compensation fails, only the reversals
        it did not complete are planned again.
        """
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

        already_reversed: set[int] = set()
        stale: list[PydanticObjectId] = []
        for earlier in reversed(await self._store.compensations_of(operation.organization_id, operation.id)):
            plan = await self._plans.load(operation.organization_id, earlier.operation_id)
            if plan is None:
                continue
            if plan.status is RestoreStatus.PLANNED:
                if earlier.plan_hash == compute_plan_hash(plan.actions):
                    return plan
                # Reviewed under an earlier plan-hash formula, so execution
                # refuses it as changed; returning it again would leave the
                # failed restore with no compensation that can ever run. It is
                # retired once its replacement exists.
                stale.append(earlier.operation_id)
                continue
            if plan.status in {RestoreStatus.QUEUED, RestoreStatus.RUNNING}:
                msg = "A compensation of this restore is already queued or running"
                raise RestoreCompensationError(msg)
            already_reversed.update(
                action.compensates_action_order
                for action in plan.actions
                if action.status is RestoreActionStatus.COMPLETED and action.compensates_action_order is not None
            )

        reversal = await self._reverse(operation, state, already_reversed)
        actions = reversal.actions

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
                *reversal.follow_ups,
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
        await self._retire_stale(operation.organization_id, stale, compensation.id)
        return compensation

    async def _retire_stale(
        self,
        organization_id: PydanticObjectId,
        stale: Sequence[PydanticObjectId],
        replacement_id: PydanticObjectId,
    ) -> None:
        """Supersede compensations that can no longer run, now that their replacement is linked.

        Retiring only after the replacement exists means a failure in between
        leaves an unrunnable plan behind rather than no plan at all, and the
        next planning retires it again.
        """
        for stale_id in stale:
            if not await self._plans.supersede_planned(organization_id, stale_id, replacement_id):
                # It left PLANNED meanwhile; the new plan is still the one linked.
                logger.warning("restore_compensation_not_superseded operation_id=%s", stale_id)

    async def _reverse(
        self,
        operation: RestoreOperation,
        state: RestoreOperationState,
        already_reversed: set[int],
    ) -> _Reversal:
        """Invert every write that reached Mist, or may have, newest first.

        Writes an earlier compensation already reversed are left out. A write
        that cannot be targeted safely becomes a manual follow-up. An applied
        write that was never read back keeps the payload it sent, which its
        reversal must still find live: one lost read-back must not keep every
        other write of the restore from being reversed.
        """
        snapshot = {entry.order: entry for entry in state.safety_snapshot}
        reversible = sorted(
            (
                action
                for action in operation.actions
                if possibly_applied(action) and action.order not in already_reversed
            ),
            key=lambda action: action.order,
            reverse=True,
        )
        if not reversible:
            msg = (
                "Every change this restore applied has already been reversed"
                if already_reversed
                else "This restore applied no changes, so there is nothing to reverse"
            )
            raise RestoreCompensationError(msg)

        reversal = _Reversal()
        for action in reversible:
            unconfirmed = unconfirmed_write(action)
            if unconfirmed and action.action is RestoreActionType.CREATE:
                # Mist never returned an id, so there is nothing to target
                # without guessing; a person has to look.
                reversal.follow_ups.append(
                    f"{action.object_name} may have been created in Mist before the worker lost contact; "
                    "check for it and delete it manually if it exists"
                )
                continue
            entry = snapshot.get(action.order)
            if entry is None:
                msg = f"{action.object_name} has no safety snapshot entry, so it cannot be reversed"
                raise RestoreCompensationError(msg)
            written = None
            if unconfirmed and action.action is RestoreActionType.UPDATE:
                reversal.follow_ups.append(
                    f"{action.object_name} was not confirmed, so its reversal cannot check for changes made since"
                )
            elif (
                action.status is RestoreActionStatus.COMPLETED
                and action.action is not RestoreActionType.DELETE
                and action.applied_hash is None
            ):
                # Mist accepted the write but it was never read back, including
                # restores recorded before writes were: its reversal is held to
                # the payload it sent instead of a read-back digest.
                written = _sent_payload(operation, action)
            reversal.actions.append(await self._invert(action, entry, len(reversal.actions), written=written))
        if not reversal.actions:
            msg = "; ".join(reversal.follow_ups)
            raise RestoreCompensationError(msg)
        return reversal

    async def compensation_for(self, operation: RestoreOperation) -> RestoreOperation | None:
        """Return the compensating plan currently linked to this restore."""
        if operation.id is None:
            return None
        state = await self._store.find_compensation_of(operation.organization_id, operation.id)
        if state is None:
            return None
        return await self._plans.load(operation.organization_id, state.operation_id)

    async def compensated_operation(self, compensation: RestoreOperation) -> RestoreOperation | None:
        """Return the failed restore a compensating plan reverses."""
        state = await load_or_build_state(self._store, compensation)
        if state.compensates_operation_id is None:
            return None
        return await self._plans.load(compensation.organization_id, state.compensates_operation_id)

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
        unsourced = sorted(format_secret_path(path) for path in masked if not _usable_secret(at_path(plaintext, path)))
        if unsourced:
            logger.warning(
                "Stored version %s cannot supply the masked secrets %s, so the live snapshot is kept",
                stored.id,
                ", ".join(unsourced),
            )
            return False
        return normalize(definition, cast("dict[str, object]", without_paths(live, masked))) == normalize(
            definition, cast("dict[str, object]", without_paths(plaintext, masked))
        )

    async def _invert(
        self,
        action: RestoreAction,
        entry: SafetySnapshotEntry,
        order: int,
        *,
        written: dict[str, object] | None = None,
    ) -> RestoreAction:
        """Build the single action that undoes one applied action.

        ``written`` is the payload of a write that was never read back, which
        the reversal expects in place of a read-back digest.
        """
        unconfirmed = unconfirmed_write(action)
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
            # Under a site this restore recreated, the object lives at the new site.
            site_mist_id=action.resulting_site_mist_id or action.site_mist_id,
            protected_configuration=configuration,
            # What the restore wrote is all its reversal may replace. Recreating
            # a deleted object has nothing to compare, and an unconfirmed write
            # recorded nothing.
            expected_current_hash=None if inverse is RestoreActionType.CREATE or unconfirmed else action.applied_hash,
            written_configuration=written,
            depends_on=[],
            # Only a write that may never have happened leaves its reversal's
            # target uncertain. A flag a confirmed write inherited describes an
            # older write, so it is not carried a second level down.
            outcome_unknown=unconfirmed,
            compensates_action_order=action.order,
        )
