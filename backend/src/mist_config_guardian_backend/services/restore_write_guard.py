"""Live-state checks immediately before each Mist write (spec §9.4.6).

The safety snapshot is taken before the first write; a plan with many actions
can run for minutes, and an object edited in between must not be overwritten.
Objects under a site the plan recreates cannot be read up front at all, so
their snapshot entry is recorded here, at the new site, right before the write.
"""

from dataclasses import dataclass

from mist_config_guardian_backend.integrations.mist_mutation import MistMutationClient
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.restore import RestoreAction, RestoreActionType
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.restore_compensation import (
    RestoreDriftError,
    assess_live_state,
    build_snapshot_entry,
)
from mist_config_guardian_backend.services.restore_planner import SafetySnapshotEntry
from mist_config_guardian_backend.snapshots.fingerprint import fingerprint_matches
from mist_config_guardian_backend.snapshots.registry import ObjectDefinition


@dataclass(frozen=True)
class WriteCheck:
    """The pre-write state one action is about to replace.

    ``recorded`` is true when the entry was taken here rather than by the
    up-front safety snapshot, so the caller must add it to the stored snapshot
    before writing: compensation can only undo what the snapshot describes.

    ``skip`` is true when a reversal has nothing left to write: its object is
    already where the reversal would leave it. The caller marks the action
    skipped instead of writing, so it never counts as applied.
    """

    entry: SafetySnapshotEntry
    recorded: bool
    skip: bool = False


async def check_before_write(  # noqa: PLR0913 - every argument is a distinct fact about the write
    client: MistMutationClient,
    organization: Organization,
    vault: CredentialVault,
    action: RestoreAction,
    definition: ObjectDefinition,
    *,
    object_id: str,
    site_id: str | None,
    entry: SafetySnapshotEntry | None,
    deferred: bool,
    compensating: bool,
) -> WriteCheck:
    """Refuse a write whose target drifted since the safety snapshot, or record a deferred entry.

    ``object_id`` and ``site_id`` are the identifiers after remapping, so an
    object under a site recreated earlier in the plan is read where it now is.
    ``compensating`` holds each reversal to what the restore it undoes wrote,
    as the up-front capture did, and then to the safety snapshot like any
    other write.
    """
    if entry is None and not deferred:
        msg = f"{action.object_name} has no pre-restore safety snapshot entry"
        raise RestoreDriftError(msg)
    if action.action is RestoreActionType.CREATE:
        return await _check_create(
            client,
            organization,
            vault,
            action,
            definition,
            object_id=object_id,
            site_id=site_id,
            entry=entry,
            compensating=compensating,
        )
    live = await client.get_current(definition, object_id, org_id=organization.mist_org_id, site_id=site_id)
    # A reversal compares the live read with what it would write; the mask Mist
    # returns for a secret it holds is not a difference (``assess_live_state``).
    if compensating and assess_live_state(action, live, vault) == "already_reversed":
        observed = entry or await build_snapshot_entry(
            action, definition, vault, live, mist_object_id=object_id, site_mist_id=site_id
        )
        return WriteCheck(entry=observed, recorded=entry is None, skip=True)
    if live is None:
        msg = f"{action.object_name} no longer exists in Mist"
        raise RestoreDriftError(msg)
    if entry is None:
        observed = await build_snapshot_entry(
            action, definition, vault, live, mist_object_id=object_id, site_mist_id=site_id
        )
        return WriteCheck(entry=observed, recorded=True)
    if not fingerprint_matches(definition, entry.configuration_hash, live):
        msg = f"{action.object_name} changed in Mist after the pre-restore safety snapshot"
        raise RestoreDriftError(msg)
    return WriteCheck(entry=entry, recorded=False)


async def _check_create(  # noqa: PLR0913 - the remapped identifiers are what the write targets
    client: MistMutationClient,
    organization: Organization,
    vault: CredentialVault,
    action: RestoreAction,
    definition: ObjectDefinition,
    *,
    object_id: str,
    site_id: str | None,
    entry: SafetySnapshotEntry | None,
    compensating: bool,
) -> WriteCheck:
    """Record where a CREATE lands, and skip one whose unconfirmed delete never removed the object.

    Only the reversal of an unconfirmed delete carries ``outcome_unknown``
    before it runs; the object still being there means that delete never
    happened, and creating it again would leave two.
    """
    unconfirmed_reversal = compensating and action.outcome_unknown
    if entry is not None:
        return WriteCheck(entry=entry, recorded=False, skip=unconfirmed_reversal and entry.existed)
    current = None
    if unconfirmed_reversal:
        # The inverse of a delete that may never have happened: its site may
        # never have gone either, and the object still there must be found
        # so the executor skips it instead of creating a duplicate.
        current = await client.get_current(definition, object_id, org_id=organization.mist_org_id, site_id=site_id)
    # Otherwise, under a site created moments ago nothing can exist yet.
    recorded = await build_snapshot_entry(
        action, definition, vault, current, mist_object_id=object_id, site_mist_id=site_id
    )
    return WriteCheck(entry=recorded, recorded=True, skip=unconfirmed_reversal and recorded.existed)
