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
from mist_config_guardian_backend.services.restore_compensation import RestoreDriftError, build_snapshot_entry
from mist_config_guardian_backend.services.restore_planner import SafetySnapshotEntry
from mist_config_guardian_backend.snapshots.canonical import configuration_hash_matches
from mist_config_guardian_backend.snapshots.registry import ObjectDefinition


@dataclass(frozen=True)
class WriteCheck:
    """The pre-write state one action is about to replace.

    ``recorded`` is true when the entry was taken here rather than by the
    up-front safety snapshot, so the caller must add it to the stored snapshot
    before writing: compensation can only undo what the snapshot describes.
    """

    entry: SafetySnapshotEntry
    recorded: bool


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
    ``compensating`` keeps the relaxed semantics a compensation plan runs
    under: the object must still exist, but it may differ from the snapshot.
    """
    if entry is None and not deferred:
        msg = f"{action.object_name} has no pre-restore safety snapshot entry"
        raise RestoreDriftError(msg)
    if action.action is RestoreActionType.CREATE:
        if entry is not None:
            return WriteCheck(entry=entry, recorded=False)
        current = None
        if action.outcome_unknown:
            # The inverse of a delete that may never have happened: its site may
            # never have gone either, and the object still there must be found
            # so the executor skips it instead of creating a duplicate.
            current = await client.get_current(definition, object_id, org_id=organization.mist_org_id, site_id=site_id)
        # Otherwise, under a site created moments ago nothing can exist yet.
        recorded = await build_snapshot_entry(
            action, definition, vault, current, mist_object_id=object_id, site_mist_id=site_id
        )
        return WriteCheck(entry=recorded, recorded=True)
    live = await client.get_current(definition, object_id, org_id=organization.mist_org_id, site_id=site_id)
    if live is None:
        msg = f"{action.object_name} no longer exists in Mist"
        raise RestoreDriftError(msg)
    if entry is None:
        observed = await build_snapshot_entry(
            action, definition, vault, live, mist_object_id=object_id, site_mist_id=site_id
        )
        return WriteCheck(entry=observed, recorded=True)
    if not compensating and not configuration_hash_matches(
        entry.configuration_hash, live, ignored_fields=definition.ignored_fields
    ):
        msg = f"{action.object_name} changed in Mist after the pre-restore safety snapshot"
        raise RestoreDriftError(msg)
    return WriteCheck(entry=entry, recorded=False)
