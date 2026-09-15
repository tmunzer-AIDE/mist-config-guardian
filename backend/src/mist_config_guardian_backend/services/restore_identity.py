"""Keep a recreated object on the logical identity its history belongs to.

The collector finds a logical object by its source key, which embeds the Mist
id and the site id. Recreating an object gives it a new id (and a recreated
site gives its children a new site id), so the restore must move the key with
it, or the next capture starts a second identity for the same object.
"""

from collections.abc import Awaitable, Callable
from datetime import datetime

from beanie import PydanticObjectId
from pymongo.errors import DuplicateKeyError

from mist_config_guardian_backend.integrations.mist_mutation import MistMutationError
from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectIncarnation, ObjectVersion
from mist_config_guardian_backend.services.restore_planner import latest_version

_REKEY_ATTEMPTS = 2


class RestoreIdentityConflictError(MistMutationError):
    """Another recorded identity owns the key a restored object needs.

    A Mist error, so the executor stops the run the way it does for any failed
    step after a write: the write stays recorded as applied and compensable.
    The message names the object, never its identifiers or configuration.
    """


async def rekey_logical_object(
    logical: LogicalObject,
    *,
    source_key: str,
    restore_started_at: datetime | None,
    incarnation: Callable[[], Awaitable[PydanticObjectId]],
) -> None:
    """Move ``logical`` to ``source_key``, adopting a capture of the same object that raced the restore.

    A holder created at or after the restore started can only have come from
    a webhook or backup seeing the object this restore just wrote, so its
    versions belong to the restored history. An older holder is a separate
    identity that nothing here can safely merge, so the restore stops for a
    person to look. The unique source index is the final arbiter: a capture
    that lands between the lookup and the write is found on the retry.

    Runs before the restored version is recorded, so an adopted capture sits
    beneath it. ``incarnation`` opens the incarnation the restore writes under
    and is only called once there is a capture to move onto it, so a refused
    re-key has recorded nothing at all.
    """
    for attempt in range(1, _REKEY_ATTEMPTS + 1):
        holder = await LogicalObject.find_one(
            LogicalObject.organization_id == logical.organization_id,
            LogicalObject.scope == logical.scope,
            LogicalObject.object_type == logical.object_type,
            LogicalObject.source_key == source_key,
        )
        if holder is not None and holder.id != logical.id:
            if restore_started_at is None or holder.created_at < restore_started_at:
                msg = f"{logical.name}: another recorded identity already owns this object; history needs manual review"
                raise RestoreIdentityConflictError(msg)
            await _adopt(logical, holder, await incarnation())
        try:
            await LogicalObject.find_one(LogicalObject.id == logical.id).update({"$set": {"source_key": source_key}})
        except DuplicateKeyError as exc:
            if attempt == _REKEY_ATTEMPTS:
                msg = f"{logical.name}: another capture keeps claiming this object; history needs manual review"
                raise RestoreIdentityConflictError(msg) from exc
            continue
        logical.source_key = source_key
        return


async def _adopt(restored: LogicalObject, duplicate: LogicalObject, incarnation_id: PydanticObjectId) -> None:
    """Fold a same-object capture into the restored identity, beneath the version the restore records next.

    The capture recorded the same Mist object under the same incarnation the
    restore opens, so its versions are renumbered onto the restored history
    rather than copied, and the duplicate identity is removed.
    """
    if restored.id is None or duplicate.id is None:
        return
    latest = await latest_version(restored.id)
    number = 0 if latest is None else latest.version
    moved = await ObjectVersion.find(ObjectVersion.logical_object_id == duplicate.id).sort("version").to_list()
    for version in moved:
        number += 1
        await ObjectVersion.find_one(ObjectVersion.id == version.id).update(
            {"$set": {"logical_object_id": restored.id, "version": number, "incarnation_id": incarnation_id}}
        )
    await ObjectIncarnation.find(ObjectIncarnation.logical_object_id == duplicate.id).delete()
    await duplicate.delete()
    restored.current_version = max(restored.current_version, number)
