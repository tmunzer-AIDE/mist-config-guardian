"""Celery task that migrates stored configuration digests to the keyed hash."""

import asyncio
import logging
from collections.abc import Collection, Mapping

from beanie import PydanticObjectId

from mist_config_guardian_backend.config import get_settings
from mist_config_guardian_backend.database import DatabaseManager
from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectVersion
from mist_config_guardian_backend.security.credentials import (
    CredentialDecryptionError,
    CredentialVault,
)
from mist_config_guardian_backend.snapshots.canonical import (
    CURRENT_HASH_GENERATION,
    configuration_hash,
    is_legacy_hash,
    legacy_configuration_hash,
)
from mist_config_guardian_backend.snapshots.registry import get_definition
from mist_config_guardian_backend.snapshots.secrets import reveal_configuration
from mist_config_guardian_backend.worker import celery_app

logger = logging.getLogger(__name__)

BACKFILL_BATCH_SIZE = 200

# Every keyed digest starts with the generation marker, so anything that does
# not is from before the hash was keyed. Matching in the query keeps the batch
# to rows that actually need work, and empties naturally as the migration runs.
_LEGACY_SELECTOR = {"configuration_hash": {"$not": {"$regex": f"^{CURRENT_HASH_GENERATION}:"}}}


@celery_app.task(name="hashes.backfill_configuration_hashes")
def backfill_configuration_hashes() -> int:
    """Rewrite a bounded batch of unkeyed configuration digests."""
    return asyncio.run(_backfill_configuration_hashes())


async def _backfill_configuration_hashes() -> int:
    """Migrate stored digests written before the configuration hash was keyed.

    Comparison tolerates both generations, so nothing breaks while this runs;
    the migration is what stops the old digests from being kept indefinitely.
    Each rewrite is proved before it is made — the unkeyed digest of the stored
    configuration must reproduce exactly what is on the row — so a version whose
    definition has since changed shape is reported and left alone rather than
    stamped with a digest that describes something else.
    """
    settings = get_settings()
    database = DatabaseManager(settings)
    await database.connect()
    try:
        vault = CredentialVault(settings)
        pending = await ObjectVersion.find(_LEGACY_SELECTOR).limit(BACKFILL_BATCH_SIZE).to_list()
        ignored: dict[PydanticObjectId, frozenset[str]] = {}
        migrated = 0
        for version in pending:
            fields = ignored.get(version.logical_object_id)
            if fields is None:
                fields = await _ignored_fields(version.logical_object_id)
                ignored[version.logical_object_id] = fields
            if await _migrate_one(version, vault, ignored_fields=fields):
                migrated += 1
        return migrated
    finally:
        await database.close()


async def _ignored_fields(logical_object_id: PydanticObjectId) -> frozenset[str]:
    """The fields the digest for this object was taken without."""
    logical = await LogicalObject.get(logical_object_id)
    if logical is None:
        return frozenset()
    definition = get_definition(logical.scope, logical.object_type)
    return frozenset() if definition is None else definition.ignored_fields


def upgraded_hash(
    plaintext: Mapping[str, object],
    stored: str,
    *,
    ignored_fields: Collection[str] = (),
) -> str | None:
    """The keyed digest that replaces `stored`, or None if it must not be replaced.

    A migration that rewrites a digest it cannot reproduce is not migrating
    anything, it is inventing: the new value would claim to describe a
    configuration nobody checked. So the unkeyed digest of the stored
    configuration has to come back exactly equal to what is on the row before
    that row is touched.
    """
    if not is_legacy_hash(stored):
        return None
    if legacy_configuration_hash(plaintext, ignored_fields=ignored_fields) != stored:
        return None
    return configuration_hash(plaintext, ignored_fields=ignored_fields)


async def _migrate_one(
    version: ObjectVersion,
    vault: CredentialVault,
    *,
    ignored_fields: frozenset[str],
) -> bool:
    """Rewrite one row's digest, or leave it as it is and say why."""
    if version.id is None:
        return False
    previous = version.configuration_hash
    try:
        plaintext = reveal_configuration(version.configuration, vault)
    except CredentialDecryptionError:
        logger.warning("Cannot re-hash object version %s: its secrets do not decrypt", version.id)
        return False
    replacement = upgraded_hash(plaintext, previous, ignored_fields=ignored_fields)
    if replacement is None:
        logger.warning(
            "Leaving object version %s alone: its stored digest does not describe its configuration",
            version.id,
        )
        return False
    result = await ObjectVersion.find_one(
        ObjectVersion.id == version.id,
        ObjectVersion.configuration_hash == previous,
    ).update({"$set": {"configuration_hash": replacement}})
    return getattr(result, "modified_count", 0) > 0
