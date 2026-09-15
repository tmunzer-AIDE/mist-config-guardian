"""Organization-scoped restore lease and the queue check that accompanies it (spec §9.5.1).

Two restores of one organization must never interleave writes: each would
overwrite what the other just applied, and neither safety snapshot would
describe what the other left behind. The lease is the executor's guard; the
queue check is the early refusal an administrator sees before anything queues.
"""

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Protocol

from beanie import PydanticObjectId
from pymongo.errors import DuplicateKeyError

from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.restore import RestoreLease, RestoreOperation, RestoreStatus

ANOTHER_RESTORE_RUNNING = "Another restore is running for this organization"


class RestoreLeaseLostError(Exception):
    """Raised when a running restore no longer holds its organization's lease.

    Deliberately not a ``MistMutationError``: another restore now owns the
    organization, or the janitor closed this run and released it, so the
    worker must stop without recording a failure over what they write.
    """


class RestoreLeaseStore(Protocol):
    """Exclusive, expiring ownership of an organization for one restore."""

    async def acquire(
        self, organization_id: PydanticObjectId, operation_id: PydanticObjectId, *, ttl: timedelta
    ) -> bool:
        """Take or re-enter the lease; ``False`` while another live holder has it."""

    async def renew(self, organization_id: PydanticObjectId, operation_id: PydanticObjectId, *, ttl: timedelta) -> bool:
        """Extend the lease; ``False`` when this operation no longer holds it."""

    async def release(self, organization_id: PydanticObjectId, operation_id: PydanticObjectId) -> None:
        """Give the lease up if this operation holds it."""


class MongoRestoreLeaseStore:
    """Lease backed by a unique organization document with a TTL index."""

    async def acquire(
        self, organization_id: PydanticObjectId, operation_id: PydanticObjectId, *, ttl: timedelta
    ) -> bool:
        """Take the lease in one conditional upsert that the unique index arbitrates.

        The filter matches only a lease this operation holds or one that has
        expired; otherwise the upsert inserts a second document for the
        organization, which the unique index refuses. There is no read before
        the write, so two workers can never both see the organization as free.
        """
        now = utc_now()
        try:
            await RestoreLease.get_pymongo_collection().update_one(
                {
                    "organization_id": organization_id,
                    "$or": [{"holder_operation_id": operation_id}, {"expires_at": {"$lte": now}}],
                },
                {"$set": {"holder_operation_id": operation_id, "acquired_at": now, "expires_at": now + ttl}},
                upsert=True,
            )
        except DuplicateKeyError:
            return False
        return True

    async def renew(self, organization_id: PydanticObjectId, operation_id: PydanticObjectId, *, ttl: timedelta) -> bool:
        """Extend the lease only while this operation still holds it."""
        result = await RestoreLease.get_pymongo_collection().update_one(
            {"organization_id": organization_id, "holder_operation_id": operation_id},
            {"$set": {"expires_at": utc_now() + ttl}},
        )
        return result.matched_count == 1

    async def release(self, organization_id: PydanticObjectId, operation_id: PydanticObjectId) -> None:
        """Remove the lease if this operation holds it, never one another restore took over."""
        await RestoreLease.get_pymongo_collection().delete_one(
            {"organization_id": organization_id, "holder_operation_id": operation_id}
        )


class MemoryRestoreLeaseStore:
    """Process-local lease with the same semantics, for tests."""

    def __init__(self, clock: Callable[[], datetime] = utc_now) -> None:
        self._clock = clock
        self._leases: dict[PydanticObjectId, tuple[PydanticObjectId, datetime]] = {}

    async def acquire(
        self, organization_id: PydanticObjectId, operation_id: PydanticObjectId, *, ttl: timedelta
    ) -> bool:
        """Take or re-enter the lease; ``False`` while another live holder has it."""
        now = self._clock()
        held = self._leases.get(organization_id)
        if held is not None and held[0] != operation_id and held[1] > now:
            return False
        self._leases[organization_id] = (operation_id, now + ttl)
        return True

    async def renew(self, organization_id: PydanticObjectId, operation_id: PydanticObjectId, *, ttl: timedelta) -> bool:
        """Extend the lease only while this operation still holds it."""
        held = self._leases.get(organization_id)
        if held is None or held[0] != operation_id:
            return False
        self._leases[organization_id] = (operation_id, self._clock() + ttl)
        return True

    async def release(self, organization_id: PydanticObjectId, operation_id: PydanticObjectId) -> None:
        """Remove the lease if this operation holds it."""
        held = self._leases.get(organization_id)
        if held is not None and held[0] == operation_id:
            del self._leases[organization_id]


async def has_active_restore(organization_id: PydanticObjectId, operation_id: PydanticObjectId) -> bool:
    """Whether another restore of this organization is queued or running.

    The operation asking is excluded, so a plan never blocks itself.
    """
    count = await RestoreOperation.find(
        RestoreOperation.organization_id == organization_id,
        {"_id": {"$ne": operation_id}, "status": {"$in": [RestoreStatus.QUEUED, RestoreStatus.RUNNING]}},
    ).count()
    return count > 0
