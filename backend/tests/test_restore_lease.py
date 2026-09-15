"""The in-memory lease behaves like the MongoDB one the executor relies on."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from beanie import PydanticObjectId
from beanie.odm.fields import ExpressionField

from mist_config_guardian_backend.models.restore import RestoreOperation
from mist_config_guardian_backend.services.restore_lease import MemoryRestoreLeaseStore, has_active_restore

TTL = timedelta(minutes=15)


@pytest.fixture
def no_queued_restores(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """No operation of any organization is queued or running."""
    monkeypatch.setattr(RestoreOperation, "organization_id", ExpressionField("organization_id"), raising=False)
    query = SimpleNamespace(count=AsyncMock(return_value=0))
    monkeypatch.setattr(RestoreOperation, "find", MagicMock(return_value=query))
    return query


async def test_a_live_lease_is_held_by_another_only_for_everyone_but_its_holder() -> None:
    now = datetime(2026, 9, 14, 12, 0, tzinfo=UTC)
    clock = [now]
    store = MemoryRestoreLeaseStore(clock=lambda: clock[0])
    organization, holder, other = PydanticObjectId(), PydanticObjectId(), PydanticObjectId()

    assert await store.held_by_another(organization, other) is False
    await store.acquire(organization, holder, ttl=TTL)
    assert await store.held_by_another(organization, other) is True
    assert await store.held_by_another(organization, holder) is False
    assert await store.held_by_another(PydanticObjectId(), other) is False

    clock[0] = now + TTL + timedelta(seconds=1)
    assert await store.held_by_another(organization, other) is False


@pytest.mark.usefixtures("no_queued_restores")
async def test_a_stale_lease_counts_as_an_active_restore_when_no_operation_is_queued() -> None:
    leases = MemoryRestoreLeaseStore()
    organization, stale_holder, asking = PydanticObjectId(), PydanticObjectId(), PydanticObjectId()
    assert await has_active_restore(organization, asking, leases=leases) is False

    # The holder reached a terminal status but its release never happened.
    await leases.acquire(organization, stale_holder, ttl=TTL)

    assert await has_active_restore(organization, asking, leases=leases) is True
    assert await has_active_restore(organization, stale_holder, leases=leases) is False
    await leases.release(organization, stale_holder)
    assert await has_active_restore(organization, asking, leases=leases) is False


async def test_a_queued_operation_is_active_without_consulting_the_lease(no_queued_restores: SimpleNamespace) -> None:
    no_queued_restores.count.return_value = 1
    leases = MemoryRestoreLeaseStore()

    assert await has_active_restore(PydanticObjectId(), PydanticObjectId(), leases=leases) is True


async def test_one_holder_per_organization_until_release() -> None:
    store = MemoryRestoreLeaseStore()
    organization, first, second = PydanticObjectId(), PydanticObjectId(), PydanticObjectId()

    assert await store.acquire(organization, first, ttl=TTL) is True
    assert await store.acquire(organization, second, ttl=TTL) is False
    assert await store.acquire(PydanticObjectId(), second, ttl=TTL) is True
    assert await store.renew(organization, second, ttl=TTL) is False
    await store.release(organization, second)
    assert await store.acquire(organization, second, ttl=TTL) is False
    await store.release(organization, first)
    assert await store.acquire(organization, second, ttl=TTL) is True


async def test_an_expired_lease_can_be_taken_over() -> None:
    now = datetime(2026, 9, 14, 12, 0, tzinfo=UTC)
    clock = [now]
    store = MemoryRestoreLeaseStore(clock=lambda: clock[0])
    organization, first, second = PydanticObjectId(), PydanticObjectId(), PydanticObjectId()
    await store.acquire(organization, first, ttl=TTL)

    clock[0] = now + TTL + timedelta(seconds=1)

    assert await store.acquire(organization, second, ttl=TTL) is True
    assert await store.renew(organization, first, ttl=TTL) is False


async def test_a_renewed_lease_outlives_its_first_expiry() -> None:
    now = datetime(2026, 9, 14, 12, 0, tzinfo=UTC)
    clock = [now]
    store = MemoryRestoreLeaseStore(clock=lambda: clock[0])
    organization, first, second = PydanticObjectId(), PydanticObjectId(), PydanticObjectId()
    await store.acquire(organization, first, ttl=TTL)

    clock[0] = now + TTL - timedelta(seconds=1)
    assert await store.renew(organization, first, ttl=TTL) is True
    clock[0] = now + TTL + timedelta(seconds=1)

    assert await store.acquire(organization, second, ttl=TTL) is False
