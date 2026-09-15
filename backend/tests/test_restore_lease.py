"""The in-memory lease behaves like the MongoDB one the executor relies on."""

from datetime import UTC, datetime, timedelta

from beanie import PydanticObjectId

from mist_config_guardian_backend.services.restore_lease import MemoryRestoreLeaseStore

TTL = timedelta(minutes=15)


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
