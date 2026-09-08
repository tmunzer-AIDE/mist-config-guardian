"""Failure counting for sign-in and password confirmation.

A password can be guessed and a six-digit code can be enumerated; neither the
hash nor the code's lifetime is a defence on its own. Every endpoint that
accepts a password or a code counts its failures here, per account and per
client address, and answers 429 once a window's limit is reached.

The count is kept in MongoDB by default so the limit holds across every API
replica; the in-memory store serves tests and single-process runs.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Annotated, Protocol

from beanie import PydanticObjectId
from fastapi import Depends, HTTPException, Request, status
from pymongo import ReturnDocument

from mist_config_guardian_backend.config import Settings, get_settings
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.challenge import ThrottleBucket


@dataclass(frozen=True, slots=True)
class Scope:
    """One counted key and the number of failures it tolerates per window."""

    key: str
    limit: int


class ThrottledError(Exception):
    """Raised when a scope has reached its limit; carries the seconds left."""

    def __init__(self, retry_after: int) -> None:
        super().__init__(f"Too many attempts; try again in {retry_after} seconds")
        self.retry_after = retry_after


class ThrottleStore(Protocol):
    """The persistence the throttle depends on."""

    async def failures(self, key: str) -> tuple[int, datetime] | None:
        """Return the count and expiry for a key, or ``None`` when it has none."""
        ...

    async def record(self, key: str, window: timedelta) -> int:
        """Count one attempt against a key, opening a window if none is running."""
        ...

    async def release(self, key: str) -> None:
        """Give back one counted attempt that turned out not to be a failure."""
        ...

    async def clear(self, key: str) -> None:
        """Forget a key's failures."""
        ...


class MemoryThrottleStore:
    """Process-local counting for tests and single-process runs."""

    def __init__(self, now: Callable[[], datetime] = utc_now) -> None:
        self._now = now
        self._buckets: dict[str, tuple[int, datetime]] = {}

    async def failures(self, key: str) -> tuple[int, datetime] | None:
        """Return the live count for a key."""
        bucket = self._buckets.get(key)
        if bucket is None:
            return None
        if bucket[1] <= self._now():
            del self._buckets[key]
            return None
        return bucket

    async def record(self, key: str, window: timedelta) -> int:
        """Count one attempt."""
        live = await self.failures(key)
        count = (live[0] if live is not None else 0) + 1
        expires_at = live[1] if live is not None else self._now() + window
        self._buckets[key] = (count, expires_at)
        return count

    async def release(self, key: str) -> None:
        """Give back one counted attempt."""
        live = await self.failures(key)
        if live is None:
            return
        remaining = live[0] - 1
        if remaining <= 0:
            self._buckets.pop(key, None)
        else:
            self._buckets[key] = (remaining, live[1])

    async def clear(self, key: str) -> None:
        """Forget a key."""
        self._buckets.pop(key, None)

    def reset(self) -> None:
        """Forget every key."""
        self._buckets.clear()


class DatabaseThrottleStore:
    """Counting shared by every API replica."""

    async def failures(self, key: str) -> tuple[int, datetime] | None:
        """Return the live count for a key; the TTL index removes expired ones."""
        bucket = await ThrottleBucket.find_one(ThrottleBucket.key == key)
        if bucket is None or bucket.expires_at <= utc_now():
            return None
        return bucket.failures, bucket.expires_at

    async def record(self, key: str, window: timedelta) -> int:
        """Count one attempt atomically, opening a window on the first.

        The increment and the count that decides admission are one operation,
        so two requests cannot both read a below-limit value and both proceed.
        """
        now = utc_now()
        document = await ThrottleBucket.get_pymongo_collection().find_one_and_update(
            {"key": key},
            {
                "$inc": {"failures": 1},
                "$set": {"updated_at": now},
                "$setOnInsert": {"expires_at": now + window, "created_at": now},
            },
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        return int(document["failures"])

    async def release(self, key: str) -> None:
        """Give back one counted attempt that turned out not to be a failure."""
        await ThrottleBucket.get_pymongo_collection().update_one(
            {"key": key, "failures": {"$gt": 0}},
            {"$inc": {"failures": -1}, "$set": {"updated_at": utc_now()}},
        )

    async def clear(self, key: str) -> None:
        """Forget a key."""
        await ThrottleBucket.find(ThrottleBucket.key == key).delete()


class ThrottleService:
    """Count failures per scope and refuse further attempts past a limit."""

    def __init__(self, settings: Settings, store: ThrottleStore | None = None) -> None:
        self._settings = settings
        self._store: ThrottleStore = store if store is not None else DatabaseThrottleStore()
        self._window = timedelta(minutes=settings.sign_in_throttle_window_minutes)

    # ----------------------------------------------------------------- scopes
    def account(self, email: str) -> Scope:
        """The scope for sign-in attempts against one email address."""
        return Scope(f"account:{email.strip().lower()}", self._settings.sign_in_failures_per_account)

    def user(self, user_id: PydanticObjectId) -> Scope:
        """The scope for password confirmations by one signed-in user."""
        return Scope(f"user:{user_id}", self._settings.sign_in_failures_per_account)

    def second_factor(self, user_id: PydanticObjectId) -> Scope:
        """The scope for second-factor codes tried against one account.

        Separate from the password scope, and cleared only by a completed
        second factor: fresh challenges and rotating addresses must not add up
        to an unbounded code budget.
        """
        return Scope(f"mfa:{user_id}", self._settings.sign_in_failures_per_account)

    def address(self, request: Request) -> Scope:
        """The scope for everything arriving from one client address.

        Behind a proxy this is the proxy unless the server is started with its
        forwarded-header handling enabled, so the per-address limit is the wide
        backstop and the per-account limit does the real work.
        """
        host = request.client.host if request.client is not None else "unknown"
        return Scope(f"address:{host}", self._settings.sign_in_failures_per_address)

    # ---------------------------------------------------------------- actions
    async def reserve(self, *scopes: Scope) -> None:
        """Count an attempt before it is made, refusing it if that exceeds a limit.

        Counting first is what makes the limit hold. Reading the count, doing
        the expensive credential check, and only then recording a failure lets
        any number of requests read the same below-limit value and all proceed:
        the threshold then bounds completed serial failures rather than
        attempts admitted. The count is given back by :meth:`succeeded` and
        :meth:`release`, so a reservation that is not a failure does not
        linger.
        """
        for scope in scopes:
            count = await self._store.record(scope.key, self._window)
            if count > scope.limit:
                live = await self._store.failures(scope.key)
                remaining = max(1, int((live[1] - utc_now()).total_seconds())) if live else 1
                raise ThrottledError(remaining)

    async def failed(self, *scopes: Scope) -> None:
        """Count one failure against every scope, outside a reservation."""
        for scope in scopes:
            await self._store.record(scope.key, self._window)

    async def release(self, *scopes: Scope) -> None:
        """Give back reservations an attempt did not spend as a failure.

        Used for the per-address scope, where one address serves many people
        and a success must not count towards their shared limit.
        """
        for scope in scopes:
            await self._store.release(scope.key)

    async def succeeded(self, *scopes: Scope) -> None:
        """Forget the failures of scopes a success vindicates.

        Only account-level scopes should be passed here: one address serves
        many people, and one person's success says nothing about the others.
        """
        for scope in scopes:
            await self._store.clear(scope.key)


def throttled(error: ThrottledError) -> HTTPException:
    """Translate a limit into the response a client can act on."""
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=str(error),
        headers={"Retry-After": str(error.retry_after)},
    )


async def reserve_or_raise(throttle: ThrottleService, *scopes: Scope) -> None:
    """Apply :meth:`ThrottleService.reserve` inside a route."""
    try:
        await throttle.reserve(*scopes)
    except ThrottledError as exc:
        raise throttled(exc) from exc


def get_throttle_service(settings: Annotated[Settings, Depends(get_settings)]) -> ThrottleService:
    """Build the throttle service backed by the shared store."""
    return ThrottleService(settings)
