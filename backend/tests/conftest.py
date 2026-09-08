"""Shared fixtures.

The API tests run with no MongoDB. Stores that the dependency factories build
against the database are replaced here with their in-memory counterparts, and
reset between tests, so a sign-in in one test cannot throttle the next.
"""

from types import SimpleNamespace
from typing import Any

import pytest

from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.services import mfa as mfa_service
from mist_config_guardian_backend.services import throttling

login_challenge_store = mfa_service.LoginChallengeStore()
throttle_store = throttling.MemoryThrottleStore()


@pytest.fixture(autouse=True)
def _memory_stores(monkeypatch: pytest.MonkeyPatch) -> None:
    login_challenge_store.reset()
    throttle_store.reset()
    monkeypatch.setattr(mfa_service, "DatabaseLoginChallengeStore", lambda: login_challenge_store)
    monkeypatch.setattr(throttling, "DatabaseThrottleStore", lambda: throttle_store)


class _RecordingUserCollection:
    """Stands in for the users collection during field-scoped writes.

    `write_user_fields` names the fields it changes rather than saving whole
    documents, and updates the in-memory object itself, so a test double only
    has to accept the write. The documents are kept so a test can assert which
    fields a request actually named.

    Some writes are conditional — they apply only while the stored document
    still says what the request read. A double that accepts everything would
    report those as applied when the real collection would not, so a test can
    `track` the user it is writing to and have the condition actually decided.
    """

    def __init__(self) -> None:
        self.writes: list[tuple[dict[str, Any], dict[str, Any]]] = []
        self._tracked: dict[Any, User] = {}

    def track(self, user: User) -> None:
        """Answer conditional writes against this user's current state."""
        self._tracked[user.id] = user

    async def update_one(self, criteria: dict[str, Any], update: dict[str, Any]) -> Any:
        self.writes.append((criteria, update))
        user = self._tracked.get(criteria.get("_id"))
        if user is None:
            # A write that asks for more than an identifier is conditional, and
            # nothing here can say whether the condition holds. Reporting it as
            # applied would let a test pass on a write the database would have
            # rejected, so it is reported as not matching instead.
            applied = set(criteria) <= {"_id"}
            return SimpleNamespace(
                modified_count=int(applied),
                matched_count=int(applied),
            )
        if not _satisfies(user, criteria):
            return SimpleNamespace(modified_count=0, matched_count=0)
        # Apply it, so a second request reading the same account sees what the
        # first one did rather than its own starting copy.
        _apply(user, update)
        return SimpleNamespace(modified_count=1, matched_count=1)

    async def update_many(self, criteria: dict[str, Any], update: dict[str, Any]) -> Any:
        self.writes.append((criteria, update))
        return SimpleNamespace(modified_count=1, matched_count=1)

    def fields(self) -> list[str]:
        """Every field name written so far, in order."""
        return [name for _criteria, update in self.writes for name in update.get("$set", {})]


def _resolve(user: User, path: str) -> Any:
    """Read a dotted document path off the in-memory user."""
    value: Any = user
    for part in path.split("."):
        if value is None:
            return None
        value = getattr(value, part, None)
    return value


def _apply(user: User, update: dict[str, Any]) -> None:
    """Apply the operators the application actually issues."""
    for path, value in update.get("$set", {}).items():
        _assign(user, path, value)
    for path, value in update.get("$pull", {}).items():
        current = _resolve(user, path)
        if isinstance(current, list):
            _assign(user, path, [item for item in current if item != value])


def _assign(user: User, path: str, value: Any) -> None:
    parts = path.split(".")
    target: Any = user
    for part in parts[:-1]:
        target = getattr(target, part, None)
        if target is None:
            return
    setattr(target, parts[-1], value)


def _satisfies(user: User, criteria: dict[str, Any]) -> bool:
    """Whether a conditional write's criteria still describe this user."""
    for path, expected in criteria.items():
        if path == "_id":
            continue
        value = _resolve(user, path)
        # A criterion naming an array field asks whether it contains the value.
        if isinstance(value, list):
            if expected not in value:
                return False
        elif value != expected:
            return False
    return True


@pytest.fixture(autouse=True)
def user_writes(monkeypatch: pytest.MonkeyPatch) -> _RecordingUserCollection:
    """Accept field-scoped user writes without a database, and record them."""
    collection = _RecordingUserCollection()
    monkeypatch.setattr(User, "get_pymongo_collection", lambda: collection)
    return collection
