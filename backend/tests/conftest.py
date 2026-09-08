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
    """

    def __init__(self) -> None:
        self.writes: list[tuple[dict[str, Any], dict[str, Any]]] = []

    async def update_one(self, criteria: dict[str, Any], update: dict[str, Any]) -> Any:
        self.writes.append((criteria, update))
        return SimpleNamespace(modified_count=1, matched_count=1)

    async def update_many(self, criteria: dict[str, Any], update: dict[str, Any]) -> Any:
        self.writes.append((criteria, update))
        return SimpleNamespace(modified_count=1, matched_count=1)

    def fields(self) -> list[str]:
        """Every field name written so far, in order."""
        return [name for _criteria, update in self.writes for name in update.get("$set", {})]


@pytest.fixture(autouse=True)
def user_writes(monkeypatch: pytest.MonkeyPatch) -> _RecordingUserCollection:
    """Accept field-scoped user writes without a database, and record them."""
    collection = _RecordingUserCollection()
    monkeypatch.setattr(User, "get_pymongo_collection", lambda: collection)
    return collection
