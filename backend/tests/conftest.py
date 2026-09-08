"""Shared fixtures.

The API tests run with no MongoDB. Stores that the dependency factories build
against the database are replaced here with their in-memory counterparts, and
reset between tests, so a sign-in in one test cannot throttle the next.
"""

import pytest

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
