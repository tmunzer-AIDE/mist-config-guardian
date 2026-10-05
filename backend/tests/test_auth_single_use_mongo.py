"""Single-use sign-in state stays single-use when requests race on MongoDB.

Each store hands out something meant to be spent once: a WebAuthn challenge, an
unconfirmed authenticator secret, a password-accepted sign-in waiting for its
second factor, an authenticator code's time step. Reading the record and then
deleting or updating it lets every request that read it before the first write
proceed, so these tests present one record from many requests at once and
count the winners.

Skipped unless ``MONGO_TEST_URL`` names a reachable MongoDB.
"""

import asyncio
import os
from datetime import timedelta

import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.models.challenge import LoginChallenge, PendingTotpEnrollment, WebAuthnChallenge
from mist_config_guardian_backend.models.user import User, claim_totp_step
from mist_config_guardian_backend.security.webauthn import (
    AUTHENTICATION_PURPOSE,
    DatabaseWebAuthnChallengeStore,
    WebAuthnError,
)
from mist_config_guardian_backend.services.mfa import (
    DatabaseLoginChallengeStore,
    DatabasePendingTotpEnrollmentStore,
)

# Bound before the shared fixtures replace it with an in-memory double.
_USERS_COLLECTION = User.get_pymongo_collection

MONGO_URL = os.environ.get("MONGO_TEST_URL")
DATABASE = "auth_single_use"
CONTENDERS = 8
# A race needs connections to race on: the first round can run on a pool still
# opening its first connection, which serializes it, so each test repeats.
ROUNDS = 5

pytestmark = [
    pytest.mark.skipif(not MONGO_URL, reason="MONGO_TEST_URL is not set"),
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.usefixtures("database"),
]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def database() -> None:
    client = AsyncMongoClient(MONGO_URL, tz_aware=True)
    await client.drop_database(DATABASE)
    await init_beanie(
        database=client[DATABASE],
        document_models=[User, WebAuthnChallenge, PendingTotpEnrollment, LoginChallenge],
    )
    yield
    await client.drop_database(DATABASE)
    await client.close()


async def test_a_webauthn_challenge_is_taken_by_one_request_only() -> None:
    store = DatabaseWebAuthnChallengeStore()
    for _ in range(ROUNDS):
        handle = await store.issue(b"challenge", purpose=AUTHENTICATION_PURPOSE)

        results = await asyncio.gather(
            *(store.take(handle, purpose=AUTHENTICATION_PURPOSE) for _ in range(CONTENDERS)),
            return_exceptions=True,
        )

        taken = [result for result in results if not isinstance(result, BaseException)]
        assert len(taken) == 1
        assert taken[0].challenge == b"challenge"
        assert sum(isinstance(result, WebAuthnError) for result in results) == CONTENDERS - 1


async def test_a_pending_enrollment_is_taken_by_one_request_only() -> None:
    store = DatabasePendingTotpEnrollmentStore()
    for _ in range(ROUNDS):
        user_id = str(PydanticObjectId())
        await store.put(user_id, "v1:encrypted")

        results = await asyncio.gather(*(store.take(user_id) for _ in range(CONTENDERS)))

        assert results.count("v1:encrypted") == 1
        assert results.count(None) == CONTENDERS - 1


async def test_a_login_challenge_is_retired_by_one_request_only() -> None:
    """Retiring the challenge is what admits a sign-in, so only one request may do it."""
    store = DatabaseLoginChallengeStore()
    for index in range(ROUNDS):
        handle = f"handle-{index}"
        await store.put(handle, str(PydanticObjectId()), timedelta(minutes=5))

        results = await asyncio.gather(*(store.discard(handle) for _ in range(CONTENDERS)))

        assert results.count(True) == 1
        assert results.count(False) == CONTENDERS - 1


@pytest.fixture
def users_on_mongo(user_writes: object, monkeypatch: pytest.MonkeyPatch) -> None:
    """Put the real users collection back for a test that needs the database to decide."""
    del user_writes
    monkeypatch.setattr(User, "get_pymongo_collection", _USERS_COLLECTION)


@pytest.mark.usefixtures("users_on_mongo")
async def test_an_authenticator_code_step_is_claimed_by_one_request_only() -> None:
    stored = User(email="operator@example.com", display_name="Operator", password_hash="unused")
    await stored.insert()
    for step in range(100, 100 + ROUNDS):
        # Each request loads its own copy of the account, as concurrent workers would.
        copies = [await User.get(stored.id) for _ in range(CONTENDERS)]

        results = await asyncio.gather(*(claim_totp_step(copy, step) for copy in copies if copy is not None))

        assert results.count(True) == 1
        assert results.count(False) == CONTENDERS - 1
    reloaded = await User.get(stored.id)
    assert reloaded is not None
    assert reloaded.totp_last_used_step == 100 + ROUNDS - 1
