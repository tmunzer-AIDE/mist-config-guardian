"""Signed-in account API tests."""

from datetime import timedelta
from typing import Any

import httpx
import pyotp
import pytest
from beanie import PydanticObjectId
from fastapi import Request

from mist_config_guardian_backend.api.dependencies import get_session_service, require_viewer
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.main import create_app
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.session import UserSession
from mist_config_guardian_backend.models.user import User, UserRole, WebAuthnCredential
from mist_config_guardian_backend.security import webauthn as webauthn_security
from mist_config_guardian_backend.security.auth import hash_password, verify_password
from mist_config_guardian_backend.security.totp import RECOVERY_CODE_COUNT, hash_recovery_code
from mist_config_guardian_backend.services import mfa as mfa_service
from mist_config_guardian_backend.services.mfa import pending_totp_store

BASE_URL = "http://test"
PASSWORD = "a-long-enough-password"


def _settings() -> Settings:
    return Settings(
        environment="test",
        database_enabled=False,
        secret_key="unit-test-signing-key-that-is-long-enough",
    )


def _user() -> User:
    return User.model_construct(
        id=PydanticObjectId(),
        email="operator@example.com",
        display_name="Operator",
        password_hash=hash_password(PASSWORD),
        role=UserRole.OPERATOR,
        is_active=True,
        totp=None,
        pending_email_change=None,
        password_changed_at=None,
        last_login_at=None,
    )


def _session(user: User) -> UserSession:
    now = utc_now()
    return UserSession.model_construct(
        id=PydanticObjectId(),
        user_id=user.id,
        token_hash="token-digest",
        csrf_hash="csrf-digest",
        label="Chrome on macOS",
        ip_address="127.0.0.1",
        location=None,
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(days=30),
        revoked_at=None,
        mfa_verified_at=None,
    )


class _FakeSessions:
    def __init__(self, sessions: list[UserSession]) -> None:
        self.sessions = sessions
        self.revoke_all_calls: list[tuple[PydanticObjectId, PydanticObjectId | None]] = []
        self.revoked: list[PydanticObjectId] = []

    async def resolve_request_user(self, _request: object) -> None:
        return None

    async def list_for_user(self, _user_id: PydanticObjectId) -> list[UserSession]:
        return list(self.sessions)

    async def revoke(self, _user_id: PydanticObjectId, session_id: PydanticObjectId) -> bool:
        self.revoked.append(session_id)
        return any(session.id == session_id for session in self.sessions)

    async def revoke_all(
        self,
        user_id: PydanticObjectId,
        *,
        except_session_id: PydanticObjectId | None = None,
    ) -> int:
        self.revoke_all_calls.append((user_id, except_session_id))
        return len([s for s in self.sessions if s.id != except_session_id])


class _FakeQuery:
    def __init__(self, items: list[WebAuthnCredential]) -> None:
        self._items = items

    def sort(self, *_args: object) -> "_FakeQuery":
        return self

    async def to_list(self) -> list[WebAuthnCredential]:
        return list(self._items)

    async def count(self) -> int:
        return len(self._items)


@pytest.fixture(autouse=True)
def _no_database(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep every document operation in memory and reset shared MFA state."""
    # The API dependency builds the database-backed stores; these tests run with
    # no MongoDB, so substitute the in-memory implementations of both.
    pending_totp_store.clear()
    webauthn_security.challenge_store.clear()
    monkeypatch.setattr(mfa_service, "DatabasePendingTotpEnrollmentStore", lambda: pending_totp_store)
    monkeypatch.setattr(
        webauthn_security,
        "DatabaseWebAuthnChallengeStore",
        lambda: webauthn_security.challenge_store,
    )

    async def _save(self: User, *_args: object, **_kwargs: object) -> User:
        return self

    async def _find_one(_criteria: dict[str, Any], **_kwargs: object) -> None:
        return None

    def _find(_criteria: dict[str, Any], **_kwargs: object) -> _FakeQuery:
        return _FakeQuery([])

    monkeypatch.setattr(User, "save", _save)
    monkeypatch.setattr(User, "find_one", _find_one)
    monkeypatch.setattr(WebAuthnCredential, "find", _find)


def _client(app: object) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL)


def _signed_in(user: User, session: UserSession | None = None):
    def dependency(request: Request) -> User:
        if session is not None:
            request.state.session = session
        return user

    return dependency


# --------------------------------------------------------------------- profile
async def test_account_endpoints_require_authentication() -> None:
    app = create_app(_settings())

    async with _client(app) as client:
        response = await client.get("/api/v1/account/profile")

    assert response.status_code == 401


async def test_profile_update_applies_preferences() -> None:
    app = create_app(_settings())
    user = _user()
    app.dependency_overrides[require_viewer] = _signed_in(user)

    async with _client(app) as client:
        response = await client.patch(
            "/api/v1/account/profile",
            json={
                "display_name": "  Night Operator  ",
                "timezone": "Europe/Paris",
                "clock": "12h",
                "landing_page": "history",
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["display_name"] == "Night Operator"
    assert body["preferences"] == {
        "timezone": "Europe/Paris",
        "clock": "12h",
        "landing_page": "history",
    }
    assert "password_hash" not in response.text


async def test_profile_update_rejects_an_unknown_timezone() -> None:
    app = create_app(_settings())
    app.dependency_overrides[require_viewer] = _signed_in(_user())

    async with _client(app) as client:
        response = await client.patch(
            "/api/v1/account/profile",
            json={"timezone": "Mars/Olympus_Mons"},
        )

    assert response.status_code == 422


# -------------------------------------------------------------------- password
async def test_password_change_revokes_every_other_session() -> None:
    app = create_app(_settings())
    user = _user()
    current = _session(user)
    other = _session(user)
    sessions = _FakeSessions([current, other])
    app.dependency_overrides[require_viewer] = _signed_in(user, current)
    app.dependency_overrides[get_session_service] = lambda: sessions

    async with _client(app) as client:
        response = await client.post(
            "/api/v1/account/password",
            json={"current_password": PASSWORD, "new_password": "an-even-longer-password"},
        )

    assert response.status_code == 200
    assert response.json()["revoked_sessions"] == 1
    assert sessions.revoke_all_calls == [(user.id, current.id)]
    assert verify_password("an-even-longer-password", user.password_hash)
    assert user.password_changed_at is not None


async def test_password_change_rejects_a_wrong_current_password() -> None:
    app = create_app(_settings())
    user = _user()
    sessions = _FakeSessions([])
    app.dependency_overrides[require_viewer] = _signed_in(user)
    app.dependency_overrides[get_session_service] = lambda: sessions

    async with _client(app) as client:
        response = await client.post(
            "/api/v1/account/password",
            json={"current_password": "not-the-password", "new_password": "an-even-longer-password"},
        )

    assert response.status_code == 403
    assert sessions.revoke_all_calls == []
    assert verify_password(PASSWORD, user.password_hash)


async def test_password_change_enforces_a_minimum_length() -> None:
    app = create_app(_settings())
    app.dependency_overrides[require_viewer] = _signed_in(_user())

    async with _client(app) as client:
        response = await client.post(
            "/api/v1/account/password",
            json={"current_password": PASSWORD, "new_password": "short"},
        )

    assert response.status_code == 422


# ---------------------------------------------------------------- email change
async def test_email_change_returns_its_token_once_and_applies_on_confirm() -> None:
    app = create_app(_settings())
    user = _user()
    app.dependency_overrides[require_viewer] = _signed_in(user)

    async with _client(app) as client:
        requested = await client.post(
            "/api/v1/account/email-change",
            json={"new_email": "New@example.com", "password": PASSWORD},
        )
        token = requested.json()["confirmation_token"]
        confirmed = await client.post("/api/v1/account/email-change/confirm", json={"token": token})

    assert requested.status_code == 200
    assert requested.json()["pending_email"] == "new@example.com"
    assert requested.json()["delivery"] == "not_implemented"
    assert "token_hash" not in requested.text
    assert confirmed.status_code == 200
    assert confirmed.json()["email"] == "new@example.com"
    assert confirmed.json()["pending_email"] is None


async def test_email_change_requires_the_current_password() -> None:
    app = create_app(_settings())
    user = _user()
    app.dependency_overrides[require_viewer] = _signed_in(user)

    async with _client(app) as client:
        response = await client.post(
            "/api/v1/account/email-change",
            json={"new_email": "new@example.com", "password": "not-the-password"},
        )

    assert response.status_code == 403
    assert user.pending_email_change is None


async def test_email_change_confirmation_rejects_a_wrong_token() -> None:
    app = create_app(_settings())
    user = _user()
    app.dependency_overrides[require_viewer] = _signed_in(user)

    async with _client(app) as client:
        await client.post(
            "/api/v1/account/email-change",
            json={"new_email": "new@example.com", "password": PASSWORD},
        )
        confirmed = await client.post(
            "/api/v1/account/email-change/confirm",
            json={"token": "not-the-real-token"},
        )
        cancelled = await client.delete("/api/v1/account/email-change")

    assert confirmed.status_code == 400
    assert cancelled.status_code == 200
    assert cancelled.json()["pending_email"] is None
    assert user.email == "operator@example.com"


# -------------------------------------------------------------------- sessions
async def test_session_list_marks_the_current_session() -> None:
    app = create_app(_settings())
    user = _user()
    current = _session(user)
    other = _session(user)
    sessions = _FakeSessions([current, other])
    app.dependency_overrides[require_viewer] = _signed_in(user, current)
    app.dependency_overrides[get_session_service] = lambda: sessions

    async with _client(app) as client:
        listed = await client.get("/api/v1/account/sessions")
        revoked = await client.delete(f"/api/v1/account/sessions/{other.id}")
        others = await client.post("/api/v1/account/sessions/revoke-others")

    assert listed.status_code == 200
    body = listed.json()
    assert body["total"] == 2
    assert [item["current"] for item in body["items"]] == [True, False]
    assert "token_hash" not in listed.text
    assert "csrf_hash" not in listed.text
    assert revoked.status_code == 200
    assert sessions.revoked == [other.id]
    assert others.json()["revoked_sessions"] == 1


async def test_revoking_an_unknown_session_is_a_not_found() -> None:
    app = create_app(_settings())
    user = _user()
    sessions = _FakeSessions([])
    app.dependency_overrides[require_viewer] = _signed_in(user)
    app.dependency_overrides[get_session_service] = lambda: sessions

    async with _client(app) as client:
        response = await client.delete(f"/api/v1/account/sessions/{PydanticObjectId()}")

    assert response.status_code == 404


# ------------------------------------------------------------------------ totp
async def test_totp_enroll_then_confirm_returns_recovery_codes_once() -> None:
    app = create_app(_settings())
    user = _user()
    app.dependency_overrides[require_viewer] = _signed_in(user)

    async with _client(app) as client:
        enrolled = await client.post("/api/v1/account/totp/enroll")
        secret = enrolled.json()["secret"]
        confirmed = await client.post(
            "/api/v1/account/totp/confirm",
            json={"code": pyotp.TOTP(secret).now()},
        )
        again = await client.post("/api/v1/account/totp/enroll")

    assert enrolled.status_code == 200
    assert enrolled.json()["otpauth_uri"].startswith("otpauth://totp/")
    assert confirmed.status_code == 200
    codes = confirmed.json()["recovery_codes"]
    assert len(codes) == RECOVERY_CODE_COUNT
    assert user.totp is not None
    assert user.totp.recovery_code_hashes == [hash_recovery_code(code) for code in codes]
    assert secret not in confirmed.text
    assert user.totp.encrypted_secret not in confirmed.text
    assert again.status_code == 409


async def test_totp_confirm_rejects_a_wrong_code() -> None:
    app = create_app(_settings())
    user = _user()
    app.dependency_overrides[require_viewer] = _signed_in(user)

    async with _client(app) as client:
        await client.post("/api/v1/account/totp/enroll")
        response = await client.post("/api/v1/account/totp/confirm", json={"code": "000000"})

    assert response.status_code == 400
    assert user.totp is None


async def test_totp_removal_and_recovery_code_rotation_need_the_password() -> None:
    app = create_app(_settings())
    user = _user()
    app.dependency_overrides[require_viewer] = _signed_in(user)

    async with _client(app) as client:
        enrolled = await client.post("/api/v1/account/totp/enroll")
        secret = enrolled.json()["secret"]
        first = await client.post(
            "/api/v1/account/totp/confirm",
            json={"code": pyotp.TOTP(secret).now()},
        )
        wrong = await client.request(
            "DELETE",
            "/api/v1/account/totp",
            json={"password": "not-the-password"},
        )
        rotated = await client.post(
            "/api/v1/account/totp/recovery-codes",
            json={"password": PASSWORD},
        )
        removed = await client.request(
            "DELETE",
            "/api/v1/account/totp",
            json={"password": PASSWORD},
        )

    assert wrong.status_code == 403
    assert rotated.status_code == 200
    assert rotated.json()["recovery_codes"] != first.json()["recovery_codes"]
    assert removed.status_code == 200
    assert user.totp is None


async def test_recovery_code_rotation_requires_an_enrollment() -> None:
    app = create_app(_settings())
    app.dependency_overrides[require_viewer] = _signed_in(_user())

    async with _client(app) as client:
        response = await client.post(
            "/api/v1/account/totp/recovery-codes",
            json={"password": PASSWORD},
        )

    assert response.status_code == 409


# -------------------------------------------------------------------- passkeys
async def test_passkey_registration_options_do_not_leak_the_challenge() -> None:
    app = create_app(_settings())
    user = _user()
    app.dependency_overrides[require_viewer] = _signed_in(user)

    async with _client(app) as client:
        listed = await client.get("/api/v1/account/passkeys")
        options = await client.post("/api/v1/account/passkeys/options", json={"password": PASSWORD})
        refused = await client.post("/api/v1/account/passkeys/options", json={"password": "not it"})

    assert listed.json() == {"items": [], "total": 0}
    assert options.status_code == 200
    body = options.json()
    assert body["options"]["rp"]["id"] == "localhost"
    assert body["challenge_token"]
    assert body["options"]["challenge"] not in body["challenge_token"]
    # A stolen session cannot install a durable credential without the password.
    assert refused.status_code == 403
