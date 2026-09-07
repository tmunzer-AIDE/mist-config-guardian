"""Second-factor enrollment, verification, step-up, and sign-in tests."""

from typing import Any

import httpx
import pyotp
import pytest
from beanie import PydanticObjectId
from fastapi import HTTPException, Request, Response

from mist_config_guardian_backend.api.dependencies import (
    get_session_service,
    get_user_service,
    require_viewer,
)
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.main import create_app
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.session import UserSession
from mist_config_guardian_backend.models.user import TotpEnrollment, User, UserRole, WebAuthnCredential
from mist_config_guardian_backend.security import webauthn as webauthn_security
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.security.totp import (
    RECOVERY_CODE_COUNT,
    consume_recovery_code,
    generate_recovery_codes,
    generate_totp_secret,
    hash_recovery_code,
    normalize_recovery_code,
    verify_totp,
)
from mist_config_guardian_backend.services import mfa as mfa_service
from mist_config_guardian_backend.services.mfa import (
    MFA_CHALLENGE_AUDIENCE,
    TOTP_SECRET_CONTEXT,
    ChallengeTokenError,
    InvalidMfaCodeError,
    MfaService,
    PendingEnrollmentError,
    PendingTotpEnrollmentStore,
    TotpAlreadyEnrolledError,
    issue_challenge_token,
    pending_totp_store,
    read_challenge_token,
    require_fresh_mfa,
)
from mist_config_guardian_backend.services.sessions import SessionService

BASE_URL = "http://test"


def _settings() -> Settings:
    return Settings(
        environment="test",
        secret_key="unit-test-signing-key-that-is-long-enough",
        credential_encryption_key="unit-test-encryption-key",
    )


def _user() -> User:
    return User.model_construct(
        id=PydanticObjectId(),
        email="operator@example.com",
        display_name="Operator",
        password_hash="unused",
        role=UserRole.OPERATOR,
        is_active=True,
        totp=None,
    )


def _service(settings: Settings | None = None) -> MfaService:
    resolved = settings or _settings()
    return MfaService(resolved, CredentialVault(resolved), PendingTotpEnrollmentStore())


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
    """Keep document writes in memory and reset process-wide enrollment state."""
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

    def _find(_criteria: dict[str, Any], **_kwargs: object) -> _FakeQuery:
        return _FakeQuery([])

    monkeypatch.setattr(User, "save", _save)
    monkeypatch.setattr(WebAuthnCredential, "find", _find)


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/",
            "raw_path": b"/",
            "root_path": "",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 5000),
            "server": ("testserver", 80),
            "state": {},
        },
    )


# ---------------------------------------------------------------- primitives
def test_totp_round_trip() -> None:
    secret = generate_totp_secret()

    assert verify_totp(secret, pyotp.TOTP(secret).now())
    assert not verify_totp(secret, "000000")
    assert not verify_totp(secret, "not-a-code")


def test_recovery_codes_are_unique_and_normalized() -> None:
    codes = generate_recovery_codes()

    assert len(codes) == RECOVERY_CODE_COUNT
    assert len(set(codes)) == RECOVERY_CODE_COUNT
    assert hash_recovery_code(codes[0]) == hash_recovery_code(normalize_recovery_code(codes[0]).lower())


def test_recovery_code_is_single_use() -> None:
    codes = generate_recovery_codes(3)
    hashes = [hash_recovery_code(code) for code in codes]

    remaining = consume_recovery_code(codes[1], hashes)

    assert remaining is not None
    assert len(remaining) == 2
    assert consume_recovery_code(codes[1], remaining) is None
    assert consume_recovery_code("ABCDE-FGHIJ", remaining) is None


# ---------------------------------------------------------------- enrollment
async def test_enrollment_stores_only_encrypted_secret() -> None:
    settings = _settings()
    service = _service(settings)
    user = _user()

    started = await service.begin_totp_enrollment(user)
    codes = await service.confirm_totp_enrollment(user, pyotp.TOTP(started.secret).now())

    assert user.totp is not None
    assert started.secret not in user.totp.encrypted_secret
    assert len(codes) == RECOVERY_CODE_COUNT
    assert user.totp.recovery_code_hashes == [hash_recovery_code(code) for code in codes]
    decrypted = CredentialVault(settings).decrypt_for_context(
        user.totp.encrypted_secret,
        context=TOTP_SECRET_CONTEXT,
    )
    assert decrypted == started.secret
    assert started.otpauth_uri.startswith("otpauth://totp/")


async def test_enrollment_rejects_a_wrong_code_but_stays_retryable() -> None:
    service = _service()
    user = _user()
    started = await service.begin_totp_enrollment(user)

    with pytest.raises(InvalidMfaCodeError):
        await service.confirm_totp_enrollment(user, "000000")

    assert user.totp is None
    codes = await service.confirm_totp_enrollment(user, pyotp.TOTP(started.secret).now())
    assert len(codes) == RECOVERY_CODE_COUNT


async def test_confirm_without_enrolling_first_is_refused() -> None:
    with pytest.raises(PendingEnrollmentError):
        await _service().confirm_totp_enrollment(_user(), "123456")


async def test_enrolling_twice_is_refused() -> None:
    service = _service()
    user = _user()
    started = await service.begin_totp_enrollment(user)
    await service.confirm_totp_enrollment(user, pyotp.TOTP(started.secret).now())

    with pytest.raises(TotpAlreadyEnrolledError):
        await service.begin_totp_enrollment(user)


async def test_second_factor_accepts_totp_and_spends_recovery_codes() -> None:
    service = _service()
    user = _user()
    started = await service.begin_totp_enrollment(user)
    codes = await service.confirm_totp_enrollment(user, pyotp.TOTP(started.secret).now())

    assert await service.verify_second_factor(user, pyotp.TOTP(started.secret).now())
    assert await service.verify_second_factor(user, codes[0])
    assert not await service.verify_second_factor(user, codes[0])
    assert user.totp is not None
    assert len(user.totp.recovery_code_hashes) == RECOVERY_CODE_COUNT - 1


# ------------------------------------------------------------- challenge token
def test_login_challenge_round_trip() -> None:
    service = _service()
    user = _user()

    token = service.issue_login_challenge(user)

    assert service.resolve_login_challenge(token) == user.id


def test_login_challenge_rejects_another_audience() -> None:
    settings = _settings()
    token = issue_challenge_token(
        "subject",
        settings=settings,
        audience="some-other-audience",
        lifetime_minutes=5,
    )

    with pytest.raises(ChallengeTokenError):
        read_challenge_token(token, settings=settings, audience=MFA_CHALLENGE_AUDIENCE)


def test_login_challenge_rejects_another_signing_key() -> None:
    token = issue_challenge_token(
        "subject",
        settings=_settings(),
        audience=MFA_CHALLENGE_AUDIENCE,
        lifetime_minutes=5,
    )
    other = Settings(environment="test", secret_key="a-completely-different-signing-key-value")

    with pytest.raises(ChallengeTokenError):
        read_challenge_token(token, settings=other, audience=MFA_CHALLENGE_AUDIENCE)


# ------------------------------------------------------------------- step-up
async def test_step_up_is_not_required_without_an_enrollment() -> None:
    user = _user()

    assert await require_fresh_mfa(_request(), user, SessionService(_settings())) is user


async def test_step_up_is_required_when_the_session_has_not_confirmed() -> None:
    user = _user()
    user.totp = TotpEnrollment(encrypted_secret="v1:whatever", confirmed_at=utc_now())

    with pytest.raises(HTTPException) as caught:
        await require_fresh_mfa(_request(), user, SessionService(_settings()))

    assert caught.value.status_code == 403


async def test_step_up_passes_on_a_freshly_confirmed_session() -> None:
    user = _user()
    user.totp = TotpEnrollment(encrypted_secret="v1:whatever", confirmed_at=utc_now())
    request = _request()
    request.state.session = UserSession.model_construct(
        id=PydanticObjectId(),
        user_id=user.id,
        token_hash="x",
        csrf_hash="y",
        expires_at=utc_now(),
        mfa_verified_at=utc_now(),
    )

    assert await require_fresh_mfa(request, user, SessionService(_settings())) is user


# ------------------------------------------------------------------- sign-in
class _FakeUserService:
    def __init__(self, user: User, password: str) -> None:
        self.user = user
        self.password = password
        self.logins = 0

    async def authenticate(self, email: str, password: str) -> User | None:
        if email.lower() == str(self.user.email).lower() and password == self.password:
            return self.user
        return None

    async def get_by_id(self, user_id: PydanticObjectId) -> User | None:
        return self.user if self.user.id == user_id else None

    async def record_login(self, user: User) -> User:
        self.logins += 1
        user.last_login_at = utc_now()
        return user


class _FakeSessionService:
    def __init__(self) -> None:
        self.started: list[bool] = []

    async def start(
        self,
        user: User,
        *,
        response: Response,
        user_agent: str | None,
        ip_address: str | None,
        mfa_verified: bool,
    ) -> UserSession:
        self.started.append(mfa_verified)
        response.set_cookie("cg_session", "opaque-session-value", httponly=True)
        return UserSession.model_construct(
            id=PydanticObjectId(),
            user_id=user.id,
            token_hash="digest",
            csrf_hash="digest",
            label=user_agent or "",
            ip_address=ip_address,
            expires_at=utc_now(),
        )

    async def resolve_request_user(self, _request: object) -> None:
        return None


def _sign_in_app(user: User, password: str) -> tuple[Any, _FakeUserService, _FakeSessionService]:
    app = create_app(Settings(environment="test", database_enabled=False))
    users = _FakeUserService(user, password)
    sessions = _FakeSessionService()
    app.dependency_overrides[get_user_service] = lambda: users
    app.dependency_overrides[get_session_service] = lambda: sessions
    app.dependency_overrides[require_viewer] = lambda: user
    return app, users, sessions


def _client(app: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL)


async def test_sign_in_without_a_second_factor_starts_a_session() -> None:
    user = _user()
    app, users, sessions = _sign_in_app(user, "a-long-enough-password")

    async with _client(app) as client:
        response = await client.post(
            "/api/v1/auth/login",
            data={"username": "operator@example.com", "password": "a-long-enough-password"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["mfa_required"] is False
    assert body["access_token"]
    assert body["user"]["email"] == "operator@example.com"
    assert "cg_session" in response.headers.get("set-cookie", "")
    assert sessions.started == [False]
    assert users.logins == 1
    assert "password_hash" not in response.text


async def test_sign_in_with_a_wrong_password_is_rejected() -> None:
    user = _user()
    app, _users, sessions = _sign_in_app(user, "a-long-enough-password")

    async with _client(app) as client:
        wrong = await client.post(
            "/api/v1/auth/login",
            data={"username": "operator@example.com", "password": "not-the-password"},
        )
        unknown = await client.post(
            "/api/v1/auth/login",
            data={"username": "nobody@example.com", "password": "not-the-password"},
        )

    assert wrong.status_code == 401
    assert unknown.status_code == 401
    assert wrong.json()["detail"] == unknown.json()["detail"]
    assert sessions.started == []


async def test_enrolled_account_must_answer_a_challenge_before_a_session_starts() -> None:
    user = _user()
    app, _users, sessions = _sign_in_app(user, "a-long-enough-password")

    async with _client(app) as client:
        enrolled = await client.post("/api/v1/account/totp/enroll")
        secret = enrolled.json()["secret"]
        confirmed = await client.post(
            "/api/v1/account/totp/confirm",
            json={"code": pyotp.TOTP(secret).now()},
        )
        challenged = await client.post(
            "/api/v1/auth/login",
            data={"username": "operator@example.com", "password": "a-long-enough-password"},
        )
        completed = await client.post(
            "/api/v1/auth/login/mfa",
            json={
                "challenge_token": challenged.json()["challenge_token"],
                "code": pyotp.TOTP(secret).now(),
            },
        )

    assert challenged.status_code == 200
    assert challenged.json()["mfa_required"] is True
    assert challenged.json()["methods"] == ["totp", "recovery_code"]
    assert "access_token" not in challenged.json()
    assert "set-cookie" not in challenged.headers
    assert sessions.started == [True]
    assert completed.status_code == 200
    assert completed.json()["access_token"]
    assert confirmed.json()["recovery_codes"]


async def test_recovery_code_completes_a_sign_in_exactly_once() -> None:
    user = _user()
    app, _users, sessions = _sign_in_app(user, "a-long-enough-password")

    async with _client(app) as client:
        enrolled = await client.post("/api/v1/account/totp/enroll")
        secret = enrolled.json()["secret"]
        confirmed = await client.post(
            "/api/v1/account/totp/confirm",
            json={"code": pyotp.TOTP(secret).now()},
        )
        recovery_code = confirmed.json()["recovery_codes"][0]
        challenged = await client.post(
            "/api/v1/auth/login",
            data={"username": "operator@example.com", "password": "a-long-enough-password"},
        )
        challenge_token = challenged.json()["challenge_token"]
        first = await client.post(
            "/api/v1/auth/login/mfa",
            json={"challenge_token": challenge_token, "code": recovery_code},
        )
        second = await client.post(
            "/api/v1/auth/login/mfa",
            json={"challenge_token": challenge_token, "code": recovery_code},
        )

    assert first.status_code == 200
    assert second.status_code == 401
    assert sessions.started == [True]
    assert user.totp is not None
    assert len(user.totp.recovery_code_hashes) == RECOVERY_CODE_COUNT - 1


async def test_mfa_login_rejects_a_forged_challenge_token() -> None:
    user = _user()
    app, _users, sessions = _sign_in_app(user, "a-long-enough-password")

    async with _client(app) as client:
        response = await client.post(
            "/api/v1/auth/login/mfa",
            json={"challenge_token": "not.a.real.token", "code": "123456"},
        )

    assert response.status_code == 401
    assert sessions.started == []
