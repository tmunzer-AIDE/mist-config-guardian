"""Passkey registration and passwordless authentication tests."""

from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from beanie import PydanticObjectId
from fastapi import Response

from mist_config_guardian_backend.api.dependencies import get_session_service, get_user_service
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.main import create_app
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.session import UserSession
from mist_config_guardian_backend.models.user import User, UserRole, WebAuthnCredential
from mist_config_guardian_backend.security import webauthn as webauthn_security
from mist_config_guardian_backend.security.webauthn import (
    WebAuthnChallengeStore,
    WebAuthnError,
    encode_credential_id,
)
from mist_config_guardian_backend.services.mfa import ChallengeTokenError
from mist_config_guardian_backend.services.passkeys import (
    PasskeyError,
    PasskeyNotFoundError,
    PasskeyService,
    get_passkey_service,
)

_CREDENTIAL_ID = b"raw-credential-identifier"
_PUBLIC_KEY = b"cose-public-key-bytes"


def _settings() -> Settings:
    return Settings(
        environment="test",
        secret_key="unit-test-signing-key-that-is-long-enough",
        webauthn_rp_id="localhost",
        webauthn_origin="http://localhost:4200",
    )


def _user(email: str = "operator@example.com") -> User:
    return User.model_construct(
        id=PydanticObjectId(),
        email=email,
        display_name="Operator",
        password_hash="unused",
        role=UserRole.OPERATOR,
        is_active=True,
    )


class _FakeQuery:
    def __init__(self, items: list[WebAuthnCredential]) -> None:
        self._items = items

    def sort(self, *_args: object) -> "_FakeQuery":
        return self

    async def to_list(self) -> list[WebAuthnCredential]:
        return list(self._items)

    async def count(self) -> int:
        return len(self._items)


class _FakeCollection:
    def __init__(self) -> None:
        self.records: list[WebAuthnCredential] = []
        self.users: dict[PydanticObjectId, User] = {}

    def matching(self, criteria: dict[str, Any]) -> list[WebAuthnCredential]:
        found = []
        for record in self.records:
            values = {key: (record.id if key == "_id" else getattr(record, key, None)) for key in criteria}
            if values == criteria:
                found.append(record)
        return found


@pytest.fixture
def collection(monkeypatch: pytest.MonkeyPatch) -> _FakeCollection:
    """Replace the passkey collection and user lookups with in-memory data."""
    fake = _FakeCollection()

    async def _insert(self: WebAuthnCredential, *_args: object, **_kwargs: object) -> WebAuthnCredential:
        self.id = PydanticObjectId()
        fake.records.append(self)
        return self

    async def _save(self: WebAuthnCredential, *_args: object, **_kwargs: object) -> WebAuthnCredential:
        return self

    async def _delete(self: WebAuthnCredential, *_args: object, **_kwargs: object) -> None:
        fake.records.remove(self)

    async def _find_one(criteria: dict[str, Any], **_kwargs: object) -> WebAuthnCredential | None:
        found = fake.matching(criteria)
        return found[0] if found else None

    def _find(criteria: dict[str, Any], **_kwargs: object) -> _FakeQuery:
        return _FakeQuery(fake.matching(criteria))

    async def _get_user(user_id: PydanticObjectId) -> User | None:
        return fake.users.get(user_id)

    def _collection(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(WebAuthnCredential, "get_pymongo_collection", _collection)
    monkeypatch.setattr(WebAuthnCredential, "insert", _insert)
    monkeypatch.setattr(WebAuthnCredential, "save", _save)
    monkeypatch.setattr(WebAuthnCredential, "delete", _delete)
    monkeypatch.setattr(WebAuthnCredential, "find_one", _find_one)
    monkeypatch.setattr(WebAuthnCredential, "find", _find)
    monkeypatch.setattr(User, "get", _get_user)
    return fake


@pytest.fixture
def verification(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Replace the WebAuthn cryptographic verification with recorded results."""
    seen: dict[str, Any] = {}

    def _verify_registration(*_args: Any, **kwargs: Any) -> SimpleNamespace:
        seen["registration_challenge"] = kwargs["expected_challenge"]
        return SimpleNamespace(
            credential_id=_CREDENTIAL_ID,
            credential_public_key=_PUBLIC_KEY,
            sign_count=0,
            credential_backed_up=True,
        )

    def _verify_authentication(*_args: Any, **kwargs: Any) -> SimpleNamespace:
        seen["authentication_challenge"] = kwargs["expected_challenge"]
        seen["public_key"] = kwargs["public_key"]
        # A test that wants an assertion without user verification sets this first.
        return SimpleNamespace(new_sign_count=7, user_verified=seen.get("user_verified", True))

    monkeypatch.setattr(webauthn_security, "verify_registration", _verify_registration)
    monkeypatch.setattr(webauthn_security, "verify_authentication", _verify_authentication)
    return seen


def _service() -> PasskeyService:
    return PasskeyService(_settings(), WebAuthnChallengeStore())


def _registration_credential() -> dict[str, Any]:
    return {
        "id": encode_credential_id(_CREDENTIAL_ID),
        "type": "public-key",
        "authenticatorAttachment": "cross-platform",
        "response": {"transports": ["usb", "nfc"]},
    }


async def test_registration_stores_the_verified_credential(
    collection: _FakeCollection,
    verification: dict[str, Any],
) -> None:
    service = _service()
    user = _user()

    options, challenge_token = await service.begin_registration(user)
    record = await service.complete_registration(
        user,
        challenge_token=challenge_token,
        credential=_registration_credential(),
        name="  YubiKey  ",
    )

    assert options["rp"]["id"] == "localhost"
    assert record.credential_id == encode_credential_id(_CREDENTIAL_ID)
    assert record.name == "YubiKey"
    assert record.device_kind == "security_key"
    assert record.transports == ["usb", "nfc"]
    assert record.backed_up is True
    assert collection.records == [record]
    assert verification["registration_challenge"] is not None


async def test_registration_challenge_cannot_be_replayed(
    collection: _FakeCollection,
    verification: dict[str, Any],
) -> None:
    assert collection is not None
    assert verification is not None
    service = _service()
    user = _user()
    _options, challenge_token = await service.begin_registration(user)
    await service.complete_registration(
        user,
        challenge_token=challenge_token,
        credential=_registration_credential(),
    )

    with pytest.raises(WebAuthnError):
        await service.complete_registration(
            user,
            challenge_token=challenge_token,
            credential=_registration_credential(),
        )


async def test_registration_challenge_is_bound_to_the_issuing_user(
    collection: _FakeCollection,
    verification: dict[str, Any],
) -> None:
    assert collection is not None
    assert verification is not None
    service = _service()
    _options, challenge_token = await service.begin_registration(_user())

    with pytest.raises(WebAuthnError):
        await service.complete_registration(
            _user("other@example.com"),
            challenge_token=challenge_token,
            credential=_registration_credential(),
        )


async def test_registration_rejects_a_forged_challenge_token(collection: _FakeCollection) -> None:
    assert collection is not None
    service = _service()

    with pytest.raises(ChallengeTokenError):
        await service.complete_registration(
            _user(),
            challenge_token="not.a.real.token",
            credential=_registration_credential(),
        )


async def test_authentication_returns_the_owning_user(
    collection: _FakeCollection,
    verification: dict[str, Any],
) -> None:
    service = _service()
    user = _user()
    collection.users[user.id] = user
    _options, registration_token = await service.begin_registration(user)
    record = await service.complete_registration(
        user,
        challenge_token=registration_token,
        credential=_registration_credential(),
    )

    options, challenge_token = await service.begin_authentication()
    outcome = await service.complete_authentication(
        challenge_token=challenge_token,
        credential={"id": record.credential_id},
    )

    assert options["rpId"] == "localhost"
    assert outcome.user is user
    assert outcome.user_verified is True
    assert outcome.credential.sign_count == 7
    assert outcome.credential.last_used_at is not None
    assert verification["public_key"] == record.public_key


async def test_authentication_reports_when_the_authenticator_did_not_verify_the_user(
    collection: _FakeCollection,
    verification: dict[str, Any],
) -> None:
    """Possession of the device and presence of the person are different facts."""
    service = _service()
    user = _user()
    collection.users[user.id] = user
    _options, registration_token = await service.begin_registration(user)
    record = await service.complete_registration(
        user,
        challenge_token=registration_token,
        credential=_registration_credential(),
    )
    verification["user_verified"] = False

    _options, challenge_token = await service.begin_authentication()
    outcome = await service.complete_authentication(
        challenge_token=challenge_token,
        credential={"id": record.credential_id},
    )

    assert outcome.user_verified is False


async def test_authentication_rejects_an_unknown_credential(
    collection: _FakeCollection,
    verification: dict[str, Any],
) -> None:
    assert collection is not None
    assert verification is not None
    service = _service()
    _options, challenge_token = await service.begin_authentication()

    with pytest.raises(PasskeyError):
        await service.complete_authentication(
            challenge_token=challenge_token,
            credential={"id": encode_credential_id(b"never-registered")},
        )


async def test_authentication_rejects_a_deactivated_account(
    collection: _FakeCollection,
    verification: dict[str, Any],
) -> None:
    assert verification is not None
    service = _service()
    user = _user()
    user.is_active = False
    collection.users[user.id] = user
    _options, registration_token = await service.begin_registration(user)
    record = await service.complete_registration(
        user,
        challenge_token=registration_token,
        credential=_registration_credential(),
    )

    _options, challenge_token = await service.begin_authentication()
    with pytest.raises(PasskeyError):
        await service.complete_authentication(
            challenge_token=challenge_token,
            credential={"id": record.credential_id},
        )


async def test_passkeys_can_only_be_managed_by_their_owner(
    collection: _FakeCollection,
    verification: dict[str, Any],
) -> None:
    assert verification is not None
    service = _service()
    user = _user()
    _options, registration_token = await service.begin_registration(user)
    record = await service.complete_registration(
        user,
        challenge_token=registration_token,
        credential=_registration_credential(),
    )
    assert record.id is not None

    renamed = await service.rename(user, record.id, "Laptop")
    assert renamed.name == "Laptop"

    with pytest.raises(PasskeyNotFoundError):
        await service.rename(_user("other@example.com"), record.id, "Stolen")
    with pytest.raises(PasskeyNotFoundError):
        await service.delete(_user("other@example.com"), record.id)

    await service.delete(user, record.id)
    assert collection.records == []
    assert await service.count_for_user(user.id) == 0
    assert await service.count_for_user(None) == 0


# --------------------------------------------------------------- sign-in API
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


class _FakeUserService:
    async def record_login(self, user: User) -> User:
        user.last_login_at = utc_now()
        return user


async def test_passkey_sign_in_starts_a_step_up_verified_session(
    collection: _FakeCollection,
    verification: dict[str, Any],
) -> None:
    assert verification is not None
    service = _service()
    user = _user()
    collection.users[user.id] = user
    _options, registration_token = await service.begin_registration(user)
    record = await service.complete_registration(
        user,
        challenge_token=registration_token,
        credential=_registration_credential(),
    )

    app = create_app(Settings(environment="test", database_enabled=False))
    sessions = _FakeSessionService()
    app.dependency_overrides[get_passkey_service] = lambda: service
    app.dependency_overrides[get_session_service] = lambda: sessions
    app.dependency_overrides[get_user_service] = _FakeUserService

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        options = await client.post("/api/v1/auth/passkey/options")
        verified = await client.post(
            "/api/v1/auth/passkey/verify",
            json={
                "challenge_token": options.json()["challenge_token"],
                "credential": {"id": record.credential_id},
            },
        )
        replayed = await client.post(
            "/api/v1/auth/passkey/verify",
            json={
                "challenge_token": options.json()["challenge_token"],
                "credential": {"id": record.credential_id},
            },
        )

    assert options.status_code == 200
    assert options.json()["options"]["rpId"] == "localhost"
    assert verified.status_code == 200
    assert verified.json()["user"]["email"] == user.email
    assert "cg_session" in verified.headers.get("set-cookie", "")
    assert sessions.started == [True]
    assert replayed.status_code == 401


async def _registered(service: PasskeyService, collection: _FakeCollection, user: User) -> WebAuthnCredential:
    collection.users[user.id] = user
    _options, registration_token = await service.begin_registration(user)
    return await service.complete_registration(
        user,
        challenge_token=registration_token,
        credential=_registration_credential(),
    )


def _sign_in_app(service: PasskeyService) -> tuple[Any, _FakeSessionService]:
    app = create_app(Settings(environment="test", database_enabled=False))
    sessions = _FakeSessionService()
    app.dependency_overrides[get_passkey_service] = lambda: service
    app.dependency_overrides[get_session_service] = lambda: sessions
    app.dependency_overrides[get_user_service] = _FakeUserService
    return app, sessions


async def _verify(app: Any, credential_id: str) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        options = await client.post("/api/v1/auth/passkey/options")
        return await client.post(
            "/api/v1/auth/passkey/verify",
            json={"challenge_token": options.json()["challenge_token"], "credential": {"id": credential_id}},
        )


async def test_an_unverified_assertion_signs_in_without_the_step_up(
    collection: _FakeCollection,
    verification: dict[str, Any],
) -> None:
    """Possession alone is not a second factor, so the session gets no MFA stamp."""
    service = _service()
    record = await _registered(service, collection, _user())
    verification["user_verified"] = False
    app, sessions = _sign_in_app(service)

    verified = await _verify(app, record.credential_id)

    assert verified.status_code == 200
    assert verified.json()["mfa_required"] is False
    assert sessions.started == [False]


async def test_an_unverified_assertion_for_an_enrolled_account_is_challenged(
    collection: _FakeCollection,
    verification: dict[str, Any],
) -> None:
    """An authenticator enrollment must not be bypassed by a device alone."""
    service = _service()
    user = _user()
    user.totp = SimpleNamespace(encrypted_secret="x", recovery_code_hashes=[])
    record = await _registered(service, collection, user)
    verification["user_verified"] = False
    app, sessions = _sign_in_app(service)

    verified = await _verify(app, record.credential_id)

    assert verified.status_code == 200
    assert verified.json()["mfa_required"] is True
    assert verified.json()["methods"] == ["totp", "recovery_code"]
    assert "set-cookie" not in verified.headers
    assert sessions.started == []
