"""Cookie session issue, CSRF, and revocation tests."""

from http.cookies import SimpleCookie
from typing import Any

import httpx
import pytest
from beanie import PydanticObjectId
from beanie.odm.fields import ExpressionField
from beanie.odm.utils.pydantic import get_model_fields
from fastapi import Request, Response

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.main import create_app
from mist_config_guardian_backend.models.session import UserSession
from mist_config_guardian_backend.models.user import User, UserRole, WebAuthnCredential
from mist_config_guardian_backend.services.sessions import CsrfError, SessionService


def _bind_query_fields(model: type) -> None:
    """Attach the query expression fields Beanie normally installs at init."""
    for name, field in get_model_fields(model).items():
        setattr(model, name, ExpressionField(field.alias or name))


_bind_query_fields(UserSession)


def _settings() -> Settings:
    return Settings(environment="test", secret_key="unit-test-signing-key-that-is-long-enough")


def _user() -> User:
    return User.model_construct(
        id=PydanticObjectId(),
        email="operator@example.com",
        display_name="Operator",
        password_hash="unused",
        role=UserRole.OPERATOR,
        is_active=True,
    )


def _criteria(args: tuple[Any, ...]) -> dict[str, Any]:
    """Flatten Beanie query expressions into a plain field/value mapping.

    The keys Beanie produces are ``ExpressionField`` instances whose ``__eq__``
    builds a query rather than comparing, so they must be reduced to plain
    strings before they are used for attribute lookup.
    """
    merged: dict[str, Any] = {}
    for argument in args:
        merged.update({str(key): value for key, value in dict(argument).items()})
    return merged


def _matches(session: UserSession, criteria: dict[str, Any]) -> bool:
    for key, expected in criteria.items():
        actual = session.id if key == "_id" else getattr(session, key, None)
        if actual != expected:
            return False
    return True


class _FakeQuery:
    def __init__(self, items: list[Any]) -> None:
        self._items = items

    def sort(self, *_args: object) -> "_FakeQuery":
        return self

    async def to_list(self) -> list[Any]:
        return list(self._items)

    async def count(self) -> int:
        return len(self._items)


class _FakeStore:
    def __init__(self, user: User) -> None:
        self.user = user
        self.sessions: list[UserSession] = []


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch) -> _FakeStore:
    """Replace the session collection with an in-memory list."""
    fake = _FakeStore(_user())

    async def _insert(self: UserSession, *_args: object, **_kwargs: object) -> UserSession:
        self.id = PydanticObjectId()
        fake.sessions.append(self)
        return self

    async def _save(self: UserSession, *_args: object, **_kwargs: object) -> UserSession:
        return self

    async def _find_one(*args: Any, **_kwargs: object) -> UserSession | None:
        criteria = _criteria(args)
        return next((item for item in fake.sessions if _matches(item, criteria)), None)

    def _find(*args: Any, **_kwargs: object) -> _FakeQuery:
        criteria = _criteria(args)
        return _FakeQuery([item for item in fake.sessions if _matches(item, criteria)])

    async def _get(user_id: PydanticObjectId) -> User | None:
        return fake.user if fake.user.id == user_id else None

    def _collection(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(UserSession, "get_pymongo_collection", _collection)
    monkeypatch.setattr(UserSession, "insert", _insert)
    monkeypatch.setattr(UserSession, "save", _save)
    monkeypatch.setattr(UserSession, "find_one", _find_one)
    monkeypatch.setattr(UserSession, "find", _find)
    monkeypatch.setattr(User, "get", _get)
    return fake


def _issued_cookies(response: Response) -> dict[str, str]:
    jar: SimpleCookie = SimpleCookie()
    for header in response.headers.getlist("set-cookie"):
        jar.load(header)
    return {name: morsel.value for name, morsel in jar.items() if morsel.value}


def _request(method: str, *, cookies: dict[str, str] | None = None, csrf: str | None = None) -> Request:
    headers: list[tuple[bytes, bytes]] = [(b"user-agent", b"Mozilla/5.0 (Macintosh) Chrome/1.0")]
    if cookies:
        jar = "; ".join(f"{name}={value}" for name, value in cookies.items())
        headers.append((b"cookie", jar.encode()))
    if csrf is not None:
        headers.append((b"x-csrf-token", csrf.encode()))
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": "/",
            "raw_path": b"/",
            "root_path": "",
            "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 5000),
            "server": ("testserver", 80),
            "state": {},
        },
    )


async def _start(service: SessionService, user: User) -> tuple[UserSession, dict[str, str]]:
    response = Response()
    session = await service.start(
        user,
        response=response,
        user_agent="Mozilla/5.0 (Macintosh) Chrome/1.0",
        ip_address="127.0.0.1",
        mfa_verified=False,
    )
    return session, _issued_cookies(response)


async def test_session_cookies_carry_only_opaque_values(store: _FakeStore) -> None:
    settings = _settings()
    service = SessionService(settings)

    session, cookies = await _start(service, store.user)

    assert settings.session_cookie_name in cookies
    assert settings.csrf_cookie_name in cookies
    assert session.token_hash != cookies[settings.session_cookie_name]
    assert session.csrf_hash != cookies[settings.csrf_cookie_name]
    assert session.label == "Chrome on macOS"


async def test_session_cookie_resolves_the_user(store: _FakeStore) -> None:
    service = SessionService(_settings())
    _session, cookies = await _start(service, store.user)

    request = _request("GET", cookies=cookies)
    resolved = await service.resolve_request_user(request)

    assert resolved is not None
    assert resolved.id == store.user.id
    assert request.scope["state"]["session"].id == store.sessions[0].id


async def test_unknown_session_cookie_is_ignored(store: _FakeStore) -> None:
    service = SessionService(_settings())
    await _start(service, store.user)
    settings = _settings()

    request = _request("GET", cookies={settings.session_cookie_name: "not-a-real-token"})

    assert await service.resolve_request_user(request) is None


async def test_unsafe_method_without_csrf_header_is_rejected(store: _FakeStore) -> None:
    service = SessionService(_settings())
    _session, cookies = await _start(service, store.user)

    with pytest.raises(CsrfError):
        await service.resolve_request_user(_request("POST", cookies=cookies))


async def test_unsafe_method_with_mismatched_csrf_header_is_rejected(store: _FakeStore) -> None:
    service = SessionService(_settings())
    _session, cookies = await _start(service, store.user)

    with pytest.raises(CsrfError):
        await service.resolve_request_user(_request("POST", cookies=cookies, csrf="a-different-value"))


async def test_unsafe_method_with_matching_csrf_header_is_allowed(store: _FakeStore) -> None:
    settings = _settings()
    service = SessionService(settings)
    _session, cookies = await _start(service, store.user)

    resolved = await service.resolve_request_user(
        _request("POST", cookies=cookies, csrf=cookies[settings.csrf_cookie_name]),
    )

    assert resolved is not None


async def test_revoked_session_stops_authenticating(store: _FakeStore) -> None:
    service = SessionService(_settings())
    session, cookies = await _start(service, store.user)
    assert store.user.id is not None
    assert session.id is not None

    assert await service.revoke(store.user.id, session.id) is True
    assert await service.resolve_request_user(_request("GET", cookies=cookies)) is None
    assert await service.revoke(store.user.id, session.id) is False


async def test_revoke_all_can_keep_the_current_session(store: _FakeStore) -> None:
    service = SessionService(_settings())
    current, cookies = await _start(service, store.user)
    await _start(service, store.user)
    await _start(service, store.user)
    assert store.user.id is not None

    revoked = await service.revoke_all(store.user.id, except_session_id=current.id)

    assert revoked == 2
    assert await service.resolve_request_user(_request("GET", cookies=cookies)) is not None
    assert [session.id for session in await service.list_for_user(store.user.id)] == [current.id]


async def test_mfa_freshness_window(store: _FakeStore) -> None:
    service = SessionService(_settings())
    session, _cookies = await _start(service, store.user)

    assert service.has_fresh_mfa(session) is False
    await service.mark_mfa_verified(session)
    assert service.has_fresh_mfa(session) is True
    assert service.has_fresh_mfa(None) is False


# ------------------------------------------------------------------ endpoints
async def test_cookie_session_authenticates_and_logout_revokes_it(
    store: _FakeStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _find(_criteria: dict[str, Any], **_kwargs: object) -> _FakeQuery:
        return _FakeQuery([])

    monkeypatch.setattr(WebAuthnCredential, "find", _find)
    app = create_app(Settings(environment="test", database_enabled=False))
    service = SessionService(_settings())
    session, cookies = await _start(service, store.user)
    settings = _settings()
    csrf = cookies[settings.csrf_cookie_name]

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test", cookies=cookies) as client:
        me = await client.get("/api/v1/auth/me")
        without_csrf = await client.post("/api/v1/auth/logout")
        signed_out = await client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})
        again = await client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})

    assert me.status_code == 200
    assert me.json()["email"] == store.user.email
    assert me.json()["passkey_count"] == 0
    assert me.json()["mfa_enabled"] is False
    assert without_csrf.status_code == 403
    assert signed_out.status_code == 200
    assert session.revoked_at is not None
    assert again.status_code == 200


async def test_logout_without_a_session_is_idempotent(store: _FakeStore) -> None:
    assert store is not None
    app = create_app(Settings(environment="test", database_enabled=False))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/auth/logout")

    assert response.status_code == 200
    assert response.json() == {"signed_out": True}
