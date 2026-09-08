"""Failure throttling on sign-in and password confirmation."""

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from beanie import PydanticObjectId
from fastapi import Response

from mist_config_guardian_backend.api.dependencies import get_session_service, get_user_service
from mist_config_guardian_backend.config import Settings, get_settings
from mist_config_guardian_backend.main import create_app
from mist_config_guardian_backend.models.user import User, UserRole
from mist_config_guardian_backend.services.passkeys import get_passkey_service
from mist_config_guardian_backend.services.throttling import (
    MemoryThrottleStore,
    Scope,
    ThrottledError,
    ThrottleService,
)


def _settings(**overrides: object) -> Settings:
    return Settings(environment="test", database_enabled=False, **overrides)  # type: ignore[arg-type]


class _Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 9, 8, 9, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


# ---------------------------------------------------------------- service


async def test_a_scope_is_refused_once_it_reaches_its_limit() -> None:
    service = ThrottleService(_settings(sign_in_failures_per_account=3), MemoryThrottleStore())
    scope = service.account("Someone@Example.com")

    for _ in range(3):
        await service.guard(scope)
        await service.failed(scope)

    with pytest.raises(ThrottledError) as caught:
        await service.guard(scope)
    assert caught.value.retry_after > 0


async def test_the_account_scope_is_case_insensitive_and_trimmed() -> None:
    service = ThrottleService(_settings(), MemoryThrottleStore())

    assert service.account(" Someone@Example.com ") == service.account("someone@example.com")


async def test_a_success_forgets_the_failures_before_it() -> None:
    service = ThrottleService(_settings(sign_in_failures_per_account=2), MemoryThrottleStore())
    scope = service.account("someone@example.com")
    await service.failed(scope)
    await service.failed(scope)

    await service.succeeded(scope)

    await service.guard(scope)


async def test_failures_expire_with_their_window() -> None:
    clock = _Clock()
    service = ThrottleService(
        _settings(sign_in_failures_per_account=1, sign_in_throttle_window_minutes=15),
        MemoryThrottleStore(clock),
    )
    scope = service.account("someone@example.com")
    await service.failed(scope)
    with pytest.raises(ThrottledError):
        await service.guard(scope)

    clock.now += timedelta(minutes=16)

    await service.guard(scope)


async def test_each_scope_counts_on_its_own() -> None:
    service = ThrottleService(_settings(sign_in_failures_per_account=1), MemoryThrottleStore())
    await service.failed(Scope("account:a", 1))

    await service.guard(Scope("account:b", 1))
    with pytest.raises(ThrottledError):
        await service.guard(Scope("account:a", 1))


# -------------------------------------------------------------------- api


class _FakeUserService:
    def __init__(self, user: User, password: str) -> None:
        self._user = user
        self._password = password

    async def authenticate(self, email: str, password: str) -> User | None:
        if email == self._user.email and password == self._password:
            return self._user
        return None

    async def get_by_id(self, user_id: PydanticObjectId) -> User | None:
        return self._user if user_id == self._user.id else None

    async def record_login(self, user: User) -> User:
        return user


class _FakePasskeys:
    async def count_for_user(self, _user_id: PydanticObjectId | None) -> int:
        return 0


class _FakeSessionService:
    def __init__(self) -> None:
        self.started = 0

    async def start(self, user: User, *, response: Response, **_kwargs: object) -> None:
        del user, response
        self.started += 1


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


def _app(limit: int) -> tuple[object, _FakeSessionService]:
    settings = _settings(sign_in_failures_per_account=limit)
    app = create_app(settings)
    sessions = _FakeSessionService()
    # The throttle reads settings through the dependency, not from the app.
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_user_service] = lambda: _FakeUserService(_user(), "correct horse battery")
    app.dependency_overrides[get_session_service] = lambda: sessions
    app.dependency_overrides[get_passkey_service] = _FakePasskeys
    return app, sessions


def _client(app: object) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")  # type: ignore[arg-type]


async def test_sign_in_is_refused_after_the_account_limit_and_says_when_to_retry() -> None:
    app, sessions = _app(limit=3)

    async with _client(app) as client:
        for _ in range(3):
            wrong = await client.post(
                "/api/v1/auth/login",
                data={"username": "operator@example.com", "password": "not it"},
            )
            assert wrong.status_code == 401
        # The correct password is refused too: the account is closed for the window.
        blocked = await client.post(
            "/api/v1/auth/login",
            data={"username": "operator@example.com", "password": "correct horse battery"},
        )

    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) > 0
    assert sessions.started == 0


async def test_a_successful_sign_in_clears_the_account_s_failures() -> None:
    app, sessions = _app(limit=3)

    async with _client(app) as client:
        for _ in range(2):
            await client.post("/api/v1/auth/login", data={"username": "operator@example.com", "password": "no"})
        signed_in = await client.post(
            "/api/v1/auth/login",
            data={"username": "operator@example.com", "password": "correct horse battery"},
        )
        for _ in range(2):
            await client.post("/api/v1/auth/login", data={"username": "operator@example.com", "password": "no"})
        again = await client.post(
            "/api/v1/auth/login",
            data={"username": "operator@example.com", "password": "correct horse battery"},
        )

    assert signed_in.status_code == 200
    assert again.status_code == 200
    assert sessions.started == 2


async def test_an_unknown_account_is_throttled_indistinguishably() -> None:
    """Refusing only known accounts would reveal which addresses exist."""
    app, _sessions = _app(limit=2)

    async with _client(app) as client:
        for _ in range(2):
            await client.post("/api/v1/auth/login", data={"username": "nobody@example.com", "password": "no"})
        blocked = await client.post("/api/v1/auth/login", data={"username": "nobody@example.com", "password": "no"})

    assert blocked.status_code == 429
