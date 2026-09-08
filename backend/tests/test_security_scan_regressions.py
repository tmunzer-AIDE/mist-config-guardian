"""Regressions for the security-scan findings fixed in this change.

Each test names the attack it refuses, so a later refactor that reopens one
fails here rather than in a scan.
"""

from datetime import UTC, datetime
from typing import Any

import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.user import User, UserRole, UserStatus, write_user_fields
from mist_config_guardian_backend.schemas.auth import BootstrapAdminRequest
from mist_config_guardian_backend.services.throttling import (
    MemoryThrottleStore,
    ThrottledError,
    ThrottleService,
)
from mist_config_guardian_backend.services.users import BootstrapClosedError, UserService

NOW = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)


def _settings(**overrides: object) -> Settings:
    return Settings(environment="test", database_enabled=False, **overrides)  # type: ignore[arg-type]


# ------------------------------------------------- a known bootstrap credential


async def test_bootstrap_is_closed_until_a_token_is_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    """A default that works is a credential published in the repository.

    The first caller to reach a fresh deployment and send it would become the
    global administrator, so there must be no correct answer until an operator
    chooses one.
    """
    settings = _settings()
    assert settings.bootstrap_admin_token.get_secret_value() == ""

    async def _count() -> int:
        return 0

    monkeypatch.setattr(User, "count", _count)
    request = BootstrapAdminRequest(
        email="attacker@example.com",
        display_name="Attacker",
        password="a-long-enough-password",
        bootstrap_token="development-only-bootstrap-token",
    )

    with pytest.raises(BootstrapClosedError, match="disabled until"):
        await UserService(settings).bootstrap_administrator(request)


# ------------------------------------------------------ concurrent authentication


async def test_a_limit_bounds_attempts_admitted_not_failures_recorded() -> None:
    """Concurrent requests must not all pass one below-limit reading.

    Reading the count, checking the password, then recording a failure lets
    every simultaneous attempt observe the same value and proceed.
    """
    service = ThrottleService(_settings(sign_in_failures_per_account=2), MemoryThrottleStore())
    scope = service.account("victim@example.com")

    # Three arrive together; each reserves before any credential work happens.
    await service.reserve(scope)
    await service.reserve(scope)
    with pytest.raises(ThrottledError):
        await service.reserve(scope)


# ---------------------------------------------------------- user security state


class _RecordingCollection:
    def __init__(self) -> None:
        self.updates: list[dict[str, Any]] = []

    async def update_one(self, _criteria: dict[str, Any], update: dict[str, Any]) -> Any:
        self.updates.append(update)
        return type("Result", (), {"modified_count": 1, "matched_count": 1})()


async def test_a_self_service_write_names_only_its_own_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    """A whole-document save carries the role and status the request loaded.

    A profile update that read the account before an administrator demoted it
    would put the old role back when it finished.
    """
    collection = _RecordingCollection()
    monkeypatch.setattr(User, "get_pymongo_collection", lambda: collection)
    user = User.model_construct(
        id=PydanticObjectId(),
        email="operator@example.com",
        display_name="Operator",
        password_hash="unused",
        role=UserRole.ADMINISTRATOR,
        is_active=True,
        status=UserStatus.ACTIVE,
        created_at=NOW,
        updated_at=NOW,
    )

    await write_user_fields(user, display_name="Renamed")

    [update] = collection.updates
    written = set(update["$set"])
    assert written == {"display_name", "updated_at"}
    # The fields an administrator owns are not in the write at all.
    assert not written & {"role", "is_active", "status"}
    assert user.display_name == "Renamed"
