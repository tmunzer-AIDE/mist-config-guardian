"""Regressions for the security-scan findings fixed in this change.

Each test names the attack it refuses, so a later refactor that reopens one
fails here rather than in a scan.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.user import (
    TotpEnrollment,
    User,
    UserRole,
    UserStatus,
    consume_user_recovery_code,
    write_user_fields,
)
from mist_config_guardian_backend.schemas.auth import BootstrapAdminRequest
from mist_config_guardian_backend.security.totp import hash_recovery_code
from mist_config_guardian_backend.services.throttling import (
    MemoryThrottleStore,
    Scope,
    ThrottledError,
    ThrottleService,
)
from mist_config_guardian_backend.services.users import (
    BootstrapClosedError,
    UserService,
    hash_opaque_token,
)

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


class _ReloadableCollection:
    """A collection double that answers what a later read would find."""

    def __init__(self, user: User) -> None:
        self._document: dict[str, Any] = user.model_dump(mode="python")

    async def update_one(self, _criteria: dict[str, Any], update: dict[str, Any]) -> Any:
        self._document.update(update["$set"])
        return type("Result", (), {"modified_count": 1, "matched_count": 1})()

    def reload(self) -> dict[str, Any]:
        return dict(self._document)


def _user(*, role: UserRole) -> User:
    return User.model_construct(
        id=PydanticObjectId(),
        email="operator@example.com",
        display_name="Operator",
        password_hash="unused",
        role=role,
        is_active=True,
        status=UserStatus.ACTIVE,
        created_at=NOW,
        updated_at=NOW,
    )


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


async def test_a_refused_attempt_does_not_spend_the_scopes_it_never_used() -> None:
    """An address that has run out of budget must not go on spending accounts'.

    Sign-in reserves the account first and the address second. When the address
    refuses, the account had already been charged, so an unauthenticated
    stranger could lock a victim out one refused request at a time without ever
    reaching a password check.
    """
    service = ThrottleService(
        _settings(sign_in_failures_per_account=5, sign_in_failures_per_address=2),
        MemoryThrottleStore(),
    )
    account = service.account("victim@example.com")
    address = Scope("address:203.0.113.7", 2)

    # The attacker spends their own address budget first.
    await service.reserve(account, address)
    await service.reserve(account, address)

    # From here every request is refused by the address scope.
    for _ in range(10):
        with pytest.raises(ThrottledError):
            await service.reserve(account, address)

    # The victim's own budget is untouched by refusals they had no part in, so
    # they can still sign in.
    for _ in range(3):
        await service.reserve(account)
    with pytest.raises(ThrottledError):
        await service.reserve(account)


async def test_renaming_a_user_cannot_put_back_a_role_it_read_on_the_way_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A patch that never mentioned the role must not write one.

    Naming both fields every time meant a rename carried whatever role the
    request had loaded. One started before a demotion and finishing after it
    handed the account its administrator role back.
    """
    collection = _RecordingCollection()
    monkeypatch.setattr(User, "get_pymongo_collection", lambda: collection)
    user = _user(role=UserRole.ADMINISTRATOR)

    async def _require(_user_id: PydanticObjectId) -> User:
        return user

    service = UserService(_settings())
    monkeypatch.setattr(service, "_require_user", _require)

    await service.update_user(user.id, actor=_user(role=UserRole.ADMINISTRATOR), display_name="Renamed")

    [update] = collection.updates
    written = set(update["$set"])
    assert written == {"display_name", "updated_at"}
    assert "role" not in written


async def test_accepting_an_invitation_persists_everything_it_changed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The chosen name and the password's age were set in memory and never written.

    The response showed both, and the next read from the database put the
    invitation's placeholder name back and left the account looking as though
    its password had never been set.
    """
    token = "an-invitation-token"
    stored = _user(role=UserRole.OPERATOR)
    stored.display_name = "Invited"
    stored.status = UserStatus.INVITED
    stored.is_active = False
    stored.invitation_token_hash = hash_opaque_token(token)
    stored.invitation_expires_at = utc_now() + timedelta(days=1)
    stored.password_changed_at = None

    collection = _ReloadableCollection(stored)
    monkeypatch.setattr(User, "get_pymongo_collection", lambda: collection)

    async def _find_one(_criteria: dict[str, Any]) -> User:
        return stored

    monkeypatch.setattr(User, "find_one", _find_one)

    accepted = await UserService(_settings()).accept_invitation(
        token=token,
        password="a-long-enough-password",
        display_name="Sara Kaur",
    )

    assert accepted.display_name == "Sara Kaur"
    # What the next request reads is what matters, not what this one returned.
    reloaded = collection.reload()
    assert reloaded["display_name"] == "Sara Kaur"
    assert reloaded["password_changed_at"] is not None
    assert reloaded["status"] is UserStatus.ACTIVE


# ------------------------------------------------------------- recovery codes


def _enrolled(hashes: list[str]) -> User:
    user = _user(role=UserRole.OPERATOR)
    user.totp = TotpEnrollment(
        encrypted_secret="v1:not-read-here",
        confirmed_at=NOW,
        recovery_code_hashes=list(hashes),
    )
    return user


async def test_a_recovery_code_is_spent_once_however_many_requests_present_it(
    user_writes: Any,
) -> None:
    """Two requests redeeming the same code must not both succeed.

    Replacing the whole enrollment from a copy of it meant each removed its own
    code from the same starting list, and the second write put the first one
    back: a single-use code good twice.
    """
    spent = hash_recovery_code("ABCD-EFGH")
    stored = _enrolled([spent, hash_recovery_code("ZZZZ-YYYY")])
    user_writes.track(stored)
    # Each request loads its own copy of the account, as two workers would.
    first = stored.model_copy(deep=True)
    second = stored.model_copy(deep=True)

    assert await consume_user_recovery_code(first, spent) is True
    assert await consume_user_recovery_code(second, spent) is False
    assert stored.totp is not None
    assert spent not in stored.totp.recovery_code_hashes


async def test_spending_a_recovery_code_cannot_undo_a_disable_it_raced(
    user_writes: Any,
) -> None:
    """The write that spends a code must not carry an enrollment back with it.

    Someone turning the second factor off, while a recovery code was in flight,
    had it turned back on by the losing request — along with the codes they had
    just retired.
    """
    spent = hash_recovery_code("ABCD-EFGH")
    stored = _enrolled([spent])
    user_writes.track(stored)
    in_flight = stored.model_copy(deep=True)

    # The owner turns the authenticator off while the code is in flight.
    await write_user_fields(stored, totp=None)

    assert await consume_user_recovery_code(in_flight, spent) is False
    assert stored.totp is None
