"""User administration API and last-administrator rule tests."""

import re
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.api.dependencies import get_current_user, get_session_service
from mist_config_guardian_backend.api.routes.users import get_mail_sender
from mist_config_guardian_backend.config import Settings, get_settings
from mist_config_guardian_backend.main import create_app
from mist_config_guardian_backend.models.user import User, UserRole, UserStatus
from mist_config_guardian_backend.security.auth import hash_password, verify_password
from mist_config_guardian_backend.services.passkeys import get_passkey_service
from mist_config_guardian_backend.services.users import (
    InvitationError,
    LastAdministratorError,
    UserAlreadyExistsError,
    UserService,
    hash_opaque_token,
)

BASE_URL = "http://test"


def _settings() -> Settings:
    return Settings(
        environment="test",
        database_enabled=False,
        secret_key="unit-test-signing-key-that-is-long-enough",
    )


def _user(
    *,
    email: str,
    role: UserRole = UserRole.VIEWER,
    is_active: bool = True,
    status: UserStatus = UserStatus.ACTIVE,
) -> User:
    return User.model_construct(
        id=PydanticObjectId(),
        email=email,
        display_name=email.split("@", maxsplit=1)[0].title(),
        password_hash="unused",
        role=role,
        is_active=is_active,
        status=status,
        invitation_token_hash=None,
        invitation_expires_at=None,
        totp=None,
        last_login_at=None,
    )


def _matches(user: User, criteria: dict[str, Any]) -> bool:
    for key, expected in criteria.items():
        if key == "$or":
            if not any(_matches(user, clause) for clause in expected):
                return False
            continue
        actual = user.id if key == "_id" else getattr(user, key, None)
        if isinstance(expected, dict):
            if "$ne" in expected and actual == expected["$ne"]:
                return False
            pattern = expected.get("$regex")
            flags = re.IGNORECASE if "i" in expected.get("$options", "") else 0
            if pattern is not None and not re.search(pattern, str(actual), flags):
                return False
            continue
        if actual != expected:
            return False
    return True


class _FakeQuery:
    def __init__(self, items: list[User]) -> None:
        self._items = items

    def sort(self, *_args: object) -> "_FakeQuery":
        return self

    def skip(self, count: int) -> "_FakeQuery":
        return _FakeQuery(self._items[count:])

    def limit(self, count: int) -> "_FakeQuery":
        return _FakeQuery(self._items[:count])

    async def to_list(self) -> list[User]:
        return list(self._items)

    async def count(self) -> int:
        return len(self._items)


class _FakeUsers:
    def __init__(self) -> None:
        self.records: list[User] = []


class _FakeSessions:
    def __init__(self) -> None:
        self.revoked: list[PydanticObjectId] = []

    async def resolve_request_user(self, _request: object) -> None:
        return None

    async def revoke_all(self, user_id: PydanticObjectId, **_kwargs: object) -> int:
        self.revoked.append(user_id)
        return 1


@pytest.fixture
def users(monkeypatch: pytest.MonkeyPatch) -> _FakeUsers:
    """Replace the user collection with an in-memory list."""
    fake = _FakeUsers()

    async def _insert(self: User, *_args: object, **_kwargs: object) -> User:
        self.id = PydanticObjectId()
        fake.records.append(self)
        return self

    async def _save(self: User, *_args: object, **_kwargs: object) -> User:
        return self

    async def _find_one(criteria: dict[str, Any], **_kwargs: object) -> User | None:
        return next((item for item in fake.records if _matches(item, criteria)), None)

    def _find(criteria: dict[str, Any], **_kwargs: object) -> _FakeQuery:
        return _FakeQuery([item for item in fake.records if _matches(item, criteria)])

    async def _get(user_id: PydanticObjectId) -> User | None:
        return next((item for item in fake.records if item.id == user_id), None)

    async def _count() -> int:
        return len(fake.records)

    class _Collection:
        """Accepts the field-scoped writes `write_user_fields` issues.

        Those name only the fields they change and update the in-memory user
        themselves, so the double only has to acknowledge them.
        """

        async def update_one(self, _criteria: dict[str, Any], _update: dict[str, Any]) -> Any:
            return SimpleNamespace(modified_count=1, matched_count=1)

    def _collection(*_args: object, **_kwargs: object) -> _Collection:
        return _Collection()

    monkeypatch.setattr(User, "get_pymongo_collection", _collection)
    monkeypatch.setattr(User, "insert", _insert)
    monkeypatch.setattr(User, "save", _save)
    monkeypatch.setattr(User, "find_one", _find_one)
    monkeypatch.setattr(User, "find", _find)
    monkeypatch.setattr(User, "get", _get)
    monkeypatch.setattr(User, "count", _count)
    return fake


def _client(app: object) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL)


# ------------------------------------------------------------ authorization
async def test_listing_users_requires_authentication() -> None:
    app = create_app(_settings())

    async with _client(app) as client:
        response = await client.get("/api/v1/users")

    assert response.status_code == 401


async def test_viewer_cannot_reach_user_administration(users: _FakeUsers) -> None:
    assert users is not None
    app = create_app(_settings())
    viewer = _user(email="viewer@example.com")
    app.dependency_overrides[get_current_user] = lambda: viewer

    async with _client(app) as client:
        listed = await client.get("/api/v1/users")
        invited = await client.post(
            "/api/v1/users",
            json={"email": "new@example.com", "display_name": "New"},
        )

    assert listed.status_code == 403
    assert invited.status_code == 403


# ------------------------------------------------------------------ invites
async def test_invite_returns_a_one_time_token_and_no_digests(users: _FakeUsers) -> None:
    app = create_app(_settings())
    administrator = _user(email="admin@example.com", role=UserRole.ADMINISTRATOR)
    users.records.append(administrator)
    app.dependency_overrides[get_current_user] = lambda: administrator
    app.dependency_overrides[get_mail_sender] = lambda: None

    async with _client(app) as client:
        response = await client.post(
            "/api/v1/users",
            json={"email": "New@Example.com", "display_name": "New Operator", "role": "operator"},
        )

    assert response.status_code == 201
    body = response.json()
    assert body["user"]["email"] == "new@example.com"
    assert body["user"]["status"] == "invited"
    assert body["user"]["is_active"] is False
    assert body["invitation_token"]
    assert "invitation_token_hash" not in response.text
    assert "password_hash" not in response.text

    invited = next(record for record in users.records if record.email == "new@example.com")
    assert invited.invitation_token_hash == hash_opaque_token(body["invitation_token"])


async def test_invite_rejects_a_duplicate_email(users: _FakeUsers) -> None:
    app = create_app(_settings())
    administrator = _user(email="admin@example.com", role=UserRole.ADMINISTRATOR)
    users.records.append(administrator)
    app.dependency_overrides[get_current_user] = lambda: administrator
    app.dependency_overrides[get_mail_sender] = lambda: None

    async with _client(app) as client:
        response = await client.post(
            "/api/v1/users",
            json={"email": "admin@example.com", "display_name": "Copy"},
        )

    assert response.status_code == 409


async def test_invitation_token_is_no_longer_withheld_in_production(users: _FakeUsers) -> None:
    """The `environment` special case is gone: production has no mail transport here either.

    This used to assert the opposite - that production withheld the token -
    which encoded the bug this deployment shipped with: an invited account
    whose token was generated, hashed, stored, and then discarded unread,
    because no mail was ever sent and nothing else could carry the credential.
    """
    settings = Settings(
        environment="production",
        database_enabled=False,
        secret_key="a-production-signing-key-that-is-long-enough",
        credential_encryption_key="a-production-encryption-key",
        bootstrap_admin_token="a-production-bootstrap-token",
    )
    app = create_app(settings)
    administrator = _user(email="admin@example.com", role=UserRole.ADMINISTRATOR)
    users.records.append(administrator)
    app.dependency_overrides[get_current_user] = lambda: administrator
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_mail_sender] = lambda: None

    async with _client(app) as client:
        response = await client.post(
            "/api/v1/users",
            json={"email": "new@example.com", "display_name": "New"},
        )

    assert response.status_code == 201
    body = response.json()
    assert body["delivery"] == "not_configured"
    assert body["invitation_token"] is not None


async def test_accept_invitation_activates_the_account(users: _FakeUsers) -> None:
    app = create_app(_settings())
    service = UserService(_settings())
    administrator = _user(email="admin@example.com", role=UserRole.ADMINISTRATOR)
    users.records.append(administrator)
    _invited, token = await service.invite(
        email="new@example.com",
        display_name="New",
        role=UserRole.OPERATOR,
        invited_by=administrator.id,
    )

    async with _client(app) as client:
        response = await client.post(
            "/api/v1/users/accept-invitation",
            json={"token": token, "password": "a-long-enough-password"},
        )

    assert response.status_code == 200
    assert response.json()["status"] == "active"
    accepted = next(record for record in users.records if record.email == "new@example.com")
    assert accepted.is_active is True
    assert accepted.invitation_token_hash is None
    assert verify_password("a-long-enough-password", accepted.password_hash)


async def test_accept_invitation_rejects_an_unknown_token(users: _FakeUsers) -> None:
    assert users is not None
    app = create_app(_settings())

    async with _client(app) as client:
        response = await client.post(
            "/api/v1/users/accept-invitation",
            json={"token": "not-a-real-token", "password": "a-long-enough-password"},
        )

    assert response.status_code == 400


async def test_invitation_cannot_be_accepted_twice(users: _FakeUsers) -> None:
    service = UserService(_settings())
    _invited, token = await service.invite(
        email="new@example.com",
        display_name="New",
        role=UserRole.VIEWER,
        invited_by=None,
    )
    assert users.records

    await service.accept_invitation(token=token, password="a-long-enough-password")

    with pytest.raises(InvitationError):
        await service.accept_invitation(token=token, password="another-long-password")


# ------------------------------------------------------ last-administrator
async def test_administrator_cannot_demote_themselves(users: _FakeUsers) -> None:
    service = UserService(_settings())
    administrator = _user(email="admin@example.com", role=UserRole.ADMINISTRATOR)
    second = _user(email="second@example.com", role=UserRole.ADMINISTRATOR)
    users.records.extend([administrator, second])
    assert administrator.id is not None

    with pytest.raises(LastAdministratorError):
        await service.update_user(administrator.id, actor=administrator, role=UserRole.VIEWER)


async def test_last_administrator_cannot_be_demoted(users: _FakeUsers) -> None:
    service = UserService(_settings())
    actor = _user(email="actor@example.com", role=UserRole.ADMINISTRATOR)
    only = _user(email="only@example.com", role=UserRole.ADMINISTRATOR)
    only.is_active = True
    actor.is_active = False
    users.records.extend([actor, only])
    assert only.id is not None

    with pytest.raises(LastAdministratorError):
        await service.update_user(only.id, actor=actor, role=UserRole.OPERATOR)


async def test_last_administrator_cannot_be_deactivated(users: _FakeUsers) -> None:
    service = UserService(_settings())
    actor = _user(email="actor@example.com", role=UserRole.ADMINISTRATOR)
    actor.is_active = False
    only = _user(email="only@example.com", role=UserRole.ADMINISTRATOR)
    users.records.extend([actor, only])
    assert only.id is not None

    with pytest.raises(LastAdministratorError):
        await service.deactivate(only.id, actor=actor)


async def test_role_change_is_allowed_while_another_administrator_remains(users: _FakeUsers) -> None:
    service = UserService(_settings())
    actor = _user(email="actor@example.com", role=UserRole.ADMINISTRATOR)
    other = _user(email="other@example.com", role=UserRole.ADMINISTRATOR)
    users.records.extend([actor, other])
    assert other.id is not None

    updated = await service.update_user(other.id, actor=actor, role=UserRole.OPERATOR)

    assert updated.role is UserRole.OPERATOR


async def test_demoting_the_last_administrator_returns_conflict(users: _FakeUsers) -> None:
    app = create_app(_settings())
    administrator = _user(email="admin@example.com", role=UserRole.ADMINISTRATOR)
    users.records.append(administrator)
    app.dependency_overrides[get_current_user] = lambda: administrator

    async with _client(app) as client:
        response = await client.patch(
            f"/api/v1/users/{administrator.id}",
            json={"role": "viewer"},
        )

    assert response.status_code == 409
    assert "administrator" in response.json()["detail"].lower()


# ------------------------------------------------------------ lifecycle
class _FakePasskeys:
    def __init__(self) -> None:
        self.revoked: list[PydanticObjectId] = []

    async def revoke_all(self, user_id: PydanticObjectId) -> int:
        self.revoked.append(user_id)
        return 1


async def test_deactivating_a_user_revokes_their_sessions_and_passkeys(users: _FakeUsers) -> None:
    """A passkey outlives a password; containment has to take it too."""
    app = create_app(_settings())
    sessions = _FakeSessions()
    passkeys = _FakePasskeys()
    administrator = _user(email="admin@example.com", role=UserRole.ADMINISTRATOR)
    target = _user(email="operator@example.com", role=UserRole.OPERATOR)
    users.records.extend([administrator, target])
    app.dependency_overrides[get_current_user] = lambda: administrator
    app.dependency_overrides[get_session_service] = lambda: sessions
    app.dependency_overrides[get_passkey_service] = lambda: passkeys

    async with _client(app) as client:
        deactivated = await client.post(f"/api/v1/users/{target.id}/deactivate")
        reactivated = await client.post(f"/api/v1/users/{target.id}/activate")

    assert deactivated.status_code == 200
    assert deactivated.json()["status"] == "deactivated"
    assert sessions.revoked == [target.id]
    assert passkeys.revoked == [target.id]
    assert reactivated.json()["status"] == "active"
    assert reactivated.json()["is_active"] is True


async def test_listing_users_filters_by_role_status_and_search(users: _FakeUsers) -> None:
    app = create_app(_settings())
    administrator = _user(email="admin@example.com", role=UserRole.ADMINISTRATOR)
    operator = _user(email="operator@example.com", role=UserRole.OPERATOR)
    invited = _user(
        email="pending@example.com",
        is_active=False,
        status=UserStatus.INVITED,
    )
    users.records.extend([administrator, operator, invited])
    app.dependency_overrides[get_current_user] = lambda: administrator

    async with _client(app) as client:
        by_role = await client.get("/api/v1/users", params={"role": "operator"})
        by_status = await client.get("/api/v1/users", params={"status": "invited"})
        by_term = await client.get("/api/v1/users", params={"q": "ADMIN"})

    assert [item["email"] for item in by_role.json()["items"]] == ["operator@example.com"]
    assert [item["email"] for item in by_status.json()["items"]] == ["pending@example.com"]
    assert [item["email"] for item in by_term.json()["items"]] == ["admin@example.com"]
    assert by_role.json()["total"] == 1


async def test_resending_an_invitation_replaces_the_token(users: _FakeUsers) -> None:
    app = create_app(_settings())
    service = UserService(_settings())
    administrator = _user(email="admin@example.com", role=UserRole.ADMINISTRATOR)
    users.records.append(administrator)
    invited, first_token = await service.invite(
        email="new@example.com",
        display_name="New",
        role=UserRole.VIEWER,
        invited_by=administrator.id,
    )
    app.dependency_overrides[get_current_user] = lambda: administrator
    app.dependency_overrides[get_mail_sender] = lambda: None

    async with _client(app) as client:
        response = await client.post(f"/api/v1/users/{invited.id}/resend-invitation")

    assert response.status_code == 200
    second_token = response.json()["invitation_token"]
    assert second_token != first_token
    assert invited.invitation_token_hash == hash_opaque_token(second_token)

    with pytest.raises(InvitationError):
        await service.accept_invitation(token=first_token, password="a-long-enough-password")


async def test_inviting_an_existing_email_raises(users: _FakeUsers) -> None:
    service = UserService(_settings())
    users.records.append(_user(email="taken@example.com"))

    with pytest.raises(UserAlreadyExistsError):
        await service.invite(
            email="Taken@example.com",
            display_name="Copy",
            role=UserRole.VIEWER,
            invited_by=None,
        )


async def test_authentication_does_not_reveal_unknown_accounts(users: _FakeUsers) -> None:
    service = UserService(_settings())
    known = _user(email="known@example.com")
    known.password_hash = hash_password("a-long-enough-password")
    users.records.append(known)

    assert await service.authenticate("known@example.com", "wrong-password") is None
    assert await service.authenticate("missing@example.com", "wrong-password") is None
    assert await service.authenticate("KNOWN@example.com", "a-long-enough-password") is known


# --------------------------------------------------------------- bootstrap gate
def _bootstrappable_settings() -> Settings:
    return Settings(
        environment="test",
        database_enabled=False,
        secret_key="unit-test-signing-key-that-is-long-enough",
        bootstrap_admin_token="a-configured-bootstrap-token",
    )


async def test_bootstrap_is_offered_while_no_account_exists(users: _FakeUsers) -> None:
    assert users.records == []
    settings = _bootstrappable_settings()
    app = create_app(settings)
    app.dependency_overrides[get_settings] = lambda: settings

    async with _client(app) as client:
        response = await client.get("/api/v1/auth/bootstrap")

    assert response.status_code == 200
    assert response.json() == {"available": True}


async def test_bootstrap_closes_once_an_account_exists(users: _FakeUsers) -> None:
    users.records.append(_user(email="admin@example.com", role=UserRole.ADMINISTRATOR))
    settings = _bootstrappable_settings()
    app = create_app(settings)
    app.dependency_overrides[get_settings] = lambda: settings

    async with _client(app) as client:
        response = await client.get("/api/v1/auth/bootstrap")

    assert response.status_code == 200
    assert response.json() == {"available": False}


async def test_bootstrap_is_closed_when_no_token_is_configured(users: _FakeUsers) -> None:
    """An empty deployment with no token cannot be bootstrapped, so it may not offer to be."""
    assert users.records == []
    app = create_app(_settings())

    async with _client(app) as client:
        response = await client.get("/api/v1/auth/bootstrap")

    assert response.status_code == 200
    assert response.json() == {"available": False}


async def test_the_bootstrap_gate_needs_no_session(users: _FakeUsers) -> None:
    """The page that reads it is the sign-in page, which has no session yet."""
    assert users.records == []
    settings = _bootstrappable_settings()
    app = create_app(settings)
    app.dependency_overrides[get_settings] = lambda: settings

    async with _client(app) as client:
        response = await client.get("/api/v1/auth/bootstrap")

    assert response.status_code != 401
