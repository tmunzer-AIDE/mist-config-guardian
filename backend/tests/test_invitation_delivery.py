"""The delivery rule: the credential is returned unless acceptance was observed."""

import re
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.api.dependencies import (
    get_application_configuration_service,
    get_current_user,
)
from mist_config_guardian_backend.api.routes.users import get_mail_sender
from mist_config_guardian_backend.config import Settings, get_settings
from mist_config_guardian_backend.integrations.smtp import SendOutcome
from mist_config_guardian_backend.main import create_app
from mist_config_guardian_backend.models.user import User, UserRole, UserStatus
from mist_config_guardian_backend.security.credentials import CredentialDecryptionError

BASE_URL = "http://test"


class FakeSender:
    """A MailSender returning a fixed outcome."""

    def __init__(self, outcome: SendOutcome) -> None:
        self.outcome = outcome
        self.calls: list[dict[str, str]] = []

    async def send(self, *, to: str, subject: str, text: str, html: str) -> SendOutcome:
        self.calls.append({"to": to, "subject": subject, "text": text, "html": html})
        return self.outcome


# --------------------------------------------------------------- settings & users
def _settings(**overrides: object) -> Settings:
    """Settings with a single, resolvable CORS origin so activation links build."""
    defaults: dict[str, object] = {
        "environment": "test",
        "database_enabled": False,
        "secret_key": "unit-test-signing-key-that-is-long-enough",
        "cors_origins": "https://guardian.example.com",
    }
    defaults.update(overrides)
    return Settings(**defaults)  # type: ignore[arg-type]


def _production_settings(**overrides: object) -> Settings:
    defaults: dict[str, object] = {
        "environment": "production",
        "database_enabled": False,
        "secret_key": "a-production-signing-key-that-is-long-enough",
        "credential_encryption_key": "a-production-encryption-key",
        "bootstrap_admin_token": "a-production-bootstrap-token",
        "cors_origins": "https://guardian.example.com",
    }
    defaults.update(overrides)
    return Settings(**defaults)  # type: ignore[arg-type]


def _administrator() -> User:
    return User.model_construct(
        id=PydanticObjectId(),
        email="admin@example.com",
        display_name="Admin",
        password_hash="unused",
        role=UserRole.ADMINISTRATOR,
        is_active=True,
        status=UserStatus.ACTIVE,
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


@pytest.fixture
def fake_users(monkeypatch: pytest.MonkeyPatch) -> _FakeUsers:
    """Replace the user collection with an in-memory list.

    Mirrors the double in ``test_users_api.py``: this suite needs its own
    copy because pytest does not share non-conftest fixtures across modules.
    """
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


# ------------------------------------------------------------------- clients
@pytest.fixture
def _apps() -> list[Any]:
    """Every app a test's client fixtures built, so `use_sender` can reach it."""
    return []


@pytest.fixture
async def admin_client(fake_users: _FakeUsers, _apps: list[Any]):
    settings = _settings()
    app = create_app(settings)
    administrator = _administrator()
    fake_users.records.append(administrator)
    app.dependency_overrides[get_current_user] = lambda: administrator
    app.dependency_overrides[get_settings] = lambda: settings
    _apps.append(app)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL) as client:
        yield client


@pytest.fixture
async def admin_client_production(fake_users: _FakeUsers, _apps: list[Any]):
    settings = _production_settings()
    app = create_app(settings)
    administrator = _administrator()
    fake_users.records.append(administrator)
    app.dependency_overrides[get_current_user] = lambda: administrator
    app.dependency_overrides[get_settings] = lambda: settings
    _apps.append(app)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL) as client:
        yield client


@pytest.fixture
def use_sender(_apps: list[Any]):
    """Override `get_mail_sender` on every app this test built a client for."""

    def _use(sender: object) -> object:
        async def _dependency() -> object:
            return sender

        for app in _apps:
            app.dependency_overrides[get_mail_sender] = _dependency
        _use.last = sender
        return sender

    _use.last = None
    return _use


# --------------------------------------------------------------- delivery rule
async def test_an_accepted_send_withholds_the_credential(admin_client, use_sender) -> None:
    use_sender(FakeSender(SendOutcome("sent")))

    body = (
        await admin_client.post(
            "/api/v1/users",
            json={"email": "a@example.com", "display_name": "A", "role": "viewer"},
        )
    ).json()

    assert body["delivery"] == "sent"
    assert body["invitation_token"] is None
    assert body["invitation_url"] is None
    assert body["delivery_detail"] is None


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        (SendOutcome("uncertain", "No confirmation was received"), "uncertain"),
        (SendOutcome("failed", "The server refused the message"), "failed"),
    ],
)
async def test_anything_short_of_acceptance_returns_the_credential(
    admin_client, use_sender, outcome: SendOutcome, expected: str
) -> None:
    use_sender(FakeSender(outcome))

    body = (
        await admin_client.post(
            "/api/v1/users",
            json={"email": "b@example.com", "display_name": "B", "role": "viewer"},
        )
    ).json()

    assert body["delivery"] == expected
    assert body["invitation_token"]
    assert body["delivery_detail"] == outcome.detail
    assert body["invitation_url"].endswith(f"#token={body['invitation_token']}")


async def test_disabled_email_returns_the_credential(admin_client, use_sender) -> None:
    use_sender(None)

    body = (
        await admin_client.post(
            "/api/v1/users",
            json={"email": "c@example.com", "display_name": "C", "role": "viewer"},
        )
    ).json()

    assert body["delivery"] == "not_configured"
    assert body["invitation_token"]


async def test_a_sender_that_raises_is_uncertain_not_failed(admin_client, use_sender) -> None:
    """An unexpected escape cannot rule out that the body was written."""

    class Exploding:
        async def send(self, **_kwargs: str) -> SendOutcome:
            msg = "bug"
            raise RuntimeError(msg)

    use_sender(Exploding())

    body = (
        await admin_client.post(
            "/api/v1/users",
            json={"email": "d@example.com", "display_name": "D", "role": "viewer"},
        )
    ).json()

    assert body["delivery"] == "uncertain"
    assert body["invitation_token"]


async def test_production_is_no_longer_a_special_case(admin_client_production, use_sender) -> None:
    use_sender(None)

    body = (
        await admin_client_production.post(
            "/api/v1/users",
            json={"email": "e@example.com", "display_name": "E", "role": "viewer"},
        )
    ).json()

    assert body["invitation_token"], "production withheld the credential with no email to carry it"


async def test_a_second_resend_inside_the_window_is_refused(admin_client, use_sender) -> None:
    use_sender(FakeSender(SendOutcome("sent")))
    user_id = (
        await admin_client.post(
            "/api/v1/users",
            json={"email": "f@example.com", "display_name": "F", "role": "viewer"},
        )
    ).json()["user"]["id"]

    first = await admin_client.post(f"/api/v1/users/{user_id}/resend-invitation")
    second = await admin_client.post(f"/api/v1/users/{user_id}/resend-invitation")

    assert first.status_code == 200
    assert second.status_code == 429


async def test_a_refused_resend_does_not_rotate_the_token(admin_client, use_sender) -> None:
    """Rotating then refusing would invalidate a token still in flight.

    The token the refused attempt was supposed to leave intact is the one the
    *preceding successful* rotation issued, not the original invite token -
    that one is already dead once the first resend succeeds. Pinning the
    live token and asserting it still activates is what actually verifies the
    ordering; accepting either 200 or 400 on the stale, pre-rotation token (as
    an earlier version of this test did) passes whether or not the refusal
    rotates again, because that token is invalid either way.
    """
    use_sender(None)
    created = (
        await admin_client.post(
            "/api/v1/users",
            json={"email": "g@example.com", "display_name": "G", "role": "viewer"},
        )
    ).json()
    user_id = created["user"]["id"]

    first_resend = await admin_client.post(f"/api/v1/users/{user_id}/resend-invitation")
    live_token = first_resend.json()["invitation_token"]
    assert live_token

    refused = await admin_client.post(f"/api/v1/users/{user_id}/resend-invitation")
    assert refused.status_code == 429

    accepted = await admin_client.post(
        "/api/v1/users/accept-invitation",
        json={"token": live_token, "password": "a-long-enough-password"},
    )
    assert accepted.status_code == 200, "the refused resend must not have rotated the still-live token"


async def test_the_token_is_not_logged(admin_client, use_sender, caplog: pytest.LogCaptureFixture) -> None:
    use_sender(FakeSender(SendOutcome("sent")))

    body = (
        await admin_client.post(
            "/api/v1/users",
            json={"email": "h@example.com", "display_name": "H", "role": "viewer"},
        )
    ).json()
    assert body["delivery"] == "sent"

    sender_calls = use_sender.last.calls
    token_in_message = sender_calls[0]["text"]
    assert "token=" in token_in_message
    assert not any("token=" in record.getMessage() for record in caplog.records)


# ------------------------------------------------------- additional coverage
async def test_invitation_url_is_null_but_the_token_survives_an_unresolved_base_url(
    fake_users: _FakeUsers,
) -> None:
    """A token with no link is worth more than nothing to a stranded administrator."""
    # Two CORS origins mean the application cannot elect a canonical one, so
    # `Settings.public_base_url` is `None` and no activation link can be built.
    settings = _settings(cors_origins="https://one.example.com,https://two.example.com")
    app = create_app(settings)
    administrator = _administrator()
    fake_users.records.append(administrator)
    app.dependency_overrides[get_current_user] = lambda: administrator
    app.dependency_overrides[get_settings] = lambda: settings

    async def _no_sender() -> None:
        return None

    app.dependency_overrides[get_mail_sender] = _no_sender

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL) as client:
        response = await client.post(
            "/api/v1/users",
            json={"email": "i@example.com", "display_name": "I", "role": "viewer"},
        )

    body = response.json()
    assert body["delivery"] == "not_configured"
    assert body["invitation_token"]
    assert body["invitation_url"] is None


async def test_delivery_detail_is_capped_and_carries_no_part_of_the_token(admin_client, use_sender) -> None:
    """The detail is a mail server's own text, shown to an administrator."""
    overlong = "x" * 5000
    use_sender(FakeSender(SendOutcome("failed", overlong)))

    body = (
        await admin_client.post(
            "/api/v1/users",
            json={"email": "j@example.com", "display_name": "J", "role": "viewer"},
        )
    ).json()

    assert body["invitation_token"]
    assert len(body["delivery_detail"]) <= 200
    assert body["invitation_token"] not in body["delivery_detail"]


async def test_delivery_detail_never_echoes_a_token_a_server_reflected_back(admin_client, use_sender) -> None:
    """A server can quote the rejected message body, which itself carries the token."""

    class EchoingSender:
        """A hostile or buggy server that quotes back what it refused.

        The activation link in ``text`` carries this invitation's own token,
        so whatever the transport reports must not simply pass it through.
        """

        async def send(self, *, text: str, **_kwargs: str) -> SendOutcome:
            # Straddle the activation link deliberately: the fixed expiry
            # sentence that follows it in the real message is much longer than
            # a naive trailing slice, so a window anchored on "#token=" is
            # what actually forces the token into the echoed snippet.
            token_at = text.index("#token=")
            return SendOutcome("failed", f"Rejected body: ...{text[max(token_at - 20, 0) :][:120]}")

    use_sender(EchoingSender())

    body = (
        await admin_client.post(
            "/api/v1/users",
            json={"email": "l@example.com", "display_name": "L", "role": "viewer"},
        )
    ).json()

    assert body["invitation_token"]
    assert body["invitation_token"] not in body["delivery_detail"]


async def test_the_per_sender_hourly_limit_refuses_the_21st_invitation(admin_client, use_sender) -> None:
    """The invite endpoint has no target user to key on; only the sender scope bounds it."""
    use_sender(FakeSender(SendOutcome("sent")))

    responses = [
        await admin_client.post(
            "/api/v1/users",
            json={"email": f"sender-limit-{index}@example.com", "display_name": "Bulk", "role": "viewer"},
        )
        for index in range(20)
    ]
    assert all(response.status_code == 201 for response in responses)

    twenty_first = await admin_client.post(
        "/api/v1/users",
        json={"email": "sender-limit-20@example.com", "display_name": "Bulk", "role": "viewer"},
    )

    assert twenty_first.status_code == 429


@pytest.mark.parametrize(
    ("build_sender", "expected_delivery"),
    [
        (lambda: None, "not_configured"),
        (lambda: FakeSender(SendOutcome("failed", "The server refused the message")), "failed"),
    ],
    ids=["not_configured", "failed"],
)
async def test_unsuccessful_outcomes_still_consume_the_sender_limit(
    fake_users: _FakeUsers, build_sender, expected_delivery: str
) -> None:
    """The connection attempt and token rotation happen regardless of outcome.

    If an unsuccessful send were refunded, a misconfigured server could be
    retried without limit - exactly when retrying is most futile. Both a
    disabled transport and one that actively refuses the message must still
    spend the reservation: the throttle is reserved before either outcome is
    known, and only a refused *reservation* (429) is ever given back.
    """
    settings = _settings(invitation_sends_per_sender_per_hour=1)
    app = create_app(settings)
    administrator = _administrator()
    fake_users.records.append(administrator)
    app.dependency_overrides[get_current_user] = lambda: administrator
    app.dependency_overrides[get_settings] = lambda: settings

    sender = build_sender()

    async def _sender() -> object:
        return sender

    app.dependency_overrides[get_mail_sender] = _sender

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL) as client:
        first = await client.post(
            "/api/v1/users",
            json={"email": "m@example.com", "display_name": "M", "role": "viewer"},
        )
        second = await client.post(
            "/api/v1/users",
            json={"email": "n@example.com", "display_name": "N", "role": "viewer"},
        )

    assert first.status_code == 201
    assert first.json()["delivery"] == expected_delivery
    assert second.status_code == 429, f"the limit of 1 must already be spent after one {expected_delivery} outcome"


async def test_a_corrupt_stored_credential_still_creates_the_account(fake_users: _FakeUsers) -> None:
    """A broken mail configuration degrades delivery; it must not block onboarding.

    `get_mail_sender` runs as a dependency, outside `_deliver`'s protection,
    so a vault that raises while decrypting a corrupted or wrong-key SMTP
    password must not turn every invite into a 500 before the account is
    even created.
    """

    class _RaisingConfigurationService:
        async def smtp_credentials(self) -> None:
            msg = "Encrypted credential could not be authenticated"
            raise CredentialDecryptionError(msg)

    settings = _settings()
    app = create_app(settings)
    administrator = _administrator()
    fake_users.records.append(administrator)
    app.dependency_overrides[get_current_user] = lambda: administrator
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_application_configuration_service] = _RaisingConfigurationService

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL) as client:
        response = await client.post(
            "/api/v1/users",
            json={"email": "p@example.com", "display_name": "P", "role": "viewer"},
        )

    assert response.status_code == 201
    body = response.json()
    assert body["delivery"] == "not_configured"
    assert body["invitation_token"]


async def test_an_unresolved_base_url_is_distinguished_from_an_smtp_problem(
    fake_users: _FakeUsers,
) -> None:
    """Email configured but no link buildable must not read as a silent SMTP failure."""
    # Two CORS origins: `Settings.public_base_url` cannot elect a canonical one.
    settings = _settings(cors_origins="https://one.example.com,https://two.example.com")
    app = create_app(settings)
    administrator = _administrator()
    fake_users.records.append(administrator)
    app.dependency_overrides[get_current_user] = lambda: administrator
    app.dependency_overrides[get_settings] = lambda: settings

    sender = FakeSender(SendOutcome("sent"))

    async def _sender() -> object:
        return sender

    app.dependency_overrides[get_mail_sender] = _sender

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL) as client:
        response = await client.post(
            "/api/v1/users",
            json={"email": "q@example.com", "display_name": "Q", "role": "viewer"},
        )

    body = response.json()
    assert body["delivery"] == "not_configured"
    assert body["invitation_token"]
    assert body["invitation_url"] is None
    assert body["delivery_detail"]
    assert "PUBLIC_BASE_URL" in body["delivery_detail"]
    assert not sender.calls, "no send should be attempted with no link to put in the message"
