"""The SMTP settings endpoints, and the connection-test probe they expose.

The API tests run over the same in-memory ``ApplicationConfiguration``
double the unit-level ``test_smtp_settings.py`` suite uses (there is no
MongoDB in this process), following the stub described in that file's
``service`` fixture and the Task 4 report: ``_get_or_create`` and the
class-level ``find_one`` Beanie call are monkeypatched directly, and
``get_pymongo_collection`` is stubbed to a bare ``AsyncMock`` since
``update_smtp``/``test_smtp_connection`` persist through a targeted
``update_one`` rather than ``save()``.

Two things the design spec asks for that a straight port of the plan's
example tests would miss:

* the probe must send no message — proven directly against ``_probe_smtp``
  for all three security modes, not just asserted for the stored, disabled
  configuration the brief's own end-to-end test happens to exercise.
* ``_probe_smtp`` chooses its own transport (``SMTP_SSL`` / ``STARTTLS`` /
  plain), duplicating ``integrations/smtp.py``'s choice in a second place,
  and needs its own coverage that the TLS contexts it builds are actually
  verified — an unverified context is silent at runtime, so nothing else
  here would notice if ``context=verified_context()`` were dropped.
"""

import smtplib
import ssl
from collections.abc import AsyncIterator
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.api.dependencies import (
    get_application_configuration_service,
    get_current_user,
)
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.integrations.smtp import SmtpCredentials
from mist_config_guardian_backend.main import create_app
from mist_config_guardian_backend.models.application_configuration import ApplicationConfiguration
from mist_config_guardian_backend.models.user import User, UserRole
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.application_configuration import (
    ApplicationConfigurationService,
    _probe_smtp,
)
from mist_config_guardian_backend.services.deep_links import SETTINGS_TABS


def test_the_email_tab_is_deep_linkable() -> None:
    """deep_link refuses a tab it does not know, so the set must carry it."""
    assert "email" in SETTINGS_TABS


# -- SMTP settings API: administrator role guard and persisted outcome -----


def _user(role: UserRole) -> User:
    return User.model_construct(
        id=PydanticObjectId(),
        email=f"{role.value}@example.com",
        display_name=role.value.capitalize(),
        password_hash="unused",
        role=role,
        is_active=True,
    )


def _build_service(monkeypatch: pytest.MonkeyPatch) -> ApplicationConfigurationService:
    """A real service over one shared in-memory configuration document.

    ``_get_or_create`` and the class-level ``find_one`` call
    (``smtp_credentials`` and ``update_smtp`` reach the database through
    different methods, mirroring ``ai_runtime``'s existing style) are
    stubbed to the same document, so a write made through one route is
    visible to a later read in the same test — matching the "service"
    fixture in ``test_smtp_settings.py`` and the stub the Task 4 report
    describes for unit-testing ``smtp_credentials`` without Mongo.
    ``update_smtp`` and ``test_smtp_connection`` write to that document
    in place (a targeted ``update_one``, not ``save()``), so the shared
    instance still carries every write forward.
    """
    vault = CredentialVault(
        Settings(
            environment="test",
            database_enabled=False,
            credential_encryption_key="test-encryption-key",
        )
    )
    settings = Settings(
        environment="test",
        database_enabled=False,
        credential_encryption_key="test-encryption-key",
        cors_origins="https://app.example.test",
    )
    service = ApplicationConfigurationService(vault, settings)
    configuration = ApplicationConfiguration.model_construct(key="global")
    monkeypatch.setattr(service, "_get_or_create", AsyncMock(return_value=configuration))
    monkeypatch.setattr(ApplicationConfiguration, "key", "global", raising=False)
    monkeypatch.setattr(ApplicationConfiguration, "find_one", AsyncMock(return_value=configuration))
    # update_smtp and test_smtp_connection persist through a targeted $set
    # against the pymongo collection rather than configuration.save(); the
    # shared in-memory document is what these tests actually assert on.
    monkeypatch.setattr(ApplicationConfiguration, "get_pymongo_collection", AsyncMock)
    return service


async def _client(role: UserRole, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[httpx.AsyncClient]:
    service = _build_service(monkeypatch)
    app = create_app(Settings(environment="test", database_enabled=False))
    app.dependency_overrides[get_application_configuration_service] = lambda: service
    app.dependency_overrides[get_current_user] = lambda: _user(role)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        yield client


@pytest.fixture
async def admin_client(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[httpx.AsyncClient]:
    async for client in _client(UserRole.ADMINISTRATOR, monkeypatch):
        yield client


@pytest.fixture
async def operator_client(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[httpx.AsyncClient]:
    async for client in _client(UserRole.OPERATOR, monkeypatch):
        yield client


async def test_an_administrator_reads_smtp_settings(admin_client: httpx.AsyncClient) -> None:
    response = await admin_client.get("/api/v1/settings/smtp")

    assert response.status_code == 200
    assert response.json()["enabled"] is False


async def test_an_operator_cannot_read_smtp_settings(operator_client: httpx.AsyncClient) -> None:
    assert (await operator_client.get("/api/v1/settings/smtp")).status_code == 403


async def test_enabling_without_a_host_answers_422(admin_client: httpx.AsyncClient) -> None:
    response = await admin_client.put(
        "/api/v1/settings/smtp",
        json={"enabled": True, "from_address": "a@example.com"},
    )

    assert response.status_code == 422
    assert "host" in response.json()["detail"]


async def test_the_connection_test_records_its_outcome(admin_client: httpx.AsyncClient) -> None:
    response = await admin_client.post("/api/v1/settings/smtp/test")

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert "checked_at" in body
    stored = (await admin_client.get("/api/v1/settings/smtp")).json()
    assert stored["last_test_ok"] is False
    assert stored["last_test_detail"]


# -- _probe_smtp: the transport it duplicates, and the message it must not --
# --    send -----------------------------------------------------------------

_STARTTLS_CREDENTIALS = SmtpCredentials(
    host="smtp.example.test",
    port=587,
    security="starttls",
    username="bot",
    password="hunter2",
    from_address="a@example.com",
    from_name="Config Guardian",
)
_TLS_CREDENTIALS = SmtpCredentials(
    host="smtp.example.test",
    port=465,
    security="tls",
    username="bot",
    password="hunter2",
    from_address="a@example.com",
    from_name="Config Guardian",
)
_NONE_CREDENTIALS = SmtpCredentials(
    host="127.0.0.1",
    port=25,
    security="none",
    username="",
    password="",
    from_address="a@example.com",
    from_name="Config Guardian",
)


@pytest.mark.parametrize(
    ("credentials", "patched_name"),
    [
        (_TLS_CREDENTIALS, "SMTP_SSL"),
        (_STARTTLS_CREDENTIALS, "SMTP"),
        (_NONE_CREDENTIALS, "SMTP"),
    ],
    ids=["tls", "starttls", "none"],
)
def test_probe_smtp_never_sends_a_message(
    monkeypatch: pytest.MonkeyPatch,
    credentials: SmtpCredentials,
    patched_name: str,
) -> None:
    """Connecting, upgrading, and authenticating is the whole check.

    There is nobody to send a real message to; a probe "improved" into
    sending one to prove deliverability would be silently sending mail to
    whatever address is on file. This must fail loudly, for all three
    transport choices ``_probe_smtp`` can make.
    """
    client = MagicMock(spec=getattr(smtplib, patched_name))
    monkeypatch.setattr(smtplib, patched_name, MagicMock(return_value=client))

    ok, _detail = _probe_smtp(credentials)

    assert ok is True
    client.send_message.assert_not_called()
    client.sendmail.assert_not_called()


def test_probe_smtp_over_tls_uses_a_verified_context(monkeypatch: pytest.MonkeyPatch) -> None:
    client = MagicMock(spec=smtplib.SMTP_SSL)
    constructor = MagicMock(return_value=client)
    monkeypatch.setattr(smtplib, "SMTP_SSL", constructor)

    ok, detail = _probe_smtp(_TLS_CREDENTIALS)

    assert ok is True
    assert "TLS" in detail
    assert constructor.call_count == 1
    call = constructor.call_args
    assert call.args == (_TLS_CREDENTIALS.host, _TLS_CREDENTIALS.port)
    assert call.kwargs["timeout"] == 10.0
    context = call.kwargs["context"]
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True
    client.login.assert_called_once_with(_TLS_CREDENTIALS.username, _TLS_CREDENTIALS.password)
    client.quit.assert_called_once()


def test_probe_smtp_over_starttls_uses_a_verified_context(monkeypatch: pytest.MonkeyPatch) -> None:
    client = MagicMock(spec=smtplib.SMTP)
    constructor = MagicMock(return_value=client)
    monkeypatch.setattr(smtplib, "SMTP", constructor)

    ok, detail = _probe_smtp(_STARTTLS_CREDENTIALS)

    assert ok is True
    assert "TLS" in detail
    constructor.assert_called_once_with(
        _STARTTLS_CREDENTIALS.host,
        _STARTTLS_CREDENTIALS.port,
        timeout=10.0,
    )
    client.starttls.assert_called_once()
    context = client.starttls.call_args.kwargs["context"]
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True
    client.login.assert_called_once_with(_STARTTLS_CREDENTIALS.username, _STARTTLS_CREDENTIALS.password)
    client.quit.assert_called_once()


def test_probe_smtp_over_plain_connects_without_upgrading(monkeypatch: pytest.MonkeyPatch) -> None:
    client = MagicMock(spec=smtplib.SMTP)
    constructor = MagicMock(return_value=client)
    monkeypatch.setattr(smtplib, "SMTP", constructor)

    ok, detail = _probe_smtp(_NONE_CREDENTIALS)

    assert ok is True
    assert "unencrypted" in detail
    constructor.assert_called_once_with(_NONE_CREDENTIALS.host, _NONE_CREDENTIALS.port, timeout=10.0)
    client.starttls.assert_not_called()
    client.login.assert_not_called()
    client.quit.assert_called_once()


def test_probe_smtp_reports_a_connection_failure_without_raising(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(smtplib, "SMTP", MagicMock(side_effect=OSError("Connection refused")))

    ok, detail = _probe_smtp(_NONE_CREDENTIALS)

    assert ok is False
    assert "Connection refused" in detail


def test_probe_smtp_never_echoes_the_servers_login_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    """A hostile or buggy server can echo the AUTH line back in a 535 reply.

    That reply must never reach ``detail``: ``test_smtp_connection`` persists
    it verbatim to ``smtp_last_test_detail`` and returns it from both
    ``POST /smtp/test`` and every later ``GET /smtp``. This is the probe's
    side of the same hardening ``test_smtp_transport.py``'s
    ``test_a_login_failure_never_echoes_the_servers_reply`` pins down for the
    message-sending transport; both now go through the one shared
    ``connect_and_authenticate``.
    """
    credential_shaped = "cG9zdG1hc3RlcjpodW50ZXIy"  # base64("postmaster:hunter2")
    error = smtplib.SMTPAuthenticationError(535, credential_shaped.encode())
    client = MagicMock(spec=smtplib.SMTP)
    client.login.side_effect = error
    monkeypatch.setattr(smtplib, "SMTP", MagicMock(return_value=client))

    ok, detail = _probe_smtp(_STARTTLS_CREDENTIALS)

    assert ok is False
    assert credential_shaped not in detail
    assert detail == "Authentication was rejected by the server."
    client.send_message.assert_not_called()
    client.sendmail.assert_not_called()
