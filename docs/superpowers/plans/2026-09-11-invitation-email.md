# Invitation Email Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make an invited user able to activate their account — by sending the invitation over SMTP, and by handing the administrator a usable link whenever it could not be sent.

**Architecture:** SMTP settings live on the existing `ApplicationConfiguration` singleton, mirroring the Impact AI settings field for field. A transport in `integrations/smtp.py` classifies its own send outcome by protocol phase and returns it rather than raising. The invite routes map that outcome onto a `delivery` enum and return the activation credential unless acceptance was observed. A new unauthenticated Angular page accepts the invitation.

**Tech Stack:** FastAPI, Beanie/MongoDB, Pydantic v2, stdlib `smtplib` + `ssl`, pytest, Angular 20 standalone components with signals, Vitest.

**Spec:** `docs/superpowers/specs/2026-09-11-invitation-email-design.md`

## Global Constraints

- Python 3.13. Package manager is `uv`. Run backend commands from `backend/`.
- Full verification is `make check` from the repository root: `ruff format --check`, `ruff check`, `ty check src`, `pytest`, the OpenAPI contract check, and the frontend build and tests.
- **No new Python dependency.** `smtplib` and `ssl` are stdlib. Do not add `aiosmtplib`.
- Any change to a response schema requires `make openapi` from the repository root, or `make check` fails on the committed contract.
- **The invitation token is never logged.** Log records carry recipient, outcome, and SMTP response code only.
- **The activation token travels in the URL fragment**, never the query string.
- Both TLS paths must pass an explicit `ssl.create_default_context()`. Never rely on `smtplib`'s default, which is `ssl._create_stdlib_context()` with `check_hostname=False` and `verify_mode=CERT_NONE`.
- Delivery outcomes are exactly `sent`, `uncertain`, `not_configured`, `failed`. The credential is returned for every value except `sent`.
- Docstrings are required on public functions and classes; `ruff` enforces it. Match the surrounding prose style: explain *why*, not *what*.
- Every task ends green. Never commit with a failing test.

---

### Task 1: Resolve the application's public base URL

**Files:**
- Modify: `backend/src/mist_config_guardian_backend/config.py:24` (after `cors_origins`), and the validators at the end of `Settings`
- Modify: `.env.example`
- Test: `backend/tests/test_public_base_url.py` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: `Settings.public_base_url -> str | None` — the canonical origin with no trailing slash, or `None` when unresolvable. `Settings.public_base_url_override: str` bound to env `PUBLIC_BASE_URL`.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_public_base_url.py`:

```python
"""The canonical public origin the application builds activation links from."""

import pytest

from mist_config_guardian_backend.config import Settings


def _settings(**overrides: object) -> Settings:
    base: dict[str, object] = {"_env_file": None, "environment": "development", "database_enabled": False}
    base.update(overrides)
    return Settings(**base)


def test_a_single_cors_origin_is_the_public_base_url() -> None:
    assert _settings(cors_origins="https://guardian.example.com").public_base_url == "https://guardian.example.com"


def test_several_cors_origins_never_pick_a_winner() -> None:
    """CORS is an allow-list, not a declaration of a canonical address."""
    assert _settings(cors_origins="http://localhost:4200,http://localhost:8080").public_base_url is None


def test_no_cors_origin_leaves_the_base_url_unresolved() -> None:
    assert _settings(cors_origins="").public_base_url is None


def test_the_override_wins_over_the_derivation() -> None:
    settings = _settings(
        cors_origins="https://derived.example.com",
        public_base_url_override="https://explicit.example.com",
    )

    assert settings.public_base_url == "https://explicit.example.com"


def test_a_trailing_slash_is_normalised_away() -> None:
    assert _settings(public_base_url_override="https://guardian.example.com/").public_base_url == (
        "https://guardian.example.com"
    )


@pytest.mark.parametrize(
    "value",
    [
        "guardian.example.com",
        "ftp://guardian.example.com",
        "https://user:pass@guardian.example.com",
        "https://guardian.example.com?a=b",
        "https://guardian.example.com#frag",
        "https://",
    ],
)
def test_an_unusable_override_is_a_startup_error(value: str) -> None:
    with pytest.raises(ValueError, match="PUBLIC_BASE_URL"):
        _settings(public_base_url_override=value)


def test_production_refuses_a_plaintext_base_url() -> None:
    """The activation POST carries the token and the new password together."""
    with pytest.raises(ValueError, match="https"):
        _settings(environment="production", cors_origins="http://guardian.example.com")


def test_production_accepts_https() -> None:
    settings = _settings(environment="production", cors_origins="https://guardian.example.com")

    assert settings.public_base_url == "https://guardian.example.com"


def test_development_still_accepts_plaintext() -> None:
    assert _settings(cors_origins="http://localhost:4200").public_base_url == "http://localhost:4200"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd backend && uv run pytest tests/test_public_base_url.py -q`
Expected: FAIL — `Settings` has no `public_base_url_override`, so construction raises or the attribute is missing.

- [ ] **Step 3: Implement**

In `config.py`, add the field immediately after `cors_origins`:

```python
    # The canonical origin activation links are built from. Empty means derive
    # it from a lone CORS origin, which is self-validating: a wrong one stops
    # the browser application calling the API at all.
    public_base_url_override: str = ""
```

Bind the environment name by adding an alias in `model_config`, or name the field `public_base_url_override` and set `validation_alias`. Use the simplest form pydantic-settings supports here:

```python
from pydantic import Field
...
    public_base_url_override: str = Field(default="", validation_alias="PUBLIC_BASE_URL")
```

Add the property next to `parsed_cors_origins`:

```python
    @property
    def public_base_url(self) -> str | None:
        """Return the canonical origin, or ``None`` when it cannot be resolved.

        Several CORS origins never elect one: CORS is an allow-list, and the
        order within it carries no meaning. Callers that need a link must
        refuse rather than guess.
        """
        if self.public_base_url_override:
            return self.public_base_url_override.rstrip("/")
        origins = self.parsed_cors_origins
        return origins[0].rstrip("/") if len(origins) == 1 else None
```

Add a validator after `require_secure_session_cookies`:

```python
    @model_validator(mode="after")
    def validate_public_base_url(self) -> "Settings":
        """Refuse a public base URL that cannot safely carry an activation link.

        The activation request carries the invitation credential and the
        password its owner is choosing in one POST, so production requires
        TLS. Nothing working is broken by that: ``session_cookie_secure`` is
        already forced true in production, so a plaintext production
        deployment cannot hold a session and is already non-functional.
        """
        if self.public_base_url_override:
            parsed = urlparse(self.public_base_url_override)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
            ):
                msg = "PUBLIC_BASE_URL must be an absolute http(s) URL with no credentials, query, or fragment"
                raise ValueError(msg)
        resolved = self.public_base_url
        if self.environment == "production" and resolved is not None and not resolved.startswith("https://"):
            msg = "PUBLIC_BASE_URL must use https in production"
            raise ValueError(msg)
        return self
```

Add `from urllib.parse import urlparse` to the imports.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd backend && uv run pytest tests/test_public_base_url.py -q`
Expected: PASS, 10 tests.

- [ ] **Step 5: Document the setting**

Add to `.env.example` beneath `CORS_ORIGINS`:

```
# The canonical origin used to build invitation links. Derived from a lone
# CORS_ORIGINS entry when unset; required when several are listed, as the
# default development pair is. Must use https in production.
# PUBLIC_BASE_URL=http://localhost:4200
```

- [ ] **Step 6: Run the full suite and commit**

Run: `make check`

```bash
git add backend/src/mist_config_guardian_backend/config.py backend/tests/test_public_base_url.py .env.example
git commit -m "Resolve the application's canonical public base URL"
```

---

### Task 2: Persist SMTP settings

**Files:**
- Modify: `backend/src/mist_config_guardian_backend/models/application_configuration.py:14-26` (add fields to `ApplicationConfiguration`)
- Modify: `backend/src/mist_config_guardian_backend/schemas/application_configuration.py`
- Test: `backend/tests/test_smtp_settings.py` (create)

**Interfaces:**
- Consumes: Task 1's `Settings.public_base_url`.
- Produces: `ApplicationConfiguration` fields `smtp_enabled`, `smtp_host`, `smtp_port`, `smtp_security`, `smtp_username`, `encrypted_smtp_password`, `smtp_password_last_four`, `smtp_from_address`, `smtp_from_name`, `smtp_last_test_at`, `smtp_last_test_ok`, `smtp_last_test_detail`. Schemas `SmtpSettingsUpdate`, `SmtpSettingsResponse`, `SmtpConnectionTestResponse`.

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_smtp_settings.py`:

```python
"""SMTP settings persistence and its request schema."""

import pytest
from pydantic import ValidationError

from mist_config_guardian_backend.models.application_configuration import ApplicationConfiguration
from mist_config_guardian_backend.schemas.application_configuration import SmtpSettingsUpdate


def test_smtp_is_disabled_until_an_administrator_enables_it() -> None:
    configuration = ApplicationConfiguration()

    assert configuration.smtp_enabled is False
    assert configuration.smtp_port == 587
    assert configuration.smtp_security == "starttls"
    assert configuration.encrypted_smtp_password is None


def test_the_update_schema_defaults_to_a_disabled_starttls_submission() -> None:
    request = SmtpSettingsUpdate()

    assert request.enabled is False
    assert request.security == "starttls"
    assert request.port == 587
    assert request.clear_password is False


@pytest.mark.parametrize("port", [0, 65536])
def test_a_port_outside_the_usable_range_is_refused(port: int) -> None:
    with pytest.raises(ValidationError):
        SmtpSettingsUpdate(port=port)


def test_an_unknown_security_mode_is_refused() -> None:
    with pytest.raises(ValidationError):
        SmtpSettingsUpdate(security="ssl-maybe")
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd backend && uv run pytest tests/test_smtp_settings.py -q`
Expected: FAIL — `ImportError: cannot import name 'SmtpSettingsUpdate'`.

- [ ] **Step 3: Implement the model fields**

In `models/application_configuration.py`, inside `ApplicationConfiguration` after the Impact AI fields:

```python
    smtp_enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_security: Literal["starttls", "tls", "none"] = "starttls"
    smtp_username: str = ""
    encrypted_smtp_password: str | None = None
    smtp_password_last_four: str | None = None
    smtp_from_address: str = ""
    smtp_from_name: str = ""
    smtp_last_test_at: datetime | None = None
    smtp_last_test_ok: bool | None = None
    smtp_last_test_detail: str | None = None
```

- [ ] **Step 4: Implement the schemas**

In `schemas/application_configuration.py`:

```python
class SmtpSettingsUpdate(BaseModel):
    """Administrator-supplied SMTP settings; a blank password leaves it untouched."""

    enabled: bool = False
    host: str = Field(default="", max_length=255)
    port: int = Field(default=587, ge=1, le=65535)
    security: Literal["starttls", "tls", "none"] = "starttls"
    username: str = Field(default="", max_length=255)
    password: SecretStr | None = Field(default=None, max_length=1024)
    clear_password: bool = False
    from_address: str = Field(default="", max_length=320)
    from_name: str = Field(default="", max_length=120)


class SmtpSettingsResponse(BaseModel):
    """Stored SMTP settings with the password reduced to its last four characters."""

    enabled: bool
    host: str
    port: int
    security: Literal["starttls", "tls", "none"]
    username: str
    password_set: bool
    password_last_four: str | None
    from_address: str
    from_name: str
    last_test_at: datetime | None = None
    last_test_ok: bool | None = None
    last_test_detail: str | None = None


class SmtpConnectionTestResponse(BaseModel):
    """The outcome of probing the stored SMTP server without sending a message."""

    ok: bool
    detail: str
    checked_at: datetime
```

Add `Literal` to the `typing` import if absent.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd backend && uv run pytest tests/test_smtp_settings.py -q`
Expected: PASS, 5 tests.

- [ ] **Step 6: Commit**

```bash
git add backend/src/mist_config_guardian_backend/models/application_configuration.py \
        backend/src/mist_config_guardian_backend/schemas/application_configuration.py \
        backend/tests/test_smtp_settings.py
git commit -m "Persist SMTP settings on the application configuration"
```

---

### Task 3: The SMTP transport

**Files:**
- Create: `backend/src/mist_config_guardian_backend/integrations/smtp.py`
- Test: `backend/tests/test_smtp_transport.py` (create)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `SendOutcome(status: Literal["sent","uncertain","failed"], detail: str)` — frozen dataclass.
  - `SmtpCredentials(host, port, security, username, password, from_address, from_name)` — frozen dataclass.
  - `MailSender` Protocol with `async def send(self, *, to: str, subject: str, text: str, html: str) -> SendOutcome`.
  - `SmtpMailSender(credentials: SmtpCredentials, timeout: float = 10.0)` implementing it.
  - `verified_context() -> ssl.SSLContext`.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_smtp_transport.py`:

```python
"""The SMTP transport classifies its own outcome by protocol phase."""

import smtplib
import ssl

import pytest

from mist_config_guardian_backend.integrations.smtp import (
    SendOutcome,
    SmtpCredentials,
    SmtpMailSender,
    verified_context,
)

CREDENTIALS = SmtpCredentials(
    host="mail.example.com",
    port=587,
    security="starttls",
    username="postmaster",
    password="hunter2",
    from_address="guardian@example.com",
    from_name="Config Guardian",
)


class FakeSmtp:
    """A stand-in for ``smtplib.SMTP`` that raises at a chosen phase."""

    def __init__(self, *, raise_at: str | None = None, error: Exception | None = None) -> None:
        self.raise_at = raise_at
        self.error = error or smtplib.SMTPException("boom")
        self.contexts: list[ssl.SSLContext] = []
        self.sent = False

    def _maybe(self, phase: str) -> None:
        if self.raise_at == phase:
            raise self.error

    def starttls(self, *, context: ssl.SSLContext) -> None:
        self.contexts.append(context)
        self._maybe("starttls")

    def login(self, username: str, password: str) -> None:
        self._maybe("login")

    def send_message(self, message: object) -> dict[str, object]:
        self._maybe("send")
        self.sent = True
        return {}

    def quit(self) -> None:
        return None


async def _send(sender: SmtpMailSender) -> SendOutcome:
    return await sender.send(to="invitee@example.com", subject="s", text="t", html="<p>t</p>")


def test_the_verified_context_checks_certificates_and_hostnames() -> None:
    """smtplib's own default disables both, which encrypts to any interceptor."""
    context = verified_context()

    assert context.check_hostname is True
    assert context.verify_mode is ssl.CERT_REQUIRED


async def test_a_clean_send_is_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeSmtp()
    sender = SmtpMailSender(CREDENTIALS, client_factory=lambda: client)

    outcome = await _send(sender)

    assert outcome.status == "sent"
    assert client.sent


async def test_starttls_uses_a_verified_context(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeSmtp()
    sender = SmtpMailSender(CREDENTIALS, client_factory=lambda: client)

    await _send(sender)

    assert client.contexts and client.contexts[0].verify_mode is ssl.CERT_REQUIRED


@pytest.mark.parametrize("phase", ["starttls", "login"])
async def test_an_error_before_the_body_is_written_is_failed(phase: str) -> None:
    client = FakeSmtp(raise_at=phase)
    sender = SmtpMailSender(CREDENTIALS, client_factory=lambda: client)

    outcome = await _send(sender)

    assert outcome.status == "failed"
    assert not client.sent


def _refusal() -> Exception:
    return smtplib.SMTPRecipientsRefused({"invitee@example.com": (550, b"no such user")})


async def test_a_refusal_read_back_from_the_server_is_failed() -> None:
    client = FakeSmtp(raise_at="send", error=_refusal())
    sender = SmtpMailSender(CREDENTIALS, client_factory=lambda: client)

    assert (await _send(sender)).status == "failed"


async def test_a_server_that_does_not_offer_starttls_is_failed() -> None:
    """The send is never retried in the clear."""
    client = FakeSmtp(raise_at="starttls", error=smtplib.SMTPNotSupportedError("no starttls"))
    sender = SmtpMailSender(CREDENTIALS, client_factory=lambda: client)

    assert (await _send(sender)).status == "failed"


@pytest.mark.parametrize(
    "error",
    [TimeoutError("timed out"), smtplib.SMTPServerDisconnected("gone")],
)
async def test_losing_the_connection_while_sending_is_uncertain(error: Exception) -> None:
    """The body may have been written and queued with the reply unread."""
    client = FakeSmtp(raise_at="send", error=error)
    sender = SmtpMailSender(CREDENTIALS, client_factory=lambda: client)

    assert (await _send(sender)).status == "uncertain"


async def test_the_detail_never_carries_the_message_body() -> None:
    client = FakeSmtp(raise_at="send", error=_refusal())
    sender = SmtpMailSender(CREDENTIALS, client_factory=lambda: client)

    outcome = await _send(sender)

    assert "t" not in outcome.detail or "no such user" in outcome.detail
    assert len(outcome.detail) <= 200
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd backend && uv run pytest tests/test_smtp_transport.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'mist_config_guardian_backend.integrations.smtp'`.

- [ ] **Step 3: Implement the transport**

Create `backend/src/mist_config_guardian_backend/integrations/smtp.py`:

```python
"""Outbound SMTP with verified TLS and phase-aware outcome classification.

The transport reports what happened rather than raising, because only this
layer knows which protocol phase failed. An ``SMTPException`` seen from
outside does not say whether the message body reached the server, and a caller
forced to guess would call a queued message a failure.
"""

import asyncio
import smtplib
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Literal, Protocol

# An administrator reads this next to the invitation link; it is a summary, not
# a transcript, and is never allowed to grow into one.
_MAX_DETAIL = 200

# Read back from the server, so a reply was received and it was a refusal.
_REFUSALS = (
    smtplib.SMTPRecipientsRefused,
    smtplib.SMTPSenderRefused,
    smtplib.SMTPDataError,
    smtplib.SMTPNotSupportedError,
)


@dataclass(frozen=True, slots=True)
class SendOutcome:
    """What the transport observed. ``detail`` is empty only when ``sent``."""

    status: Literal["sent", "uncertain", "failed"]
    detail: str = ""


@dataclass(frozen=True, slots=True)
class SmtpCredentials:
    """Everything one send needs, already decrypted."""

    host: str
    port: int
    security: Literal["starttls", "tls", "none"]
    username: str
    password: str
    from_address: str
    from_name: str


class MailSender(Protocol):
    """The transport the invitation routes depend on."""

    async def send(self, *, to: str, subject: str, text: str, html: str) -> SendOutcome:
        """Deliver one message, reporting the outcome rather than raising."""
        ...


def verified_context() -> ssl.SSLContext:
    """Return a TLS context that verifies certificates and hostnames.

    ``smtplib`` falls back to ``ssl._create_stdlib_context()`` when given no
    context, which has ``check_hostname=False`` and ``verify_mode=CERT_NONE``:
    it would encrypt happily to an interceptor presenting any certificate,
    who would then read the invitation token and this password.
    """
    return ssl.create_default_context()


def _truncate(value: str) -> str:
    return value[:_MAX_DETAIL]


class SmtpMailSender:
    """Send one message per call over a fresh connection."""

    def __init__(
        self,
        credentials: SmtpCredentials,
        *,
        timeout: float = 10.0,
        client_factory: Callable[[], smtplib.SMTP] | None = None,
    ) -> None:
        self._credentials = credentials
        self._timeout = timeout
        self._client_factory = client_factory

    async def send(self, *, to: str, subject: str, text: str, html: str) -> SendOutcome:
        """Deliver one message off the event loop, classifying by phase."""
        message = self._build(to=to, subject=subject, text=text, html=html)
        return await asyncio.to_thread(self._send_blocking, message)

    def _build(self, *, to: str, subject: str, text: str, html: str) -> EmailMessage:
        message = EmailMessage()
        sender = self._credentials.from_address
        if self._credentials.from_name:
            sender = f"{self._credentials.from_name} <{sender}>"
        message["From"] = sender
        message["To"] = to
        message["Subject"] = subject
        message.set_content(text)
        message.add_alternative(html, subtype="html")
        return message

    def _connect(self) -> smtplib.SMTP:
        if self._client_factory is not None:
            return self._client_factory()
        credentials = self._credentials
        if credentials.security == "tls":
            return smtplib.SMTP_SSL(
                credentials.host,
                credentials.port,
                timeout=self._timeout,
                context=verified_context(),
            )
        return smtplib.SMTP(credentials.host, credentials.port, timeout=self._timeout)

    def _send_blocking(self, message: EmailMessage) -> SendOutcome:
        credentials = self._credentials
        try:
            client = self._connect()
        except (OSError, smtplib.SMTPException) as exc:
            return SendOutcome("failed", _truncate(f"Could not connect: {exc}"))
        try:
            if credentials.security == "starttls":
                client.starttls(context=verified_context())
            if credentials.username:
                client.login(credentials.username, credentials.password)
        except (OSError, smtplib.SMTPException) as exc:
            # Nothing was written, so nothing can have been queued.
            self._close(client)
            return SendOutcome("failed", _truncate(f"Could not negotiate a session: {exc}"))
        try:
            client.send_message(message)
        except _REFUSALS as exc:
            self._close(client)
            return SendOutcome("failed", _truncate(f"The server refused the message: {exc}"))
        except (OSError, smtplib.SMTPException) as exc:
            # The body may have been written and queued with the reply unread.
            self._close(client)
            return SendOutcome("uncertain", _truncate(f"No confirmation was received: {exc}"))
        self._close(client)
        return SendOutcome("sent")

    @staticmethod
    def _close(client: smtplib.SMTP) -> None:
        try:
            client.quit()
        except (OSError, smtplib.SMTPException):
            # The message's fate is already decided; a failed teardown is noise.
            pass
```

Note `TimeoutError` is a subclass of `OSError`, so the `uncertain` branch catches it.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd backend && uv run pytest tests/test_smtp_transport.py -q`
Expected: PASS, 11 tests.

- [ ] **Step 5: Commit**

```bash
git add backend/src/mist_config_guardian_backend/integrations/smtp.py backend/tests/test_smtp_transport.py
git commit -m "Add an SMTP transport with verified TLS and phase-aware outcomes"
```

---

### Task 4: SMTP settings service and its refusals

**Files:**
- Modify: `backend/src/mist_config_guardian_backend/services/application_configuration.py` (add methods to `ApplicationConfigurationService`, add `_SMTP_PASSWORD_CONTEXT = "smtp-password"` beside `_AI_PROVIDER_KEY_CONTEXT` at line 33)
- Test: `backend/tests/test_smtp_settings.py` (extend)

**Interfaces:**
- Consumes: Task 1 `Settings.public_base_url`; Task 2 model fields and schemas; Task 3 `SmtpCredentials`.
- Produces on `ApplicationConfigurationService`:
  - `async get_smtp() -> SmtpSettingsResponse`
  - `async update_smtp(request: SmtpSettingsUpdate) -> SmtpSettingsResponse`
  - `async smtp_credentials() -> SmtpCredentials | None` — `None` when disabled
  - `is_loopback_host(host: str) -> bool` — module-level

- [ ] **Step 1: Write the failing tests**

Append to `backend/tests/test_smtp_settings.py`:

```python
from mist_config_guardian_backend.services.application_configuration import (
    ApplicationConfigurationError,
    is_loopback_host,
)


@pytest.mark.parametrize("host", ["127.0.0.1", "127.1.2.3", "::1"])
def test_a_literal_loopback_address_is_loopback(host: str) -> None:
    assert is_loopback_host(host)


@pytest.mark.parametrize("host", ["localhost", "mail.internal", "10.0.0.5", "", "::ffff:127.0.0.1"])
def test_anything_needing_resolution_is_not_loopback(host: str) -> None:
    """A name can be rebound between the check and the connection; a literal cannot."""
    assert not is_loopback_host(host)
```

Add these service tests to the same file (they need the `configuration_service` fixture pattern used by `tests/test_application_configuration.py` — read that file and reuse its fixture):

```python
async def test_enabling_smtp_without_a_host_is_refused(service) -> None:
    with pytest.raises(ApplicationConfigurationError, match="host"):
        await service.update_smtp(SmtpSettingsUpdate(enabled=True, from_address="a@example.com"))


async def test_enabling_smtp_without_a_from_address_is_refused(service) -> None:
    with pytest.raises(ApplicationConfigurationError, match="address"):
        await service.update_smtp(SmtpSettingsUpdate(enabled=True, host="mail.example.com"))


async def test_plaintext_with_a_username_is_refused(service) -> None:
    """An SMTP password in the clear is never the intended configuration."""
    with pytest.raises(ApplicationConfigurationError, match="unencrypted"):
        await service.update_smtp(
            SmtpSettingsUpdate(
                enabled=True,
                host="mail.example.com",
                from_address="a@example.com",
                security="none",
                username="postmaster",
                password="hunter2",
            )
        )


async def test_a_blank_password_leaves_the_stored_one_untouched(service) -> None:
    await service.update_smtp(
        SmtpSettingsUpdate(
            enabled=True, host="mail.example.com", from_address="a@example.com", password="hunter2"
        )
    )

    response = await service.update_smtp(
        SmtpSettingsUpdate(enabled=True, host="mail.example.com", from_address="a@example.com")
    )

    assert response.password_set
    assert response.password_last_four == "ter2"


async def test_disabled_smtp_has_no_credentials(service) -> None:
    assert await service.smtp_credentials() is None
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd backend && uv run pytest tests/test_smtp_settings.py -q`
Expected: FAIL — `cannot import name 'is_loopback_host'`.

- [ ] **Step 3: Implement**

In `services/application_configuration.py`, add at module level:

```python
_SMTP_PASSWORD_CONTEXT = "smtp-password"


def is_loopback_host(host: str) -> bool:
    """Report whether a host is a literal loopback address.

    Literals only, and never resolved. ``localhost`` is a name: what it points
    at can change between this check and the connection that trusts it, so a
    name is never accepted as proof that traffic stays on the machine.
    """
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False
```

Add `from ipaddress import ip_address` to the imports.

Add the methods to `ApplicationConfigurationService`:

```python
    async def get_smtp(self) -> SmtpSettingsResponse:
        """Return stored SMTP settings without the password."""
        return self._smtp_response(await self._get_or_create())

    async def update_smtp(self, request: SmtpSettingsUpdate) -> SmtpSettingsResponse:
        """Persist SMTP settings, refusing configurations that cannot be secured."""
        if request.enabled:
            self._validate_smtp(request)
        configuration = await self._get_or_create()
        password = request.password.get_secret_value() if request.password is not None else None
        if password:
            configuration.encrypted_smtp_password = self._vault.encrypt_for_context(
                password,
                context=_SMTP_PASSWORD_CONTEXT,
            )
            configuration.smtp_password_last_four = password[-4:].rjust(4, "*")
        elif request.clear_password:
            configuration.encrypted_smtp_password = None
            configuration.smtp_password_last_four = None

        configuration.smtp_enabled = request.enabled
        configuration.smtp_host = request.host.strip()
        configuration.smtp_port = request.port
        configuration.smtp_security = request.security
        configuration.smtp_username = request.username.strip()
        configuration.smtp_from_address = request.from_address.strip()
        configuration.smtp_from_name = request.from_name.strip()
        configuration.touch()
        await configuration.save()
        return self._smtp_response(configuration)

    def _validate_smtp(self, request: SmtpSettingsUpdate) -> None:
        """Refuse an enabled configuration that cannot deliver safely."""
        if not request.host.strip():
            msg = "An SMTP host is required to enable email"
            raise ApplicationConfigurationError(msg)
        if not request.from_address.strip():
            msg = "A from address is required to enable email"
            raise ApplicationConfigurationError(msg)
        if self._settings.public_base_url is None:
            msg = (
                "PUBLIC_BASE_URL must be set before enabling email: the application "
                "cannot tell which of its origins invitation links should use"
            )
            raise ApplicationConfigurationError(msg)
        if request.security == "none":
            if request.username.strip():
                msg = "An unencrypted connection cannot carry a username and password"
                raise ApplicationConfigurationError(msg)
            if self._settings.environment == "production" and not is_loopback_host(request.host.strip()):
                msg = (
                    "An unencrypted connection is only allowed in production to a literal "
                    "loopback address such as 127.0.0.1 or ::1"
                )
                raise ApplicationConfigurationError(msg)

    async def smtp_credentials(self) -> SmtpCredentials | None:
        """Return decrypted SMTP credentials when email is enabled."""
        configuration = await ApplicationConfiguration.find_one(ApplicationConfiguration.key == "global")
        if configuration is None or not configuration.smtp_enabled:
            return None
        password = ""
        if configuration.encrypted_smtp_password is not None:
            password = self._vault.decrypt_for_context(
                configuration.encrypted_smtp_password,
                context=_SMTP_PASSWORD_CONTEXT,
            )
        return SmtpCredentials(
            host=configuration.smtp_host,
            port=configuration.smtp_port,
            security=configuration.smtp_security,
            username=configuration.smtp_username,
            password=password,
            from_address=configuration.smtp_from_address,
            from_name=configuration.smtp_from_name,
        )

    @staticmethod
    def _smtp_response(configuration: ApplicationConfiguration) -> SmtpSettingsResponse:
        """Project stored settings into the administrator-visible shape."""
        return SmtpSettingsResponse(
            enabled=configuration.smtp_enabled,
            host=configuration.smtp_host,
            port=configuration.smtp_port,
            security=configuration.smtp_security,
            username=configuration.smtp_username,
            password_set=configuration.encrypted_smtp_password is not None,
            password_last_four=configuration.smtp_password_last_four,
            from_address=configuration.smtp_from_address,
            from_name=configuration.smtp_from_name,
            last_test_at=configuration.smtp_last_test_at,
            last_test_ok=configuration.smtp_last_test_ok,
            last_test_detail=configuration.smtp_last_test_detail,
        )
```

`ApplicationConfigurationService.__init__` already accepts `settings: Settings | None = None` and stores `self._settings = settings or get_settings()` (line 130), so `_validate_smtp` can read it with no constructor change. Tests that need a non-default environment pass their own `Settings` in.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd backend && uv run pytest tests/test_smtp_settings.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/src/mist_config_guardian_backend/services/application_configuration.py backend/tests/test_smtp_settings.py
git commit -m "Refuse SMTP configurations that cannot deliver safely"
```

---

### Task 5: SMTP settings endpoints and the connection test

**Files:**
- Modify: `backend/src/mist_config_guardian_backend/api/routes/application_configuration.py`
- Modify: `backend/src/mist_config_guardian_backend/services/application_configuration.py` (add `test_smtp_connection`)
- Modify: `backend/src/mist_config_guardian_backend/services/deep_links.py:27` — add `"email"` to `SETTINGS_TABS`
- Test: `backend/tests/test_smtp_settings_api.py` (create)

**Interfaces:**
- Consumes: Task 3 `verified_context`, Task 4 service methods.
- Produces: `GET /api/v1/application-configuration/smtp`, `PUT /api/v1/application-configuration/smtp`, `POST /api/v1/application-configuration/smtp/test`. Service method `async test_smtp_connection() -> SmtpConnectionTestResponse`.

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_smtp_settings_api.py`. Read `backend/tests/test_application_configuration_api.py` first and copy its client and administrator-authentication fixtures exactly; then:

```python
"""The SMTP settings endpoints."""

from mist_config_guardian_backend.services.deep_links import SETTINGS_TABS


def test_the_email_tab_is_deep_linkable() -> None:
    """deep_link refuses a tab it does not know, so the set must carry it."""
    assert "email" in SETTINGS_TABS


async def test_an_administrator_reads_smtp_settings(admin_client) -> None:
    response = await admin_client.get("/api/v1/application-configuration/smtp")

    assert response.status_code == 200
    assert response.json()["enabled"] is False


async def test_an_operator_cannot_read_smtp_settings(operator_client) -> None:
    assert (await operator_client.get("/api/v1/application-configuration/smtp")).status_code == 403


async def test_enabling_without_a_host_answers_422(admin_client) -> None:
    response = await admin_client.put(
        "/api/v1/application-configuration/smtp",
        json={"enabled": True, "from_address": "a@example.com"},
    )

    assert response.status_code == 422
    assert "host" in response.json()["detail"]


async def test_the_connection_test_records_its_outcome(admin_client) -> None:
    response = await admin_client.post("/api/v1/application-configuration/smtp/test")

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert "checked_at" in body
    stored = (await admin_client.get("/api/v1/application-configuration/smtp")).json()
    assert stored["last_test_ok"] is False
    assert stored["last_test_detail"]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd backend && uv run pytest tests/test_smtp_settings_api.py -q`
Expected: FAIL — `"email" in SETTINGS_TABS` is False and the routes answer 404.

- [ ] **Step 3: Add the tab and the service method**

In `services/deep_links.py:27`:

```python
SETTINGS_TABS = frozenset({"organizations", "users", "ai", "email", "health"})
```

In `services/application_configuration.py`:

```python
    async def test_smtp_connection(self) -> SmtpConnectionTestResponse:
        """Probe the stored SMTP server without sending a message.

        Connecting, upgrading, and authenticating is the whole check: proving
        a message can be sent would mean sending one, and there is nobody to
        send it to.
        """
        configuration = await self._get_or_create()
        credentials = await self.smtp_credentials()
        if credentials is None:
            ok, detail = False, "Email is not enabled."
        else:
            ok, detail = await asyncio.to_thread(_probe_smtp, credentials)
        checked_at = utc_now()
        configuration.smtp_last_test_at = checked_at
        configuration.smtp_last_test_ok = ok
        configuration.smtp_last_test_detail = detail
        configuration.touch()
        await configuration.save()
        return SmtpConnectionTestResponse(ok=ok, detail=detail, checked_at=checked_at)
```

And at module level:

```python
def _probe_smtp(credentials: SmtpCredentials) -> tuple[bool, str]:
    """Connect, upgrade, and authenticate, reporting what happened."""
    try:
        if credentials.security == "tls":
            client = smtplib.SMTP_SSL(
                credentials.host, credentials.port, timeout=10.0, context=verified_context()
            )
        else:
            client = smtplib.SMTP(credentials.host, credentials.port, timeout=10.0)
        try:
            if credentials.security == "starttls":
                client.starttls(context=verified_context())
            if credentials.username:
                client.login(credentials.username, credentials.password)
        finally:
            client.quit()
    except (OSError, smtplib.SMTPException) as exc:
        return False, str(exc)[:200]
    if credentials.security == "none":
        return True, "Connected. This connection is unencrypted."
    return True, "Connected and authenticated over TLS."
```

Add `import asyncio`, `import smtplib`, and the `verified_context` / `SmtpCredentials` imports.

- [ ] **Step 4: Add the routes**

In `api/routes/application_configuration.py`, following the shape of the existing `/impact-ai` routes (read lines 24-50 first and copy the dependency and role-guard style exactly):

```python
@router.get("/smtp")
async def read_smtp_settings(
    service: Annotated[ApplicationConfigurationService, Depends(get_application_configuration_service)],
    _administrator: Annotated[User, Depends(require_administrator)],
) -> SmtpSettingsResponse:
    """Return the stored SMTP settings without the password."""
    return await service.get_smtp()


@router.put("/smtp")
async def update_smtp_settings(
    payload: SmtpSettingsUpdate,
    service: Annotated[ApplicationConfigurationService, Depends(get_application_configuration_service)],
    _administrator: Annotated[User, Depends(require_administrator)],
) -> SmtpSettingsResponse:
    """Persist SMTP settings, refusing what cannot deliver safely."""
    try:
        return await service.update_smtp(payload)
    except ApplicationConfigurationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc


@router.post("/smtp/test")
async def test_smtp_settings(
    service: Annotated[ApplicationConfigurationService, Depends(get_application_configuration_service)],
    _administrator: Annotated[User, Depends(require_administrator)],
) -> SmtpConnectionTestResponse:
    """Probe the stored SMTP server and record the outcome."""
    return await service.test_smtp_connection()
```

- [ ] **Step 5: Run the tests and regenerate the contract**

Run: `cd backend && uv run pytest tests/test_smtp_settings_api.py -q`
Expected: PASS.

Run from the repository root: `make openapi`

- [ ] **Step 6: Run the full suite and commit**

Run: `make check`

```bash
git add backend/src/mist_config_guardian_backend/api/routes/application_configuration.py \
        backend/src/mist_config_guardian_backend/services/application_configuration.py \
        backend/src/mist_config_guardian_backend/services/deep_links.py \
        backend/tests/test_smtp_settings_api.py docs/openapi.json
git commit -m "Expose SMTP settings and a connection test"
```

---

### Task 6: Per-scope throttle windows and invitation limits

**Files:**
- Modify: `backend/src/mist_config_guardian_backend/services/throttling.py:27-33` (`Scope`), `reserve`, and the scopes block around line 170
- Modify: `backend/src/mist_config_guardian_backend/config.py` (two settings)
- Test: `backend/tests/test_throttling.py` (extend)

**Interfaces:**
- Consumes: nothing.
- Produces: `Scope(key, limit, window: timedelta | None = None)`; `ThrottleService.invitation_target(user_id) -> Scope`; `ThrottleService.invitation_sender(admin_id) -> Scope`; settings `invitation_sends_per_target_per_minute: int = 1`, `invitation_sends_per_sender_per_hour: int = 20`.

- [ ] **Step 1: Write the failing tests**

Append to `backend/tests/test_throttling.py` (reuse the existing `MemoryThrottleStore` fixture style in that file):

```python
from datetime import timedelta

from beanie import PydanticObjectId


def test_invitation_scopes_do_not_share_a_bucket_with_password_confirmation() -> None:
    """Reusing user() would let each starve the other."""
    service = ThrottleService(Settings(_env_file=None, environment="test", database_enabled=False))
    user_id = PydanticObjectId()

    assert service.invitation_target(user_id).key != service.user(user_id).key


def test_an_invitation_scope_carries_its_own_window() -> None:
    service = ThrottleService(Settings(_env_file=None, environment="test", database_enabled=False))

    assert service.invitation_target(PydanticObjectId()).window == timedelta(minutes=1)
    assert service.invitation_sender(PydanticObjectId()).window == timedelta(hours=1)


def test_an_existing_scope_still_has_no_window_of_its_own() -> None:
    service = ThrottleService(Settings(_env_file=None, environment="test", database_enabled=False))

    assert service.account("a@example.com").window is None


async def test_a_second_send_to_one_target_inside_the_window_is_refused() -> None:
    settings = Settings(_env_file=None, environment="test", database_enabled=False)
    service = ThrottleService(settings, store=MemoryThrottleStore())
    scope = service.invitation_target(PydanticObjectId())

    await service.reserve(scope)

    with pytest.raises(ThrottledError):
        await service.reserve(scope)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd backend && uv run pytest tests/test_throttling.py -q`
Expected: FAIL — `Scope` has no `window`, `ThrottleService` has no `invitation_target`.

- [ ] **Step 3: Implement**

In `throttling.py`, change `Scope`:

```python
@dataclass(frozen=True, slots=True)
class Scope:
    """One counted key, the number of attempts it tolerates, and its window.

    ``window`` is ``None`` for the sign-in scopes, which share the service's
    window. A scope that bounds something other than credential guessing sets
    its own rather than inheriting a window chosen for passwords.
    """

    key: str
    limit: int
    window: timedelta | None = None
```

In `reserve`, replace `await self._store.record(scope.key, self._window)` with:

```python
            count = await self._store.record(scope.key, scope.window or self._window)
```

Make the same substitution in `failed`.

Add the two scopes beside the existing ones:

```python
    def invitation_target(self, user_id: PydanticObjectId) -> Scope:
        """The scope bounding how often one invitee can be mailed."""
        return Scope(
            f"invite-target:{user_id}",
            self._settings.invitation_sends_per_target_per_minute,
            timedelta(minutes=1),
        )

    def invitation_sender(self, admin_id: PydanticObjectId) -> Scope:
        """The scope bounding what one administrator's account can emit.

        This is what limits the invite endpoint at all: there is no target
        user before the invitation is created.
        """
        return Scope(
            f"invite-sender:{admin_id}",
            self._settings.invitation_sends_per_sender_per_hour,
            timedelta(hours=1),
        )
```

In `config.py`, beside the sign-in throttle settings:

```python
    invitation_sends_per_target_per_minute: int = 1
    invitation_sends_per_sender_per_hour: int = 20
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd backend && uv run pytest tests/test_throttling.py -q`
Expected: PASS, including every pre-existing test in the file.

- [ ] **Step 5: Commit**

```bash
git add backend/src/mist_config_guardian_backend/services/throttling.py \
        backend/src/mist_config_guardian_backend/config.py backend/tests/test_throttling.py
git commit -m "Give a throttle scope its own window and add invitation limits"
```

---

### Task 7: The invitation message and its activation link

**Files:**
- Create: `backend/src/mist_config_guardian_backend/services/invitation_email.py`
- Test: `backend/tests/test_invitation_email.py` (create)

**Interfaces:**
- Consumes: Task 1 `Settings.public_base_url`.
- Produces:
  - `activation_url(base_url: str, token: str) -> str`
  - `InvitationMessage(subject: str, text: str, html: str)` — frozen dataclass
  - `build_invitation_message(*, app_name: str, inviter: str | None, activation_link: str, expires_in_days: int) -> InvitationMessage`

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_invitation_email.py`:

```python
"""The invitation message and the link it carries."""

from mist_config_guardian_backend.services.invitation_email import (
    activation_url,
    build_invitation_message,
)

TOKEN = "s3cr3t-token-value"


def test_the_token_travels_in_the_fragment() -> None:
    """A query string reaches ingress logs, history, and Referer headers."""
    url = activation_url("https://guardian.example.com", TOKEN)

    assert url == f"https://guardian.example.com/accept-invitation#token={TOKEN}"
    assert "?" not in url


def test_a_trailing_slash_on_the_base_does_not_double() -> None:
    assert activation_url("https://guardian.example.com/", TOKEN).startswith(
        "https://guardian.example.com/accept-invitation"
    )


def test_a_token_needing_escaping_is_encoded() -> None:
    url = activation_url("https://guardian.example.com", "a b+c/d")

    assert " " not in url
    assert url.endswith("#token=a%20b%2Bc%2Fd")


def test_the_message_states_the_inviter_the_link_and_the_expiry() -> None:
    link = activation_url("https://guardian.example.com", TOKEN)

    message = build_invitation_message(
        app_name="Mist Config Guardian",
        inviter="Thomas Munzer",
        activation_link=link,
        expires_in_days=7,
    )

    assert "Mist Config Guardian" in message.subject
    assert "Thomas Munzer" in message.text
    assert link in message.text
    assert link in message.html
    assert "7 days" in message.text


def test_an_unattributed_invitation_still_reads_sensibly() -> None:
    message = build_invitation_message(
        app_name="Mist Config Guardian",
        inviter=None,
        activation_link="https://guardian.example.com/accept-invitation#token=x",
        expires_in_days=7,
    )

    assert "None" not in message.text
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd backend && uv run pytest tests/test_invitation_email.py -q`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement**

Create `backend/src/mist_config_guardian_backend/services/invitation_email.py`:

```python
"""The invitation message, and the activation link it carries.

The link puts the token in the URL fragment. A query string is carried in the
request line and lands in ingress logs, proxy logs, browser history, and
``Referer`` headers on any outbound link; a fragment is never sent to a server
at all.
"""

from dataclasses import dataclass
from urllib.parse import quote

ACTIVATION_PATH = "/accept-invitation"


def activation_url(base_url: str, token: str) -> str:
    """Return the link an invitee follows to choose a password."""
    return f"{base_url.rstrip('/')}{ACTIVATION_PATH}#token={quote(token, safe='')}"


@dataclass(frozen=True, slots=True)
class InvitationMessage:
    """One rendered invitation, in both the parts a mail client may show."""

    subject: str
    text: str
    html: str


def build_invitation_message(
    *,
    app_name: str,
    inviter: str | None,
    activation_link: str,
    expires_in_days: int,
) -> InvitationMessage:
    """Render the invitation. Every value here is supplied, never AI-written."""
    who = f"{inviter} has invited you" if inviter else "You have been invited"
    subject = f"Your invitation to {app_name}"
    text = (
        f"{who} to {app_name}.\n\n"
        f"Choose a password to activate your account:\n{activation_link}\n\n"
        f"This link expires in {expires_in_days} days. "
        "If you were not expecting this invitation, you can ignore this message."
    )
    html = (
        f"<p>{who} to {app_name}.</p>"
        f'<p><a href="{activation_link}">Choose a password to activate your account</a></p>'
        f"<p>This link expires in {expires_in_days} days. "
        "If you were not expecting this invitation, you can ignore this message.</p>"
    )
    return InvitationMessage(subject=subject, text=text, html=html)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd backend && uv run pytest tests/test_invitation_email.py -q`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add backend/src/mist_config_guardian_backend/services/invitation_email.py backend/tests/test_invitation_email.py
git commit -m "Render the invitation message with a fragment-borne activation link"
```

---

### Task 8: Deliver the invitation and apply the delivery rule

**Files:**
- Modify: `backend/src/mist_config_guardian_backend/schemas/users.py:59-68` (`UserInviteResponse`)
- Modify: `backend/src/mist_config_guardian_backend/api/routes/users.py:40-51` (`_invitation_response`), `97-136` (both endpoints)
- Test: `backend/tests/test_invitation_delivery.py` (create)

**Interfaces:**
- Consumes: Tasks 1, 3, 4, 6, 7.
- Produces: `UserInviteResponse` with `delivery: Literal["sent","uncertain","not_configured","failed"]`, `invitation_token: str | None`, `invitation_url: str | None`, `delivery_detail: str | None`.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_invitation_delivery.py`. Read `backend/tests/test_users_api.py` for the administrator client fixture and reuse it; override the mail sender dependency with a fake per test.

```python
"""The delivery rule: the credential is returned unless acceptance was observed."""

import pytest

from mist_config_guardian_backend.integrations.smtp import SendOutcome


class FakeSender:
    """A MailSender returning a fixed outcome."""

    def __init__(self, outcome: SendOutcome) -> None:
        self.outcome = outcome
        self.calls: list[dict[str, str]] = []

    async def send(self, *, to: str, subject: str, text: str, html: str) -> SendOutcome:
        self.calls.append({"to": to, "subject": subject, "text": text, "html": html})
        return self.outcome


async def test_an_accepted_send_withholds_the_credential(admin_client, use_sender) -> None:
    use_sender(FakeSender(SendOutcome("sent")))

    body = (await admin_client.post("/api/v1/users", json={
        "email": "a@example.com", "display_name": "A", "role": "viewer",
    })).json()

    assert body["delivery"] == "sent"
    assert body["invitation_token"] is None
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

    body = (await admin_client.post("/api/v1/users", json={
        "email": "b@example.com", "display_name": "B", "role": "viewer",
    })).json()

    assert body["delivery"] == expected
    assert body["invitation_token"]
    assert body["delivery_detail"] == outcome.detail
    assert body["invitation_url"].endswith(f"#token={body['invitation_token']}")


async def test_disabled_email_returns_the_credential(admin_client, use_sender) -> None:
    use_sender(None)

    body = (await admin_client.post("/api/v1/users", json={
        "email": "c@example.com", "display_name": "C", "role": "viewer",
    })).json()

    assert body["delivery"] == "not_configured"
    assert body["invitation_token"]


async def test_a_sender_that_raises_is_uncertain_not_failed(admin_client, use_sender) -> None:
    """An unexpected escape cannot rule out that the body was written."""

    class Exploding:
        async def send(self, **_kwargs: str) -> SendOutcome:
            raise RuntimeError("bug")

    use_sender(Exploding())

    body = (await admin_client.post("/api/v1/users", json={
        "email": "d@example.com", "display_name": "D", "role": "viewer",
    })).json()

    assert body["delivery"] == "uncertain"
    assert body["invitation_token"]


async def test_production_is_no_longer_a_special_case(admin_client_production, use_sender) -> None:
    use_sender(None)

    body = (await admin_client_production.post("/api/v1/users", json={
        "email": "e@example.com", "display_name": "E", "role": "viewer",
    })).json()

    assert body["invitation_token"], "production withheld the credential with no email to carry it"


async def test_a_second_resend_inside_the_window_is_refused(admin_client, use_sender) -> None:
    use_sender(FakeSender(SendOutcome("sent")))
    user_id = (await admin_client.post("/api/v1/users", json={
        "email": "f@example.com", "display_name": "F", "role": "viewer",
    })).json()["user"]["id"]

    first = await admin_client.post(f"/api/v1/users/{user_id}/resend-invitation")
    second = await admin_client.post(f"/api/v1/users/{user_id}/resend-invitation")

    assert first.status_code == 200
    assert second.status_code == 429


async def test_a_refused_resend_does_not_rotate_the_token(admin_client, use_sender) -> None:
    """Rotating then refusing would invalidate a token still in flight."""
    use_sender(None)
    created = (await admin_client.post("/api/v1/users", json={
        "email": "g@example.com", "display_name": "G", "role": "viewer",
    })).json()
    user_id = created["user"]["id"]
    await admin_client.post(f"/api/v1/users/{user_id}/resend-invitation")
    refused = await admin_client.post(f"/api/v1/users/{user_id}/resend-invitation")

    assert refused.status_code == 429
    accepted = await admin_client.post("/api/v1/users/accept-invitation", json={
        "token": created["invitation_token"], "password": "a-long-enough-password",
    })
    assert accepted.status_code in {200, 400}, "the refused resend must not have changed the stored hash"


async def test_the_token_is_not_logged(admin_client, use_sender, caplog) -> None:
    use_sender(FakeSender(SendOutcome("sent")))

    body = (await admin_client.post("/api/v1/users", json={
        "email": "h@example.com", "display_name": "H", "role": "viewer",
    })).json()

    sender_calls = use_sender.last.calls
    token_in_message = sender_calls[0]["text"]
    assert "token=" in token_in_message
    assert not any("token=" in record.getMessage() for record in caplog.records)
```

Write the `use_sender` fixture in this file. It overrides a FastAPI dependency `get_mail_sender` with a callable returning the fake (or `None` for disabled), and records the last fake on `use_sender.last`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd backend && uv run pytest tests/test_invitation_delivery.py -q`
Expected: FAIL — `get_mail_sender` does not exist and `delivery` is still the literal `"not_implemented"`.

- [ ] **Step 3: Update the response schema**

In `schemas/users.py`, replace `UserInviteResponse`:

```python
class UserInviteResponse(BaseModel):
    """A created invitation and what became of it.

    ``invitation_token`` and ``invitation_url`` are populated unless positive
    SMTP acceptance was observed. "Email did not carry it" is not observable —
    a server can queue a message while the client times out before reading the
    reply — so the rule is one-directional and errs towards giving the
    administrator something to pass on.
    """

    user: UserSummaryResponse
    invitation_expires_at: datetime | None
    delivery: Literal["sent", "uncertain", "not_configured", "failed"]
    invitation_token: str | None = None
    invitation_url: str | None = None
    delivery_detail: str | None = None
```

- [ ] **Step 4: Implement the delivery helper and the dependency**

In `api/routes/users.py`, replace `_invitation_response` and add the sender dependency:

```python
logger = logging.getLogger(__name__)


async def get_mail_sender(
    service: Annotated[ApplicationConfigurationService, Depends(get_application_configuration_service)],
) -> MailSender | None:
    """Build a sender from the stored settings, or ``None`` when email is off."""
    credentials = await service.smtp_credentials()
    return SmtpMailSender(credentials) if credentials is not None else None


async def _deliver(
    user: User,
    token: str,
    settings: Settings,
    sender: MailSender | None,
    inviter: str | None,
) -> UserInviteResponse:
    """Send the invitation and apply the delivery rule to what happened."""
    base_url = settings.public_base_url
    link = activation_url(base_url, token) if base_url else None
    status_value = "not_configured"
    detail: str | None = None
    if sender is not None and link is not None:
        message = build_invitation_message(
            app_name=settings.app_name,
            inviter=inviter,
            activation_link=link,
            expires_in_days=INVITATION_LIFETIME_DAYS,
        )
        try:
            outcome = await sender.send(
                to=user.email, subject=message.subject, text=message.text, html=message.html
            )
        except Exception:
            # A sender that raises is a bug, not a delivery problem, and an
            # unexpected escape cannot rule out that the body was written.
            logger.exception("Invitation sender failed for %s", user.email)
            outcome = SendOutcome("uncertain", "The mail transport failed unexpectedly.")
        status_value, detail = outcome.status, (outcome.detail or None)
    logger.info("Invitation for %s: %s", user.email, status_value)
    delivered = status_value == "sent"
    return UserInviteResponse(
        user=UserSummaryResponse.from_document(user),
        invitation_expires_at=user.invitation_expires_at,
        delivery=status_value,
        invitation_token=None if delivered else token,
        invitation_url=None if delivered else link,
        delivery_detail=detail,
    )
```

The `environment` check is deleted entirely. Do not reintroduce it.

- [ ] **Step 5: Wire both endpoints**

`invite_user` gains `throttle` and `sender` dependencies, and reserves the sender scope **before** creating anything:

```python
    await reserve_or_raise(throttle, throttle.invitation_sender(administrator.id))
    try:
        user, token = await users.invite(...)
    except UserAlreadyExistsError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return await _deliver(user, token, settings, sender, administrator.display_name)
```

`resend_invitation` reserves **both** scopes before rotating:

```python
    await reserve_or_raise(
        throttle,
        throttle.invitation_sender(administrator.id),
        throttle.invitation_target(user_id),
    )
    try:
        user, token = await users.resend_invitation(user_id)
    except UserNotFoundError as exc:
        raise _not_found(exc) from exc
    except InvitationError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return await _deliver(user, token, settings, sender, administrator.display_name)
```

`resend_invitation` needs `administrator: Annotated[User, Depends(require_administrator)]` if it does not already have it.

- [ ] **Step 6: Run the tests, regenerate the contract, commit**

Run: `cd backend && uv run pytest tests/test_invitation_delivery.py tests/test_users_api.py -q`
Expected: PASS. Existing `test_users_api.py` assertions about `invitation_token` in production will need updating to the new rule — update them, do not weaken them.

Run from the repository root: `make openapi && make check`

```bash
git add backend/src/mist_config_guardian_backend/api/routes/users.py \
        backend/src/mist_config_guardian_backend/schemas/users.py \
        backend/tests/test_invitation_delivery.py backend/tests/test_users_api.py docs/openapi.json
git commit -m "Deliver invitations by email and return the credential when it was not carried"
```

---

### Task 9: The accept-invitation page

**Files:**
- Create: `frontend/src/app/features/auth/accept-invitation-page.ts`, `.html`, `.spec.ts`
- Modify: `frontend/src/app/app.routes.ts` — add before the `**` entry, with no `authGuard`
- Modify: `frontend/src/app/features/settings/users.service.ts` — add `acceptInvitation`

**Interfaces:**
- Consumes: Task 7's URL shape `/accept-invitation#token=<token>`.
- Produces: route `accept-invitation`; `UsersService.acceptInvitation(token: string, password: string): Promise<void>`.

- [ ] **Step 1: Write the failing test**

Create `frontend/src/app/features/auth/accept-invitation-page.spec.ts`. Read an existing page spec such as `login-page.spec.ts` for the TestBed setup and copy it.

```typescript
import { ActivatedRoute } from '@angular/router';
import { of } from 'rxjs';

describe('AcceptInvitationPage', () => {
  it('reads the token from the fragment', async () => {
    const page = await render({ fragment: 'token=abc123' });
    expect(page.component.hasToken()).toBe(true);
  });

  it('clears the token from the address bar on load', async () => {
    const replaceState = vi.spyOn(history, 'replaceState');
    await render({ fragment: 'token=abc123' });
    expect(replaceState).toHaveBeenCalled();
  });

  it('shows the failure message when there is no fragment', async () => {
    const page = await render({ fragment: null });
    expect(page.component.hasToken()).toBe(false);
    expect(page.text()).toContain('invalid or has expired');
  });

  it('refuses a mismatched confirmation without calling the API', async () => {
    const page = await render({ fragment: 'token=abc123' });
    page.fill({ password: 'a-long-enough-password', confirm: 'something-else' });
    await page.submit();
    expect(page.users.acceptInvitation).not.toHaveBeenCalled();
  });

  it('submits the token in the body and redirects to login', async () => {
    const page = await render({ fragment: 'token=abc123' });
    page.fill({ password: 'a-long-enough-password', confirm: 'a-long-enough-password' });
    await page.submit();
    expect(page.users.acceptInvitation).toHaveBeenCalledWith('abc123', 'a-long-enough-password');
    expect(page.router.navigate).toHaveBeenCalledWith(['/login']);
  });
});
```

Write `render` in the spec, providing `ActivatedRoute` with `{ fragment: of(fragment) }`, a mocked `UsersService`, and a mocked `Router`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd frontend && npm test -- accept-invitation`
Expected: FAIL — the component does not exist.

- [ ] **Step 3: Implement the component**

Create `accept-invitation-page.ts` as a standalone component using signals and `ReactiveFormsModule`, matching the style of `login-page.ts` (read it first). It must:

- read `route.fragment` once, parse it with `new URLSearchParams(fragment ?? '')`, and take `token`;
- call `history.replaceState(null, '', location.pathname)` immediately so the token does not persist in browser history;
- expose `hasToken()`;
- show the text `This invitation is invalid or has expired.` when there is no token, and render no form;
- validate that password and confirmation match before calling the service;
- call `users.acceptInvitation(token, password)` then `router.navigate(['/login'])`;
- render the same indistinct failure message for any API error.

Add to `users.service.ts`:

```typescript
  async acceptInvitation(token: string, password: string): Promise<void> {
    await firstValueFrom(
      this.http.post<void>(`${API_ROOT}/users/accept-invitation`, { token, password }),
    );
  }
```

- [ ] **Step 4: Add the route**

In `app.routes.ts`, immediately before `{ path: '**', redirectTo: '' }`:

```typescript
  {
    // Unauthenticated by design: the invitation token is the credential, and
    // the invitee has no account to sign in with yet. It must precede the
    // wildcard, which would otherwise redirect it to the dashboard.
    path: 'accept-invitation',
    loadComponent: () =>
      import('./features/auth/accept-invitation-page').then((m) => m.AcceptInvitationPage),
    title: 'Accept invitation · Config Guardian',
  },
```

- [ ] **Step 5: Run the tests and commit**

Run: `cd frontend && npm test -- accept-invitation`
Expected: PASS, 5 tests.

```bash
git add frontend/src/app/features/auth/accept-invitation-page.ts \
        frontend/src/app/features/auth/accept-invitation-page.html \
        frontend/src/app/features/auth/accept-invitation-page.spec.ts \
        frontend/src/app/app.routes.ts frontend/src/app/features/settings/users.service.ts
git commit -m "Add the page that accepts an invitation"
```

---

### Task 10: Hand the administrator a usable link

**Files:**
- Modify: `frontend/src/app/features/settings/users.service.ts:36-42` (`UserInviteResult`)
- Modify: `frontend/src/app/features/settings/users-tab.ts:45,103-136`
- Modify: `frontend/src/app/features/settings/users-tab.html:18-27,54`
- Test: `frontend/src/app/features/settings/users-tab.spec.ts`

**Interfaces:**
- Consumes: Task 8's response fields; Task 7's URL shape.
- Produces: nothing later tasks depend on.

- [ ] **Step 1: Write the failing test**

Add to `users-tab.spec.ts` (create it if absent, copying the TestBed setup from a sibling tab spec):

```typescript
it('shows the backend link when one is returned', async () => {
  const page = await render();
  page.users.invite.mockResolvedValue({
    user: { email: 'a@example.com' },
    delivery: 'not_configured',
    invitation_token: 'abc',
    invitation_url: 'https://guardian.example.com/accept-invitation#token=abc',
    delivery_detail: null,
  });
  await page.invite();
  expect(page.text()).toContain('https://guardian.example.com/accept-invitation#token=abc');
});

it('builds a link from the document base when the backend could not', async () => {
  const page = await render();
  page.users.invite.mockResolvedValue({
    user: { email: 'a@example.com' },
    delivery: 'not_configured',
    invitation_token: 'abc',
    invitation_url: null,
    delivery_detail: null,
  });
  await page.invite();
  expect(page.text()).toContain(`${document.baseURI.replace(/\/$/, '')}/accept-invitation#token=abc`);
});

it('never shows a bare token with no link', async () => {
  const page = await render();
  page.users.invite.mockResolvedValue({
    user: { email: 'a@example.com' },
    delivery: 'failed',
    invitation_token: 'abc',
    invitation_url: null,
    delivery_detail: 'The server refused the message',
  });
  await page.invite();
  expect(page.text()).toContain('/accept-invitation#token=abc');
});

it('shows no link at all when the invitation was emailed', async () => {
  const page = await render();
  page.users.invite.mockResolvedValue({
    user: { email: 'a@example.com' },
    delivery: 'sent',
    invitation_token: null,
    invitation_url: null,
    delivery_detail: null,
  });
  await page.invite();
  expect(page.text()).toContain('Invitation emailed to a@example.com');
  expect(page.text()).not.toContain('accept-invitation#');
});

it('names the failure reason', async () => {
  const page = await render();
  page.users.invite.mockResolvedValue({
    user: { email: 'a@example.com' },
    delivery: 'failed',
    invitation_token: 'abc',
    invitation_url: 'https://g.example.com/accept-invitation#token=abc',
    delivery_detail: 'The server refused the message',
  });
  await page.invite();
  expect(page.text()).toContain('The server refused the message');
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd frontend && npm test -- users-tab`
Expected: FAIL — the component has no `invitation_url` handling.

- [ ] **Step 3: Update the service types**

In `users.service.ts`:

```typescript
export type InvitationDelivery = 'sent' | 'uncertain' | 'not_configured' | 'failed';

export interface UserInviteResult {
  user: ManagedUser;
  invitation_expires_at: string | null;
  delivery: InvitationDelivery;
  invitation_token: string | null;
  invitation_url: string | null;
  delivery_detail: string | null;
}
```

- [ ] **Step 4: Implement the link and the messages**

In `users-tab.ts`, replace the `invitationToken` signal with:

```typescript
  protected readonly invitationLink = signal<{ email: string; url: string } | null>(null);
```

Add:

```typescript
  /** The link to hand over, preferring the canonical one the backend built. */
  private activationLink(result: UserInviteResult): string | null {
    if (result.invitation_url) {
      return result.invitation_url;
    }
    if (!result.invitation_token) {
      return null;
    }
    // The backend could not resolve a canonical origin. This is display only,
    // for an administrator already on this origin: the server neither reads
    // nor sends it, and it is unreachable whenever an email was attempted.
    return `${document.baseURI.replace(/\/$/, '')}/accept-invitation#token=${encodeURIComponent(
      result.invitation_token,
    )}`;
  }

  private deliveryNotice(result: UserInviteResult): string {
    const email = result.user.email;
    switch (result.delivery) {
      case 'sent':
        return `Invitation emailed to ${email}.`;
      case 'uncertain':
        return `Sent to ${email}, but the mail server did not confirm. Share this link if it does not arrive.`;
      case 'not_configured':
        return `No SMTP server is configured, so no email was sent. Share this link with ${email}.`;
      case 'failed':
        return `Email to ${email} failed: ${result.delivery_detail ?? 'unknown error'}. Share this link instead.`;
    }
  }
```

Use both in `invite()` and `resend()`, setting `invitationLink` from `activationLink(result)` and `notice` from `deliveryNotice(result)`.

In `users-tab.html`, replace the token block at lines 18-27 to render `invitationLink()` as a selectable link with a copy button, and change the submit button label at line 54 from `Send invitation` to `Invite user` — the button no longer promises delivery it cannot guarantee.

- [ ] **Step 5: Run the tests and commit**

Run: `cd frontend && npm test -- users-tab`
Expected: PASS.

```bash
git add frontend/src/app/features/settings/users.service.ts \
        frontend/src/app/features/settings/users-tab.ts \
        frontend/src/app/features/settings/users-tab.html \
        frontend/src/app/features/settings/users-tab.spec.ts
git commit -m "Hand the administrator a complete activation link"
```

---

### Task 11: The email settings tab

**Files:**
- Create: `frontend/src/app/features/settings/email-tab.ts`, `.html`, `.spec.ts`
- Create: `frontend/src/app/features/settings/smtp.service.ts`
- Modify: `frontend/src/app/features/settings/settings-page.ts:21-31,116` — add `'email'` to `SettingsTab`, `SETTINGS_TABS`, `LABELS`, and `imports`
- Modify: `frontend/src/app/features/settings/settings-page.html` — render the panel

**Interfaces:**
- Consumes: Task 5's three endpoints.
- Produces: nothing later tasks depend on.

- [ ] **Step 1: Write the failing test**

Create `email-tab.spec.ts`, copying the TestBed setup from `ai-tab.spec.ts`:

```typescript
it('is one of the settings tabs', () => {
  expect(SETTINGS_TABS).toContain('email');
});

it('loads and shows the stored settings', async () => {
  const page = await render({ enabled: true, host: 'mail.example.com', port: 587, security: 'starttls' });
  expect(page.text()).toContain('mail.example.com');
});

it('shows the last test outcome', async () => {
  const page = await render({ last_test_ok: false, last_test_detail: 'Connection refused' });
  expect(page.text()).toContain('Connection refused');
});

it('surfaces a rejected configuration', async () => {
  const page = await render({});
  page.smtp.update.mockRejectedValue({ error: { detail: 'An SMTP host is required to enable email' } });
  await page.save();
  expect(page.text()).toContain('An SMTP host is required to enable email');
});

it('does not send the password back when it was left blank', async () => {
  const page = await render({ password_set: true, password_last_four: '**r2' });
  await page.save();
  expect(page.smtp.update.mock.calls[0][0].password).toBeUndefined();
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd frontend && npm test -- email-tab`
Expected: FAIL — the component does not exist.

- [ ] **Step 3: Implement**

Create `smtp.service.ts` with `get()`, `update(request)`, and `test()` calling the three endpoints from Task 5, following `users.service.ts` for style.

Create `email-tab.ts` / `.html` modelled on `ai-tab.ts` / `.html` (read them first): a form for enabled, host, port, security, username, password, from address, from name; a Save button; a Test connection button showing `last_test_ok` and `last_test_detail`; and a hint that the password is write-only, showing `password_last_four` when set. Leave the password control empty on load so a blank submission leaves the stored one untouched.

In `settings-page.ts`:

```typescript
export type SettingsTab = 'organizations' | 'users' | 'ai' | 'email' | 'health';

export const SETTINGS_TABS: readonly SettingsTab[] = ['organizations', 'users', 'ai', 'email', 'health'];
```

Add `email: 'Email'` to `LABELS`, `EmailTab` to `imports`, and the panel to `settings-page.html` beside the others.

- [ ] **Step 4: Run the tests and commit**

Run: `cd frontend && npm test -- email-tab settings-page`
Expected: PASS.

```bash
git add frontend/src/app/features/settings/email-tab.ts \
        frontend/src/app/features/settings/email-tab.html \
        frontend/src/app/features/settings/email-tab.spec.ts \
        frontend/src/app/features/settings/smtp.service.ts \
        frontend/src/app/features/settings/settings-page.ts \
        frontend/src/app/features/settings/settings-page.html
git commit -m "Add the email settings tab"
```

---

### Task 12: Verify the whole flow and record the upgrade note

**Files:**
- Modify: `README.md` or the release notes the repository keeps — find with `ls docs/` and `git log --oneline --name-only -5 -- docs/`

- [ ] **Step 1: Run the full verification**

Run from the repository root: `make check`
Expected: every backend test, `ruff`, `ty`, the OpenAPI contract check, and the frontend build and tests pass.

- [ ] **Step 2: Exercise it end to end**

Start the stack, set `PUBLIC_BASE_URL=http://localhost:4200` in `.env` (the development default lists two CORS origins, so it will not resolve without this), leave SMTP disabled, invite a user, follow the link the UI shows, set a password, and sign in as that user.

- [ ] **Step 3: Record the upgrade note**

Note that a production deployment whose resolved `public_base_url` is `http` will now refuse to start. This surfaces an existing misconfiguration — `session_cookie_secure` is already forced true in production, so such a deployment could never hold a session — but it is a behaviour change on upgrade.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "Note the https requirement for production deployments"
```

---

## Self-Review

**Spec coverage.** Delivery rule and all four outcomes — Task 8. Interrupted-request recovery via resend — Task 8. SMTP configuration mirroring Impact AI — Tasks 2, 4, 5. Public base URL with derivation, multi-origin refusal, override validation, and the production https rule — Task 1. Transport with verified TLS and phase classification — Task 3. Plaintext constraints including the strict literal-loopback check — Task 4. Inline sending — Task 8. Email content — Task 7. Fragment-borne token — Tasks 7 and 9. Manual delivery with `invitation_url`, `delivery_detail`, per-outcome messages, and the `document.baseURI` fallback — Tasks 8 and 10. Accept-invitation page — Task 9. `SETTINGS_TABS` — backend in Task 5, frontend in Task 11. Throttling on both endpoints with reservation before rotation — Tasks 6 and 8. OpenAPI regeneration — Tasks 5 and 8.

**Placeholders.** None. Every code step carries the code. Task 9's component and Task 11's tab give behavioural requirements plus a named sibling file to copy the style from, rather than a full listing, because both are conventional Angular forms whose shape is set by files already in the repository.

**Type consistency.** `SendOutcome(status, detail)` is produced in Task 3 and consumed in Task 8 under the same name. `SmtpCredentials` is defined in Task 3, built in Task 4's `smtp_credentials()`, and consumed by `SmtpMailSender` and `_probe_smtp`. `activation_url(base_url, token)` is defined in Task 7 and used in Task 8. `Scope.window` is added in Task 6 and used only there. `UserInviteResult` in Task 10 matches `UserInviteResponse` in Task 8 field for field.
