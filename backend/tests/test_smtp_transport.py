"""The SMTP transport classifies its own outcome by protocol phase."""

import smtplib
import ssl
from typing import ClassVar

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

TLS_CREDENTIALS = SmtpCredentials(
    host="mail.example.com",
    port=465,
    security="tls",
    username="postmaster",
    password="hunter2",
    from_address="guardian@example.com",
    from_name="Config Guardian",
)

_SUBJECT = "Your invitation to Config Guardian"
_TEXT_BODY = "UNIQUE-BODY-MARKER-9471"
_HTML_BODY = "<p>UNIQUE-BODY-MARKER-9471</p>"


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

    def login(self, _username: str, _password: str) -> None:
        self._maybe("login")

    def send_message(self, _message: object) -> dict[str, object]:
        self._maybe("send")
        self.sent = True
        return {}

    def quit(self) -> None:
        return None


async def _send(sender: SmtpMailSender) -> SendOutcome:
    return await sender.send(to="invitee@example.com", subject=_SUBJECT, text=_TEXT_BODY, html=_HTML_BODY)


def test_the_verified_context_checks_certificates_and_hostnames() -> None:
    """smtplib's own default disables both, which encrypts to any interceptor."""
    context = verified_context()

    assert context.check_hostname is True
    assert context.verify_mode is ssl.CERT_REQUIRED


async def test_a_clean_send_is_sent() -> None:
    client = FakeSmtp()
    sender = SmtpMailSender(CREDENTIALS, client_factory=lambda: client)

    outcome = await _send(sender)

    assert outcome.status == "sent"
    assert client.sent


async def test_starttls_uses_a_verified_context() -> None:
    client = FakeSmtp()
    sender = SmtpMailSender(CREDENTIALS, client_factory=lambda: client)

    await _send(sender)

    assert client.contexts
    assert client.contexts[0].verify_mode is ssl.CERT_REQUIRED
    assert client.contexts[0].check_hostname is True


class _RecordingSmtpSsl:
    """Stands in for ``smtplib.SMTP_SSL``, recording the ``context`` it is built with.

    Unlike ``FakeSmtp`` (injected via ``client_factory``), this replaces the
    real class that ``_connect()`` calls for ``security="tls"``, so it is the
    only thing that exercises the ``context=`` argument passed to
    ``smtplib.SMTP_SSL`` itself.
    """

    instances: ClassVar[list["_RecordingSmtpSsl"]] = []

    def __init__(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        context: ssl.SSLContext | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.context = context
        type(self).instances.append(self)

    def login(self, _username: str, _password: str) -> None:
        return None

    def send_message(self, _message: object) -> dict[str, object]:
        return {}

    def quit(self) -> None:
        return None


async def test_tls_security_connects_with_a_verified_context(monkeypatch: pytest.MonkeyPatch) -> None:
    """``SMTP_SSL``'s own default context has ``check_hostname=False``; this must override it.

    No other test here uses ``security="tls"`` or leaves ``client_factory``
    unset, so without this test ``context=verified_context()`` could be
    deleted from the ``SMTP_SSL(...)`` call in ``_connect()`` and nothing
    would fail.
    """
    _RecordingSmtpSsl.instances = []
    monkeypatch.setattr(smtplib, "SMTP_SSL", _RecordingSmtpSsl)
    sender = SmtpMailSender(TLS_CREDENTIALS)

    outcome = await _send(sender)

    assert outcome.status == "sent"
    assert _RecordingSmtpSsl.instances
    context = _RecordingSmtpSsl.instances[0].context
    assert context is not None
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True


@pytest.mark.parametrize("phase", ["starttls", "login"])
async def test_an_error_before_the_body_is_written_is_failed(phase: str) -> None:
    client = FakeSmtp(raise_at=phase)
    sender = SmtpMailSender(CREDENTIALS, client_factory=lambda: client)

    outcome = await _send(sender)

    assert outcome.status == "failed"
    assert not client.sent


def _refusal() -> Exception:
    return smtplib.SMTPRecipientsRefused({"invitee@example.com": (550, b"no such user")})


@pytest.mark.parametrize(
    "error",
    [
        smtplib.SMTPRecipientsRefused({"invitee@example.com": (550, b"no such user")}),
        smtplib.SMTPSenderRefused(550, b"sender refused", "guardian@example.com"),
        smtplib.SMTPDataError(451, b"data error"),
        smtplib.SMTPNotSupportedError("not supported"),
    ],
)
async def test_a_refusal_read_back_from_the_server_is_failed(error: Exception) -> None:
    """Every member of ``_REFUSALS`` is a confirmed reply, not a lost connection."""
    client = FakeSmtp(raise_at="send", error=error)
    sender = SmtpMailSender(CREDENTIALS, client_factory=lambda: client)

    assert (await _send(sender)).status == "failed"


async def test_a_server_that_does_not_offer_starttls_is_failed() -> None:
    """The send is never retried in the clear."""
    client = FakeSmtp(raise_at="starttls", error=smtplib.SMTPNotSupportedError("no starttls"))
    sender = SmtpMailSender(CREDENTIALS, client_factory=lambda: client)

    assert (await _send(sender)).status == "failed"


async def test_a_login_failure_never_echoes_the_servers_reply() -> None:
    """A hostile or buggy server can echo the AUTH line back in a 535 reply.

    That reply is exception text this module must never interpolate into
    ``detail`` on the login path: ``detail`` is persisted (Task 5 stores it
    as ``smtp_last_test_detail``), and a base64-encoded credential landing in
    a database column is exactly what ``verified_context`` exists to prevent
    on the wire.
    """
    credential_shaped = "cG9zdG1hc3RlcjpodW50ZXIy"  # base64("postmaster:hunter2")
    error = smtplib.SMTPAuthenticationError(535, credential_shaped.encode())
    client = FakeSmtp(raise_at="login", error=error)
    sender = SmtpMailSender(CREDENTIALS, client_factory=lambda: client)

    outcome = await _send(sender)

    assert outcome.status == "failed"
    assert credential_shaped not in outcome.detail
    assert outcome.detail == "Authentication was rejected by the server."


@pytest.mark.parametrize(
    "error",
    [TimeoutError("timed out"), smtplib.SMTPServerDisconnected("gone")],
)
async def test_losing_the_connection_while_sending_is_uncertain(error: Exception) -> None:
    """The body may have been written and queued with the reply unread."""
    client = FakeSmtp(raise_at="send", error=error)
    sender = SmtpMailSender(CREDENTIALS, client_factory=lambda: client)

    assert (await _send(sender)).status == "uncertain"


async def test_an_undeterminable_envelope_while_sending_is_uncertain() -> None:
    """``send_message`` documents raising bare ``ValueError`` for a bad envelope.

    That must be reported like any other mid-send failure, not escape
    ``send()`` and break the "reports rather than raises" contract.
    """
    client = FakeSmtp(raise_at="send", error=ValueError("Invalid Resent- headers"))
    sender = SmtpMailSender(CREDENTIALS, client_factory=lambda: client)

    assert (await _send(sender)).status == "uncertain"


async def test_the_detail_never_carries_the_message_body() -> None:
    """A refusal's detail may quote the server's reply, never our own body text."""
    client = FakeSmtp(raise_at="send", error=_refusal())
    sender = SmtpMailSender(CREDENTIALS, client_factory=lambda: client)

    outcome = await _send(sender)

    assert _TEXT_BODY not in outcome.detail
    assert len(outcome.detail) <= 200
