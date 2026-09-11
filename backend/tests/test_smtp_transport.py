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
    """A refusal's detail may quote the server's reply, never our own body text."""
    client = FakeSmtp(raise_at="send", error=_refusal())
    sender = SmtpMailSender(CREDENTIALS, client_factory=lambda: client)

    outcome = await _send(sender)

    assert _TEXT_BODY not in outcome.detail
    assert len(outcome.detail) <= 200
