"""Outbound SMTP with verified TLS and phase-aware outcome classification.

The transport reports what happened rather than raising, because only this
layer knows which protocol phase failed. An ``SMTPException`` seen from
outside does not say whether the message body reached the server, and a caller
forced to guess would call a queued message a failure.
"""

import asyncio
import contextlib
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

# Everything this module treats as "the operation did not complete as asked"
# rather than letting it escape ``send()``. ``send_message`` documents raising
# a bare ``ValueError`` for an undeterminable envelope (no from/to address, or
# repeated ``Resent-`` blocks); without it here that ``ValueError`` would break
# the "reports rather than raises" contract this module exists to uphold.
_TRANSPORT_ERRORS = (OSError, smtplib.SMTPException, ValueError)


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
        """Store the credentials and connection settings for later sends.

        ``client_factory`` exists so tests can substitute a fake SMTP client
        without opening a socket; production code leaves it unset and gets a
        real connection built from ``credentials``.
        """
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
        except _TRANSPORT_ERRORS as exc:
            return SendOutcome("failed", _truncate(f"Could not connect: {exc}"))
        if credentials.security == "starttls":
            try:
                client.starttls(context=verified_context())
            except _TRANSPORT_ERRORS as exc:
                # Nothing was written, so nothing can have been queued. STARTTLS
                # carries no credential, so the server's own text is safe to show.
                self._close(client)
                return SendOutcome("failed", _truncate(f"Could not negotiate a session: {exc}"))
        if credentials.username:
            try:
                client.login(credentials.username, credentials.password)
            except _TRANSPORT_ERRORS:
                # A hostile or buggy server can echo the AUTH line back in its
                # reply. Never interpolate it: a base64-encoded credential in
                # this detail would be persisted (Task 5 stores it verbatim).
                self._close(client)
                return SendOutcome("failed", "Authentication was rejected by the server.")
        try:
            client.send_message(message)
        except _REFUSALS as exc:
            self._close(client)
            return SendOutcome("failed", _truncate(f"The server refused the message: {exc}"))
        except _TRANSPORT_ERRORS as exc:
            # The body may have been written and queued with the reply unread.
            self._close(client)
            return SendOutcome("uncertain", _truncate(f"No confirmation was received: {exc}"))
        self._close(client)
        return SendOutcome("sent")

    @staticmethod
    def _close(client: smtplib.SMTP) -> None:
        # The message's fate is already decided; a failed teardown is noise.
        with contextlib.suppress(OSError, smtplib.SMTPException):
            client.quit()
