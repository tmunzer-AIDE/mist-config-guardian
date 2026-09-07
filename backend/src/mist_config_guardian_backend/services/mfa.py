"""Second-factor enrollment, verification, and step-up authorization.

``require_fresh_mfa`` is the reusable dependency other workstreams import to
gate a sensitive action, such as restore execution, behind a recent step-up.

Note for maintainers: this module imports ``api.dependencies``. Do not import
it from ``api/dependencies.py`` or the import graph becomes circular.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Protocol

import jwt
from beanie import PydanticObjectId
from beanie.odm.operators.update.general import Set
from fastapi import Depends, HTTPException, Request, status
from jwt import InvalidTokenError

from mist_config_guardian_backend.api.dependencies import (
    get_credential_vault,
    get_session_service,
    require_viewer,
)
from mist_config_guardian_backend.config import Settings, get_settings
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.challenge import PendingTotpEnrollment
from mist_config_guardian_backend.models.user import TotpEnrollment, User
from mist_config_guardian_backend.security.auth import verify_password
from mist_config_guardian_backend.security.credentials import CredentialDecryptionError, CredentialVault
from mist_config_guardian_backend.security.totp import (
    RECOVERY_CODE_COUNT,
    consume_recovery_code,
    generate_recovery_codes,
    generate_totp_secret,
    hash_recovery_code,
    totp_provisioning_uri,
    totp_qr_svg,
    verify_totp,
)
from mist_config_guardian_backend.services.sessions import SessionService
from mist_config_guardian_backend.services.users import InvalidPasswordError

MFA_CHALLENGE_AUDIENCE = "mfa-challenge"
PASSKEY_CHALLENGE_AUDIENCE = "webauthn-challenge"
MFA_CHALLENGE_LIFETIME_MINUTES = 5
PASSKEY_CHALLENGE_LIFETIME_MINUTES = 5
TOTP_SECRET_CONTEXT = "totp-secret"  # noqa: S105 - an encryption context label, not a secret
PENDING_ENROLLMENT_LIFETIME_MINUTES = 15

_ISSUER = "mist-config-guardian"
_ALGORITHM = "HS256"


class ChallengeTokenError(ValueError):
    """Raised when a short-lived challenge token is missing, stale, or forged."""


class MfaError(ValueError):
    """Raised when a second-factor operation cannot be completed."""


class TotpAlreadyEnrolledError(MfaError):
    """Raised when an account already completed TOTP enrollment."""


class TotpNotEnrolledError(MfaError):
    """Raised when an account has not completed TOTP enrollment."""


class PendingEnrollmentError(MfaError):
    """Raised when no unconfirmed TOTP enrollment is waiting."""


class InvalidMfaCodeError(MfaError):
    """Raised when a submitted second-factor code is not accepted."""


def issue_challenge_token(
    subject: str,
    *,
    settings: Settings,
    audience: str,
    lifetime_minutes: int,
) -> str:
    """Sign a short-lived, audience-bound token carrying a challenge subject."""
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "sub": subject,
            "iss": _ISSUER,
            "aud": audience,
            "iat": now,
            "exp": now + timedelta(minutes=lifetime_minutes),
        },
        settings.secret_key.get_secret_value(),
        algorithm=_ALGORITHM,
    )


def read_challenge_token(token: str, *, settings: Settings, audience: str) -> str:
    """Validate a challenge token and return the subject it carries."""
    try:
        payload = jwt.decode(
            token,
            settings.secret_key.get_secret_value(),
            algorithms=[_ALGORITHM],
            audience=audience,
            issuer=_ISSUER,
        )
        subject = payload["sub"]
    except (InvalidTokenError, KeyError, TypeError, ValueError) as exc:
        msg = "This challenge is invalid or has expired"
        raise ChallengeTokenError(msg) from exc
    if not isinstance(subject, str) or not subject:
        msg = "This challenge is invalid or has expired"
        raise ChallengeTokenError(msg)
    return subject


@dataclass(frozen=True)
class TotpEnrollmentStart:
    """The one-time material shown while a user sets up an authenticator."""

    secret: str
    otpauth_uri: str
    qr_svg: str


@dataclass(frozen=True)
class _PendingEnrollment:
    encrypted_secret: str
    expires_at: datetime


class PendingEnrollmentStore(Protocol):
    """The subset of pending-enrollment storage this service depends on."""

    async def put(self, user_id: str, encrypted_secret: str) -> None:
        """Record an unconfirmed enrollment for a user."""
        ...

    async def take(self, user_id: str) -> str | None:
        """Consume an unconfirmed enrollment, if one is still valid."""
        ...

    async def discard(self, user_id: str) -> None:
        """Drop any unconfirmed enrollment for a user."""
        ...


class PendingTotpEnrollmentStore:
    """Hold unconfirmed, encrypted TOTP secrets between enroll and confirm.

    In-memory: used by tests and single-process runs. Production uses
    :class:`DatabasePendingTotpEnrollmentStore` so an enrollment started on one
    API replica can be confirmed on another.
    """

    def __init__(self, lifetime_minutes: int = PENDING_ENROLLMENT_LIFETIME_MINUTES) -> None:
        self._lifetime = timedelta(minutes=lifetime_minutes)
        self._entries: dict[str, _PendingEnrollment] = {}

    async def put(self, user_id: str, encrypted_secret: str) -> None:
        """Record an unconfirmed enrollment for a user."""
        self._prune()
        self._entries[user_id] = _PendingEnrollment(
            encrypted_secret=encrypted_secret,
            expires_at=utc_now() + self._lifetime,
        )

    async def take(self, user_id: str) -> str | None:
        """Consume an unconfirmed enrollment, if one is still valid."""
        self._prune()
        entry = self._entries.pop(user_id, None)
        return entry.encrypted_secret if entry is not None else None

    async def discard(self, user_id: str) -> None:
        """Drop any unconfirmed enrollment for a user."""
        self._entries.pop(user_id, None)

    def clear(self) -> None:
        """Drop every unconfirmed enrollment."""
        self._entries.clear()

    def _prune(self) -> None:
        now = utc_now()
        for user_id in [key for key, entry in self._entries.items() if entry.expires_at <= now]:
            del self._entries[user_id]


class DatabasePendingTotpEnrollmentStore:
    """Persist unconfirmed enrollments so any API replica can confirm them."""

    def __init__(self, lifetime_minutes: int = PENDING_ENROLLMENT_LIFETIME_MINUTES) -> None:
        self._lifetime = timedelta(minutes=lifetime_minutes)

    async def put(self, user_id: str, encrypted_secret: str) -> None:
        """Record an unconfirmed enrollment, replacing any earlier attempt."""
        await PendingTotpEnrollment.find_one(
            PendingTotpEnrollment.user_id == PydanticObjectId(user_id),
        ).upsert(
            Set(
                {
                    PendingTotpEnrollment.encrypted_secret: encrypted_secret,
                    PendingTotpEnrollment.expires_at: utc_now() + self._lifetime,
                }
            ),
            on_insert=PendingTotpEnrollment(
                user_id=PydanticObjectId(user_id),
                encrypted_secret=encrypted_secret,
                expires_at=utc_now() + self._lifetime,
            ),
        )

    async def take(self, user_id: str) -> str | None:
        """Consume an unconfirmed enrollment, if one is still valid."""
        record = await PendingTotpEnrollment.find_one(
            PendingTotpEnrollment.user_id == PydanticObjectId(user_id),
        )
        if record is None:
            return None
        await record.delete()
        expires_at = record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        return None if expires_at <= utc_now() else record.encrypted_secret

    async def discard(self, user_id: str) -> None:
        """Drop any unconfirmed enrollment for a user."""
        await PendingTotpEnrollment.find(
            PendingTotpEnrollment.user_id == PydanticObjectId(user_id),
        ).delete()


pending_totp_store = PendingTotpEnrollmentStore()


class MfaService:
    """Enroll, verify, and retire an account's second factor."""

    def __init__(
        self,
        settings: Settings,
        vault: CredentialVault,
        store: PendingEnrollmentStore | None = None,
    ) -> None:
        self._settings = settings
        self._vault = vault
        self._store: PendingEnrollmentStore = store or DatabasePendingTotpEnrollmentStore()

    # ------------------------------------------------------------- enrollment
    async def begin_totp_enrollment(self, user: User) -> TotpEnrollmentStart:
        """Generate an unconfirmed TOTP secret and its provisioning URI."""
        if user.totp is not None:
            msg = "An authenticator application is already enrolled"
            raise TotpAlreadyEnrolledError(msg)
        secret = generate_totp_secret()
        await self._store.put(
            self._identity(user),
            self._vault.encrypt_for_context(secret, context=TOTP_SECRET_CONTEXT),
        )
        provisioning_uri = totp_provisioning_uri(
            secret,
            account_name=user.email,
            issuer=self._settings.totp_issuer,
        )
        return TotpEnrollmentStart(
            secret=secret,
            otpauth_uri=provisioning_uri,
            qr_svg=totp_qr_svg(provisioning_uri),
        )

    async def confirm_totp_enrollment(self, user: User, code: str) -> list[str]:
        """Confirm an enrollment and return its recovery codes exactly once."""
        if user.totp is not None:
            msg = "An authenticator application is already enrolled"
            raise TotpAlreadyEnrolledError(msg)
        identity = self._identity(user)
        encrypted_secret = await self._store.take(identity)
        if encrypted_secret is None:
            msg = "Start enrollment again; the pending setup expired"
            raise PendingEnrollmentError(msg)

        secret = self._decrypt(encrypted_secret)
        if not verify_totp(secret, code):
            await self._store.put(identity, encrypted_secret)
            msg = "That code is not valid"
            raise InvalidMfaCodeError(msg)

        codes = generate_recovery_codes(RECOVERY_CODE_COUNT)
        now = utc_now()
        user.totp = TotpEnrollment(
            encrypted_secret=encrypted_secret,
            confirmed_at=now,
            recovery_code_hashes=[hash_recovery_code(code) for code in codes],
            recovery_codes_viewed_at=now,
        )
        user.touch()
        await user.save()
        return codes

    async def disable_totp(self, user: User, password: str) -> User:
        """Retire an account's authenticator enrollment."""
        self._require_password(user, password)
        if user.totp is None:
            msg = "No authenticator application is enrolled"
            raise TotpNotEnrolledError(msg)
        user.totp = None
        user.touch()
        await user.save()
        await self._store.discard(self._identity(user))
        return user

    async def regenerate_recovery_codes(self, user: User, password: str) -> list[str]:
        """Replace an account's recovery codes and return them exactly once."""
        self._require_password(user, password)
        if user.totp is None:
            msg = "No authenticator application is enrolled"
            raise TotpNotEnrolledError(msg)
        codes = generate_recovery_codes(RECOVERY_CODE_COUNT)
        user.totp.recovery_code_hashes = [hash_recovery_code(code) for code in codes]
        user.totp.recovery_codes_viewed_at = utc_now()
        user.touch()
        await user.save()
        return codes

    # ----------------------------------------------------------- verification
    def verify_totp_code(self, user: User, code: str) -> bool:
        """Check a submitted authenticator code against the enrolled secret."""
        if user.totp is None:
            return False
        return verify_totp(self._decrypt(user.totp.encrypted_secret), code)

    async def consume_recovery_code(self, user: User, code: str) -> bool:
        """Spend a single-use recovery code, removing it from the account."""
        if user.totp is None:
            return False
        remaining = consume_recovery_code(code, user.totp.recovery_code_hashes)
        if remaining is None:
            return False
        user.totp.recovery_code_hashes = remaining
        user.touch()
        await user.save()
        return True

    async def verify_second_factor(self, user: User, code: str) -> bool:
        """Accept either a valid authenticator code or an unused recovery code."""
        if self.verify_totp_code(user, code):
            return True
        return await self.consume_recovery_code(user, code)

    # -------------------------------------------------------------- challenge
    def issue_login_challenge(self, user: User) -> str:
        """Issue the short-lived token that pairs a password with its second factor."""
        return issue_challenge_token(
            self._identity(user),
            settings=self._settings,
            audience=MFA_CHALLENGE_AUDIENCE,
            lifetime_minutes=MFA_CHALLENGE_LIFETIME_MINUTES,
        )

    def resolve_login_challenge(self, token: str) -> PydanticObjectId:
        """Return the user identifier a login challenge token was issued for."""
        subject = read_challenge_token(
            token,
            settings=self._settings,
            audience=MFA_CHALLENGE_AUDIENCE,
        )
        try:
            return PydanticObjectId(subject)
        except (ValueError, TypeError) as exc:
            msg = "This challenge is invalid or has expired"
            raise ChallengeTokenError(msg) from exc

    # --------------------------------------------------------------- internals
    def _decrypt(self, encrypted_secret: str) -> str:
        try:
            return self._vault.decrypt_for_context(encrypted_secret, context=TOTP_SECRET_CONTEXT)
        except CredentialDecryptionError as exc:
            msg = "The stored authenticator secret could not be read"
            raise MfaError(msg) from exc

    @staticmethod
    def _require_password(user: User, password: str) -> None:
        if not verify_password(password, user.password_hash):
            msg = "The password you entered is incorrect"
            raise InvalidPasswordError(msg)

    @staticmethod
    def _identity(user: User) -> str:
        if user.id is None:
            msg = "Cannot manage a second factor for an unpersisted user"
            raise MfaError(msg)
        return str(user.id)


def get_mfa_service(
    settings: Annotated[Settings, Depends(get_settings)],
    vault: Annotated[CredentialVault, Depends(get_credential_vault)],
) -> MfaService:
    """Build the second-factor service."""
    return MfaService(settings, vault)


async def require_fresh_mfa(
    request: Request,
    user: Annotated[User, Depends(require_viewer)],
    sessions: Annotated[SessionService, Depends(get_session_service)],
) -> User:
    """Require a recent step-up before a sensitive action proceeds.

    Accounts without an authenticator enrollment pass through, because there is
    no second factor to step up with. Enrolled accounts must be on a browser
    session that confirmed a code inside the configured step-up window.
    """
    if user.totp is None:
        return user
    session = getattr(request.state, "session", None)
    if not sessions.has_fresh_mfa(session):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Confirm your authenticator code again before continuing",
        )
    return user
