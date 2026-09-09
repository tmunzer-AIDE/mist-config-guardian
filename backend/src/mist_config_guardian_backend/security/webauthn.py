"""WebAuthn primitives with server-held, single-use challenges.

The browser never supplies the challenge it signed. Every ceremony stores the
freshly generated challenge here and hands the client only an opaque handle,
so a caller cannot replay or choose its own challenge.

Challenges are stored in MongoDB with a time-to-live index, so a ceremony that
starts on one API replica can be completed on another and expiry is enforced by
the database. An in-memory store with the same interface is kept for tests.
"""

import base64
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, cast

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.authentication.verify_authentication_response import VerifiedAuthentication
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, options_to_json_dict
from webauthn.helpers.exceptions import InvalidJSONStructure, WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn.registration.verify_registration_response import VerifiedRegistration

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.challenge import WebAuthnChallenge

CHALLENGE_TTL_SECONDS = 300
REGISTRATION_PURPOSE = "registration"
AUTHENTICATION_PURPOSE = "authentication"

_HANDLE_BYTES = 32
_CHALLENGE_UNUSABLE = "The security key challenge expired or was already used"


class WebAuthnError(ValueError):
    """Raised when a WebAuthn ceremony cannot be completed."""


@dataclass(frozen=True)
class StoredChallenge:
    """One issued challenge held server-side until it is consumed or expires."""

    challenge: bytes
    purpose: str
    user_id: str | None
    expires_at: datetime


class WebAuthnChallengeStore:
    """Hold issued challenges under opaque handles for a short window.

    In-memory: used by tests and by single-process runs. Production uses
    :class:`DatabaseWebAuthnChallengeStore` so a ceremony that starts on one API
    replica can finish on another.
    """

    def __init__(self, ttl_seconds: int = CHALLENGE_TTL_SECONDS) -> None:
        self._ttl = timedelta(seconds=ttl_seconds)
        self._entries: dict[str, StoredChallenge] = {}

    async def issue(self, challenge: bytes, *, purpose: str, user_id: str | None = None) -> str:
        """Store a challenge and return the handle given to the client."""
        self._prune()
        handle = secrets.token_urlsafe(_HANDLE_BYTES)
        self._entries[handle] = StoredChallenge(
            challenge=challenge,
            purpose=purpose,
            user_id=user_id,
            expires_at=utc_now() + self._ttl,
        )
        return handle

    async def take(self, handle: str, *, purpose: str, user_id: str | None = None) -> StoredChallenge:
        """Consume a challenge exactly once, or fail when it does not apply."""
        self._prune()
        entry = self._entries.pop(handle, None)
        if entry is None or entry.purpose != purpose or entry.user_id != user_id:
            raise WebAuthnError(_CHALLENGE_UNUSABLE)
        return entry

    def clear(self) -> None:
        """Drop every stored challenge."""
        self._entries.clear()

    def _prune(self) -> None:
        now = utc_now()
        expired = [handle for handle, entry in self._entries.items() if entry.expires_at <= now]
        for handle in expired:
            del self._entries[handle]


class DatabaseWebAuthnChallengeStore:
    """Persist issued challenges so any API replica can complete a ceremony."""

    def __init__(self, ttl_seconds: int = CHALLENGE_TTL_SECONDS) -> None:
        self._ttl = timedelta(seconds=ttl_seconds)

    async def issue(self, challenge: bytes, *, purpose: str, user_id: str | None = None) -> str:
        """Store a challenge and return the handle given to the client."""
        handle = secrets.token_urlsafe(_HANDLE_BYTES)
        record = WebAuthnChallenge(
            handle=handle,
            challenge=base64.urlsafe_b64encode(challenge).decode(),
            purpose=cast("Literal['registration', 'authentication']", purpose),
            user_id=user_id,
            expires_at=utc_now() + self._ttl,
        )
        await record.insert()
        return handle

    async def take(self, handle: str, *, purpose: str, user_id: str | None = None) -> StoredChallenge:
        """Consume a challenge exactly once, or fail when it does not apply.

        The delete is what makes consumption single-use: a replayed handle finds
        nothing to delete and is refused, even under concurrent requests.
        """
        record = await WebAuthnChallenge.find_one(WebAuthnChallenge.handle == handle)
        if record is None:
            raise WebAuthnError(_CHALLENGE_UNUSABLE)
        await record.delete()
        if record.purpose != purpose or record.user_id != user_id or _aware(record.expires_at) <= utc_now():
            raise WebAuthnError(_CHALLENGE_UNUSABLE)
        return StoredChallenge(
            challenge=base64.urlsafe_b64decode(record.challenge.encode()),
            purpose=record.purpose,
            user_id=record.user_id,
            expires_at=_aware(record.expires_at),
        )


def _aware(value: datetime) -> datetime:
    """Treat naive datetimes read back from MongoDB as UTC."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


challenge_store = WebAuthnChallengeStore()


def build_registration_options(
    settings: Settings,
    *,
    user_id: str,
    user_name: str,
    display_name: str,
    excluded_credential_ids: list[str],
) -> tuple[dict[str, Any], bytes]:
    """Build passkey registration options and the challenge they must sign."""
    options = generate_registration_options(
        rp_id=settings.webauthn_rp_id,
        rp_name=settings.webauthn_rp_name,
        user_id=user_id.encode(),
        user_name=user_name,
        user_display_name=display_name,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=decode_credential_id(credential_id))
            for credential_id in excluded_credential_ids
        ],
    )
    return options_to_json_dict(options), options.challenge


def build_authentication_options(
    settings: Settings,
    *,
    allowed_credential_ids: list[str] | None = None,
) -> tuple[dict[str, Any], bytes]:
    """Build passkey authentication options and the challenge they must sign."""
    options = generate_authentication_options(
        rp_id=settings.webauthn_rp_id,
        user_verification=UserVerificationRequirement.PREFERRED,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=decode_credential_id(credential_id))
            for credential_id in allowed_credential_ids or []
        ]
        or None,
    )
    return options_to_json_dict(options), options.challenge


def verify_registration(
    settings: Settings,
    *,
    credential: dict[str, Any],
    expected_challenge: bytes,
) -> VerifiedRegistration:
    """Verify an attestation produced by a registration ceremony."""
    try:
        return verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=settings.webauthn_rp_id,
            expected_origin=settings.webauthn_origin,
        )
    except (WebAuthnException, InvalidJSONStructure, ValueError) as exc:
        msg = "The security key registration could not be verified"
        raise WebAuthnError(msg) from exc


def verify_authentication(
    settings: Settings,
    *,
    credential: dict[str, Any],
    expected_challenge: bytes,
    public_key: str,
    sign_count: int,
) -> VerifiedAuthentication:
    """Verify an assertion produced by an authentication ceremony."""
    try:
        return verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=settings.webauthn_rp_id,
            expected_origin=settings.webauthn_origin,
            credential_public_key=base64url_to_bytes(public_key),
            credential_current_sign_count=sign_count,
        )
    except (WebAuthnException, InvalidJSONStructure, ValueError) as exc:
        msg = "The security key assertion could not be verified"
        raise WebAuthnError(msg) from exc


def encode_credential_id(credential_id: bytes) -> str:
    """Encode a raw credential identifier for storage and transport."""
    return bytes_to_base64url(credential_id)


def decode_credential_id(credential_id: str) -> bytes:
    """Decode a stored credential identifier back to raw bytes."""
    try:
        return base64url_to_bytes(credential_id)
    except (ValueError, TypeError) as exc:
        msg = "Stored credential identifier is not valid base64url"
        raise WebAuthnError(msg) from exc


def encode_public_key(public_key: bytes) -> str:
    """Encode a COSE public key for storage."""
    return bytes_to_base64url(public_key)
