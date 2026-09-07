"""Passkey registration and passwordless authentication.

Challenges are held server-side, keyed by a random handle that the client only
ever sees wrapped in a short-lived signed token. The default store is the
MongoDB-backed one, so a ceremony that starts on one API replica can be
completed on another.
"""

from typing import Annotated, Any, Literal, Protocol

from beanie import PydanticObjectId
from fastapi import Depends

from mist_config_guardian_backend.config import Settings, get_settings
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.user import User, WebAuthnCredential
from mist_config_guardian_backend.security import webauthn as webauthn_security
from mist_config_guardian_backend.services.mfa import (
    PASSKEY_CHALLENGE_AUDIENCE,
    PASSKEY_CHALLENGE_LIFETIME_MINUTES,
    issue_challenge_token,
    read_challenge_token,
)

DEFAULT_PASSKEY_NAME = "Passkey"


class ChallengeStore(Protocol):
    """The subset of challenge storage this service depends on."""

    async def issue(self, challenge: bytes, *, purpose: str, user_id: str | None = None) -> str:
        """Store a challenge and return its opaque handle."""
        ...

    async def take(
        self,
        handle: str,
        *,
        purpose: str,
        user_id: str | None = None,
    ) -> webauthn_security.StoredChallenge:
        """Consume a challenge exactly once."""
        ...


class PasskeyError(ValueError):
    """Raised when a passkey ceremony cannot be completed."""


class PasskeyNotFoundError(ValueError):
    """Raised when a passkey does not exist for the requesting user."""


class PasskeyService:
    """Register, list, rename, remove, and authenticate with passkeys."""

    def __init__(
        self,
        settings: Settings,
        store: ChallengeStore | None = None,
    ) -> None:
        self._settings = settings
        self._store: ChallengeStore = store if store is not None else webauthn_security.DatabaseWebAuthnChallengeStore()

    # -------------------------------------------------------------- inventory
    async def list_for_user(self, user_id: PydanticObjectId) -> list[WebAuthnCredential]:
        """Return a user's registered passkeys, newest first."""
        return await WebAuthnCredential.find({"user_id": user_id}).sort("-created_at").to_list()

    async def count_for_user(self, user_id: PydanticObjectId | None) -> int:
        """Count a user's registered passkeys."""
        if user_id is None:
            return 0
        return await WebAuthnCredential.find({"user_id": user_id}).count()

    # ----------------------------------------------------------- registration
    async def begin_registration(self, user: User) -> tuple[dict[str, Any], str]:
        """Build registration options and the token that carries their challenge."""
        user_id = self._identity(user)
        existing = await self.list_for_user(user.id) if user.id is not None else []
        options, challenge = webauthn_security.build_registration_options(
            self._settings,
            user_id=user_id,
            user_name=str(user.email),
            display_name=user.display_name,
            excluded_credential_ids=[credential.credential_id for credential in existing],
        )
        handle = await self._store.issue(
            challenge,
            purpose=webauthn_security.REGISTRATION_PURPOSE,
            user_id=user_id,
        )
        return options, self._token(handle)

    async def complete_registration(
        self,
        user: User,
        *,
        challenge_token: str,
        credential: dict[str, Any],
        name: str | None = None,
    ) -> WebAuthnCredential:
        """Verify an attestation and store the resulting passkey."""
        user_id = self._identity(user)
        stored = await self._store.take(
            self._handle(challenge_token),
            purpose=webauthn_security.REGISTRATION_PURPOSE,
            user_id=user_id,
        )
        verified = webauthn_security.verify_registration(
            self._settings,
            credential=credential,
            expected_challenge=stored.challenge,
        )
        if user.id is None:
            msg = "Cannot register a passkey for an unpersisted user"
            raise PasskeyError(msg)

        record = WebAuthnCredential(
            user_id=user.id,
            credential_id=webauthn_security.encode_credential_id(verified.credential_id),
            public_key=webauthn_security.encode_public_key(verified.credential_public_key),
            sign_count=verified.sign_count,
            name=(name or "").strip() or DEFAULT_PASSKEY_NAME,
            transports=_transports(credential),
            device_kind=_device_kind(credential),
            backed_up=verified.credential_backed_up,
        )
        await record.insert()
        return record

    # --------------------------------------------------------- authentication
    async def begin_authentication(self) -> tuple[dict[str, Any], str]:
        """Build authentication options and the token that carries their challenge."""
        options, challenge = webauthn_security.build_authentication_options(self._settings)
        handle = await self._store.issue(challenge, purpose=webauthn_security.AUTHENTICATION_PURPOSE)
        return options, self._token(handle)

    async def complete_authentication(
        self,
        *,
        challenge_token: str,
        credential: dict[str, Any],
    ) -> tuple[User, WebAuthnCredential]:
        """Verify an assertion and return the account it authenticates."""
        stored = await self._store.take(
            self._handle(challenge_token),
            purpose=webauthn_security.AUTHENTICATION_PURPOSE,
        )
        credential_id = credential.get("id")
        rejected = "That passkey is not registered"
        if not isinstance(credential_id, str) or not credential_id:
            raise PasskeyError(rejected)

        record = await WebAuthnCredential.find_one({"credential_id": credential_id})
        if record is None:
            raise PasskeyError(rejected)

        verified = webauthn_security.verify_authentication(
            self._settings,
            credential=credential,
            expected_challenge=stored.challenge,
            public_key=record.public_key,
            sign_count=record.sign_count,
        )
        user = await User.get(record.user_id)
        if user is None or not user.is_active:
            raise PasskeyError(rejected)

        record.sign_count = verified.new_sign_count
        record.last_used_at = utc_now()
        record.touch()
        await record.save()
        return user, record

    # ------------------------------------------------------------- management
    async def rename(
        self,
        user: User,
        credential_id: PydanticObjectId,
        name: str,
    ) -> WebAuthnCredential:
        """Rename one of a user's own passkeys."""
        record = await self._require_own(user, credential_id)
        record.name = name.strip() or DEFAULT_PASSKEY_NAME
        record.touch()
        await record.save()
        return record

    async def delete(self, user: User, credential_id: PydanticObjectId) -> None:
        """Remove one of a user's own passkeys."""
        record = await self._require_own(user, credential_id)
        await record.delete()

    # --------------------------------------------------------------- internals
    async def _require_own(self, user: User, credential_id: PydanticObjectId) -> WebAuthnCredential:
        record = await WebAuthnCredential.find_one({"_id": credential_id, "user_id": user.id})
        if record is None:
            msg = "Passkey not found"
            raise PasskeyNotFoundError(msg)
        return record

    def _token(self, handle: str) -> str:
        return issue_challenge_token(
            handle,
            settings=self._settings,
            audience=PASSKEY_CHALLENGE_AUDIENCE,
            lifetime_minutes=PASSKEY_CHALLENGE_LIFETIME_MINUTES,
        )

    def _handle(self, challenge_token: str) -> str:
        return read_challenge_token(
            challenge_token,
            settings=self._settings,
            audience=PASSKEY_CHALLENGE_AUDIENCE,
        )

    @staticmethod
    def _identity(user: User) -> str:
        if user.id is None:
            msg = "Cannot run a passkey ceremony for an unpersisted user"
            raise PasskeyError(msg)
        return str(user.id)


def get_passkey_service(settings: Annotated[Settings, Depends(get_settings)]) -> PasskeyService:
    """Build the passkey service."""
    return PasskeyService(settings)


def _transports(credential: dict[str, Any]) -> list[str]:
    response = credential.get("response")
    if not isinstance(response, dict):
        return []
    transports = response.get("transports")
    if not isinstance(transports, list):
        return []
    return [value for value in transports if isinstance(value, str)]


def _device_kind(credential: dict[str, Any]) -> Literal["platform", "security_key"]:
    attachment = credential.get("authenticatorAttachment")
    return "security_key" if attachment == "cross-platform" else "platform"
