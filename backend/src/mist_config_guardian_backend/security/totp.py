"""Time-based one-time-password and recovery-code primitives."""

import hashlib
import hmac
import secrets
from collections.abc import Sequence

import pyotp

RECOVERY_CODE_COUNT = 10
_RECOVERY_GROUP_LENGTH = 5
_RECOVERY_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_TOTP_VALID_WINDOW = 1


def generate_totp_secret() -> str:
    """Generate a fresh base32 TOTP shared secret."""
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, *, account_name: str, issuer: str) -> str:
    """Build the otpauth URI an authenticator application scans."""
    return pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    """Verify a submitted TOTP code against the enrolled shared secret."""
    normalized = "".join(character for character in code if character.isdigit())
    if not normalized:
        return False
    return pyotp.TOTP(secret).verify(normalized, valid_window=_TOTP_VALID_WINDOW)


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Generate single-use recovery codes in a readable grouped form."""
    return [_recovery_code() for _ in range(count)]


def normalize_recovery_code(code: str) -> str:
    """Strip formatting so recovery codes compare regardless of presentation."""
    return "".join(character for character in code.upper() if character.isalnum())


def hash_recovery_code(code: str) -> str:
    """Hash a recovery code for storage.

    Recovery codes carry 50 bits of entropy from a uniform alphabet, so a plain
    SHA-256 digest is not brute-forceable in the way a human password would be.
    """
    return hashlib.sha256(normalize_recovery_code(code).encode()).hexdigest()


def consume_recovery_code(code: str, hashes: Sequence[str]) -> list[str] | None:
    """Return the remaining hashes after use, or ``None`` when the code is unknown."""
    candidate = hash_recovery_code(code)
    matched = False
    remaining: list[str] = []
    for stored in hashes:
        if not matched and hmac.compare_digest(stored, candidate):
            matched = True
            continue
        remaining.append(stored)
    return remaining if matched else None


def _recovery_code() -> str:
    groups = ["".join(secrets.choice(_RECOVERY_CODE_ALPHABET) for _ in range(_RECOVERY_GROUP_LENGTH)) for _ in range(2)]
    return "-".join(groups)
