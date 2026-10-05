"""Time-based one-time-password and recovery-code primitives."""

import hashlib
import hmac
import io
import secrets
from collections.abc import Sequence
from datetime import UTC, datetime

import pyotp
import segno
from pyotp.utils import strings_equal

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
    return totp_time_step(secret, code) is not None


def totp_time_step(secret: str, code: str) -> int | None:
    """Return the time step a submitted code belongs to, or ``None`` when it matches none.

    The step is what makes a code single-use: a caller that records the last
    step it accepted can refuse that code, and every earlier one, while they
    are still inside the verification window.
    """
    normalized = "".join(character for character in code if character.isdigit())
    if not normalized:
        return None
    totp = pyotp.TOTP(secret)
    current = totp.timecode(datetime.now(UTC))
    for step in range(current - _TOTP_VALID_WINDOW, current + _TOTP_VALID_WINDOW + 1):
        if strings_equal(normalized, totp.generate_otp(step)):
            return step
    return None


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


def totp_qr_svg(otpauth_uri: str) -> str:
    """Render a provisioning URI as a self-contained, inline-able SVG.

    Rendered server-side with a tested encoder rather than hand-rolled in the
    browser: an authenticator that cannot read the code is worse than no code at
    all, and correctness here is not something a UI review would catch.
    """
    code = segno.make(otpauth_uri, error="m")
    buffer = io.BytesIO()
    code.save(
        buffer,
        kind="svg",
        scale=1,
        border=2,
        omitsize=True,
        svgclass=None,
        lineclass=None,
        xmldecl=False,
        svgns=True,
        nl=False,
    )
    return buffer.getvalue().decode()
