"""Mist webhook signature verification."""

import hashlib
import hmac
from enum import StrEnum


class SignatureVersion(StrEnum):
    """Supported Mist signature header versions."""

    V1 = "v1"
    V2 = "v2"


def verify_signature(
    body: bytes,
    signature: str,
    secret: str,
    *,
    version: SignatureVersion,
) -> bool:
    """Compare a Mist HMAC signature without timing-dependent equality."""
    if not signature or not secret:
        return False
    digest = hashlib.sha256 if version is SignatureVersion.V2 else hashlib.sha1
    expected = hmac.new(secret.encode(), body, digest).hexdigest()
    return hmac.compare_digest(signature.strip().lower(), expected)
