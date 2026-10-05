"""Mist webhook signature tests."""

import hashlib
import hmac

import pytest

from mist_config_guardian_backend.webhooks.signatures import (
    SignatureVersion,
    verify_signature,
)


@pytest.mark.parametrize(
    ("version", "digest"),
    [
        (SignatureVersion.V1, hashlib.sha1),
        (SignatureVersion.V2, hashlib.sha256),
    ],
)
def test_verify_signature_accepts_supported_mist_hmac(
    version: SignatureVersion,
    digest: object,
) -> None:
    body = b'{"topic":"audits"}'
    signature = hmac.new(b"webhook-secret", body, digest).hexdigest()  # type: ignore[arg-type]

    assert verify_signature(body, signature, "webhook-secret", version=version)


def test_verify_signature_rejects_modified_payload() -> None:
    signature = hmac.new(b"webhook-secret", b"original", hashlib.sha256).hexdigest()

    assert not verify_signature(
        b"modified",
        signature,
        "webhook-secret",
        version=SignatureVersion.V2,
    )


def test_verify_signature_rejects_a_non_ascii_signature() -> None:
    # Header values arrive decoded as Latin-1. Comparing non-ASCII text as a
    # string raises instead of failing, which the receiver answered with 500.
    assert not verify_signature(
        b'{"topic":"audits"}',
        "é" * 64,
        "webhook-secret",
        version=SignatureVersion.V2,
    )
