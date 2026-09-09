"""Canonical configuration serialization and hashing."""

import hashlib
import hmac
import json
from collections.abc import Collection, Mapping, Sequence
from functools import lru_cache

from mist_config_guardian_backend.config import get_settings

# The generation marker every keyed digest carries. Digests written before the
# hash was keyed carry no marker at all, which is what makes them recognisable
# without a separate schema field to track.
CURRENT_HASH_GENERATION = "v2"

# Purpose separation: this subkey hashes configuration and nothing else, so it
# is never the key that encrypts a credential or fingerprints one.
_HASH_CONTEXT = b"mist-config-guardian/configuration-hash/v2"


def canonicalize(value: object, *, ignored_fields: Collection[str] = ()) -> object:
    """Return a deterministic structure while preserving list order."""
    if isinstance(value, Mapping):
        return {
            str(key): canonicalize(child, ignored_fields=ignored_fields)
            for key, child in sorted(value.items(), key=lambda item: str(item[0]))
            if str(key) not in ignored_fields
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [canonicalize(item, ignored_fields=ignored_fields) for item in value]
    return value


def _canonical_json(value: Mapping[str, object], *, ignored_fields: Collection[str] = ()) -> bytes:
    """Serialize a configuration to the one byte string both generations hash."""
    canonical = canonicalize(value, ignored_fields=ignored_fields)
    return json.dumps(canonical, separators=(",", ":"), ensure_ascii=True).encode()


@lru_cache(maxsize=2)
def _derive_key(secret: str) -> bytes:
    """Derive the hashing subkey from the credential key it shares a life with."""
    return hmac.new(secret.encode(), _HASH_CONTEXT, hashlib.sha256).digest()


def _hash_key() -> bytes:
    return _derive_key(get_settings().credential_encryption_key.get_secret_value())


def configuration_hash(value: Mapping[str, object], *, ignored_fields: Collection[str] = ()) -> str:
    """Return a keyed, generation-tagged digest of a canonical configuration.

    The digest is taken over the plaintext configuration, secrets included,
    while the API returns the same object with those secrets redacted. An
    unkeyed digest published beside a redacted configuration is an offline
    oracle: everything except the secret is known, so a guess can be confirmed
    by recomputing the hash. Keying it with a value only the server holds makes
    it useless for that and no less useful for the equality comparisons it
    exists for.
    """
    digest = hmac.new(_hash_key(), _canonical_json(value, ignored_fields=ignored_fields), hashlib.sha256)
    return f"{CURRENT_HASH_GENERATION}:{digest.hexdigest()}"


def legacy_configuration_hash(value: Mapping[str, object], *, ignored_fields: Collection[str] = ()) -> str:
    """Return the unkeyed digest written before the hash was keyed."""
    return hashlib.sha256(_canonical_json(value, ignored_fields=ignored_fields)).hexdigest()


def is_legacy_hash(stored: str) -> bool:
    """Report whether a stored digest predates the keyed generation."""
    return not stored.startswith(f"{CURRENT_HASH_GENERATION}:")


def configuration_hash_matches(
    stored: str | None,
    value: Mapping[str, object],
    *,
    ignored_fields: Collection[str] = (),
) -> bool:
    """Report whether a stored digest of either generation describes `value`.

    Stored digests outlive the change that keyed them, so every comparison
    against one asks which generation it belongs to rather than assuming. A
    digest that is never read again is simply never migrated, and that costs
    nothing.
    """
    if stored is None:
        return False
    expected = (
        legacy_configuration_hash(value, ignored_fields=ignored_fields)
        if is_legacy_hash(stored)
        else configuration_hash(value, ignored_fields=ignored_fields)
    )
    return hmac.compare_digest(stored, expected)


def changed_top_level_fields(
    before: Mapping[str, object],
    after: Mapping[str, object],
) -> list[str]:
    """Return sorted top-level fields whose canonical values differ."""
    all_keys = set(before) | set(after)
    return sorted(key for key in all_keys if canonicalize(before.get(key)) != canonicalize(after.get(key)))
