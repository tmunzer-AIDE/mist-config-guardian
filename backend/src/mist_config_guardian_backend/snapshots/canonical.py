"""Canonical configuration serialization and hashing."""

import hashlib
import json
from collections.abc import Collection, Mapping, Sequence


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


def configuration_hash(value: Mapping[str, object], *, ignored_fields: Collection[str] = ()) -> str:
    """Hash canonical JSON using SHA-256."""
    canonical = canonicalize(value, ignored_fields=ignored_fields)
    serialized = json.dumps(canonical, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(serialized.encode()).hexdigest()


def changed_top_level_fields(
    before: Mapping[str, object],
    after: Mapping[str, object],
) -> list[str]:
    """Return sorted top-level fields whose canonical values differ."""
    all_keys = set(before) | set(after)
    return sorted(key for key in all_keys if canonicalize(before.get(key)) != canonicalize(after.get(key)))
