"""The canonical structure of a configuration: sorted keys, list order kept, ignored fields removed at every depth.

It holds no key material and reads no settings, so pure code compares configurations with it; ``canonical`` hashes
this structure with the server's key.
"""

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


def changed_top_level_fields(
    before: Mapping[str, object],
    after: Mapping[str, object],
    *,
    ignored_fields: Collection[str],
) -> list[str]:
    """Return sorted top-level fields whose canonical values differ, under the field policy the digest uses.

    ``ignored_fields`` is required so no caller can forget it: an unfiltered comparison lists metadata such as
    ``modified_time``, which changes on every capture, as a change.
    """
    all_keys = (set(before) | set(after)) - set(ignored_fields)
    return sorted(
        key
        for key in all_keys
        if canonicalize(before.get(key), ignored_fields=ignored_fields)
        != canonicalize(after.get(key), ignored_fields=ignored_fields)
    )
