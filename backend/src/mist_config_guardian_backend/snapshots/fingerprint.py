"""The one definition-aware normalization every configuration comparison uses.

Backup captures, fresh baselines, safety snapshots, write guards, restored
versions and read-after-write verification all compare the same Mist objects.
Each used to strip fields and treat masked secrets its own way, and every
disagreement showed up as drift that was not there (#28). They all come through
here now, so a digest or a comparison means the same thing wherever it is taken.

``canonical`` keeps the generic primitives, which know nothing of a registry
definition; ``tasks.hashes`` still hashes under the historical field sets a
stored digest may have been written with, and the diff view keeps its own
display-only comparison.
"""

import copy
from collections.abc import Collection, Mapping, Sequence

from mist_config_guardian_backend.snapshots.canonical import (
    canonicalize,
    configuration_hash,
    configuration_hash_matches,
)
from mist_config_guardian_backend.snapshots.registry import ObjectDefinition
from mist_config_guardian_backend.snapshots.secrets import SecretPath, find_unavailable_secrets

# A location a configuration does not have. No real value equals it, so a field
# present on one side only always differs.
MISSING = object()


def normalize(definition: ObjectDefinition, configuration: Mapping[str, object]) -> object:
    """The canonical structure the collector hashes, under the definition's field policy.

    For comparing two configurations structurally where a digest cannot be
    used, such as a stored configuration whose digest predates the policy.
    """
    return canonicalize(configuration, ignored_fields=definition.ignored_fields)


def fingerprint(definition: ObjectDefinition, configuration: Mapping[str, object]) -> str:
    """The keyed digest the collector stores for this configuration.

    Every digest that is later compared with a live read, whether a backup
    version, a baseline, a safety snapshot entry, a restored version or what a
    restore wrote, is taken here, so all of them agree for the same response.
    """
    return configuration_hash(configuration, ignored_fields=definition.ignored_fields)


def fingerprint_matches(definition: ObjectDefinition, stored: str | None, configuration: Mapping[str, object]) -> bool:
    """Whether a stored digest of either hash generation describes this configuration."""
    return configuration_hash_matches(stored, configuration, ignored_fields=definition.ignored_fields)


def at_path(value: object, path: SecretPath) -> object:
    """Read one of the locations :func:`find_unavailable_secrets` reports; ``MISSING`` when absent.

    A step is a mapping key or a sequence position, and only the matching kind
    of container answers to it: a mapping is not indexed by number, and a list
    is not keyed by name. Anything else means the location is not there, and a
    location that is not there supplies nothing.
    """
    for step in path:
        if isinstance(step, str) and isinstance(value, Mapping):
            if step not in value:
                return MISSING
            value = value[step]
        elif isinstance(step, int) and isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            if not -len(value) <= step < len(value):
                return MISSING
            value = value[step]
        else:
            return MISSING
    return value


def without_paths(value: object, paths: frozenset[SecretPath], *, path: SecretPath = ()) -> object:
    """Drop exactly those locations, leaving same-named fields elsewhere.

    The paths are the ones :func:`find_unavailable_secrets` reports, so this
    walks a configuration the same way it does and removes only what it named
    — step for step, so a key that happens to spell another location's path
    does not stand in for it.
    """
    if isinstance(value, Mapping):
        kept: dict[str, object] = {}
        for key, child in value.items():
            child_path = (*path, str(key))
            if child_path in paths:
                continue
            kept[str(key)] = without_paths(child, paths, path=child_path)
        return kept
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [without_paths(child, paths, path=(*path, index)) for index, child in enumerate(value)]
    return value


def _top_level_without(configuration: Mapping[str, object], paths: frozenset[SecretPath]) -> dict[str, object]:
    """:func:`without_paths` for a whole configuration, typed as the mapping it returns."""
    return {
        str(key): without_paths(child, paths, path=(str(key),))
        for key, child in configuration.items()
        if (str(key),) not in paths
    }


def differing_fields(
    definition: ObjectDefinition,
    expected: Mapping[str, object],
    actual: Mapping[str, object],
    *,
    fields: Collection[str] | None = None,
) -> list[str]:
    """Top-level fields whose values differ under the collector's field policy, masked secrets aside.

    Mist returns some secrets it stores as a run of asterisks, so a location
    masked on either side says nothing about whether the two agree. It is left
    out of both, by exact location: a mask over a primary key must not hide a
    change to a backup key of the same name. A secret that came back real is
    compared like any other value. ``fields`` restricts the comparison to what
    was written, since Mist echoes fields a payload never carried.

    Only key names are returned, never values, so the result can be shown and
    logged.
    """
    masked = frozenset(
        find_unavailable_secrets(dict(expected), definition.sensitive_fields)
        | find_unavailable_secrets(dict(actual), definition.sensitive_fields)
    )
    left = _top_level_without(expected, masked)
    right = _top_level_without(actual, masked)
    keys = sorted(set(expected) | set(actual)) if fields is None else sorted(set(fields))
    ignored = definition.ignored_fields
    return [
        key
        for key in keys
        if key not in ignored
        and canonicalize(left.get(key, MISSING), ignored_fields=ignored)
        != canonicalize(right.get(key, MISSING), ignored_fields=ignored)
    ]


def equivalent(
    definition: ObjectDefinition,
    expected: Mapping[str, object],
    actual: Mapping[str, object],
    *,
    fields: Collection[str] | None = None,
) -> bool:
    """Whether two configurations agree under the collector's field policy, tolerating masked secrets."""
    return not differing_fields(definition, expected, actual, fields=fields)


def restored_configuration(
    definition: ObjectDefinition,
    readback: Mapping[str, object],
    written: Mapping[str, object],
) -> dict[str, object]:
    """What Mist now holds, with each secret it masked filled from the value just written.

    A restored version's digest is taken over the read-back as returned, masks
    included, because that is what the next capture of the same object hashes.
    Its stored configuration keeps the real secret instead, so the version can
    be restored again. A mask that nothing written can fill stays a mask, and
    authorization refuses to replay it. The read-back itself is not modified.
    """
    restored = copy.deepcopy(dict(readback))
    for path in find_unavailable_secrets(restored, definition.sensitive_fields):
        value = at_path(written, path)
        if isinstance(value, str) and value and set(value) != {"*"}:
            _assign(restored, path, value)
    return restored


def _assign(configuration: dict[str, object], path: SecretPath, value: str) -> None:
    """Replace the value at a location :func:`find_unavailable_secrets` found in ``configuration``.

    A masked secret is always the value of a sensitive key, so its location
    ends in a mapping key.
    """
    parent = at_path(configuration, path[:-1])
    if isinstance(parent, dict):
        parent[path[-1]] = value
