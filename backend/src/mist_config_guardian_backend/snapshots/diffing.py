"""The pure, secret-safe walk that compares two stored configurations.

Both documents are pushed through :func:`redact_configuration` semantics before anything is emitted, so no encrypted
value can reach a response body, an export, a log line, or an AI prompt built from the result. The module reads no
settings and touches no database, so the API diff (``services.diff``) and the Guardian change model share one walker.
"""

import json
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum, StrEnum
from typing import Final, TypeIs

from pydantic import BaseModel

from mist_config_guardian_backend.snapshots.canonical_form import canonicalize
from mist_config_guardian_backend.snapshots.registry import DEFAULT_IGNORED_FIELDS, GENERATED_DEVICE_IMAGE_FIELDS
from mist_config_guardian_backend.snapshots.secrets import redact_configuration

ENCRYPTED_MARKER: Final = "$encrypted"
FINGERPRINT_MARKER: Final = "$fingerprint"
IDENTITY_KEYS: Final = ("id", "_id", "name", "mac", "port_id")
MAX_ENTRIES: Final = 5000
# The canonical metadata set snapshot hashing ignores, plus generated image URLs this display-only view also hides.
COMPARISON_IGNORED_FIELDS: Final = DEFAULT_IGNORED_FIELDS | GENERATED_DEVICE_IMAGE_FIELDS | {"thumbnail_url"}

_VALUE_DISPLAY_LIMIT: Final = 120
_INLINE_LIST_LIMIT: Final = 8
_REORDER_DISPLAY_LIMIT: Final = 6

_SECURITY_TOKENS: Final = ("auth", "psk", "radius", "cert", "acl", "firewall")
_TOPOLOGY_TOKENS: Final = ("vlan", "network", "subnet", "route", "gateway")
_RADIO_TOKENS: Final = ("rf_template", "channel", "power", "band")

_NOTABLE_RULES: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("security", _SECURITY_TOKENS),
    ("topology", _TOPOLOGY_TOKENS),
    ("radio", _RADIO_TOKENS),
)

_CATEGORY_CLAUSES: Final[dict[str, str]] = {
    "security": "Security-relevant field: review authentication and access control before rollout.",
    "topology": "Topology field: addressing or reachability can change for attached devices.",
    "radio": "Radio field: coverage or capacity can change on the affected devices.",
    "removal": "A removed field takes its previous behaviour with it.",
}

DIFF_SECRET_MASK = "********"  # noqa: S105 - redaction sentinel, not a credential


class DiffChangeKind(StrEnum):
    """Classification of one changed configuration leaf."""

    ADDED = "ADDED"
    MODIFIED = "MODIFIED"
    REMOVED = "REMOVED"


class DiffEntry(BaseModel):
    """One changed configuration leaf rendered for display.

    ``before`` and ``after`` are display strings, never raw configuration
    values: encrypted material is replaced by the redaction mask before it ever
    reaches this model.
    """

    field: str
    kind: DiffChangeKind
    before: str | None = None
    after: str | None = None
    note: str
    section: str
    notable: bool = False
    secret: bool = False
    secret_unknown: bool = False
    reordered: bool = False


class DiffCounts(BaseModel):
    """Change magnitude for a diff or one of its sections."""

    changed: int = 0
    added: int = 0
    modified: int = 0
    removed: int = 0


class _Absent:
    """Sentinel for a value that does not exist on one side of the diff."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "<absent>"


ABSENT: Final = _Absent()


def is_secret(value: object) -> bool:
    """Return whether a value is registry-protected encrypted material."""
    return isinstance(value, Mapping) and ENCRYPTED_MARKER in value


def _secret_fingerprint(value: object) -> str | None:
    if not isinstance(value, Mapping):
        return None
    fingerprint = value.get(FINGERPRINT_MARKER)
    return fingerprint if isinstance(fingerprint, str) and fingerprint else None


def _secret_payload(value: object) -> str | None:
    if not isinstance(value, Mapping):
        return None
    payload = value.get(ENCRYPTED_MARKER)
    return payload if isinstance(payload, str) else None


def is_sequence(value: object) -> TypeIs[Sequence[object]]:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


def redact_value(value: object) -> object:
    """Redact any configuration fragment, not only a top-level document."""
    if is_secret(value):
        return DIFF_SECRET_MASK
    if isinstance(value, Mapping):
        return redact_configuration(value)
    if is_sequence(value):
        return [redact_value(child) for child in value]
    return value


def stable_json(value: object) -> str:
    return json.dumps(redact_value(value), sort_keys=True, default=str)


def _truncate(text: str) -> str:
    if len(text) <= _VALUE_DISPLAY_LIMIT:
        return text
    return f"{text[: _VALUE_DISPLAY_LIMIT - 1]}…"


def _render_scalar(value: object) -> str | None:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return _truncate(value) if value else '""'
    return None


def render_value(value: object) -> str | None:
    """Render a configuration value as a short, secret-free display string."""
    if isinstance(value, _Absent):
        return None
    if is_secret(value):
        return DIFF_SECRET_MASK
    scalar = _render_scalar(value)
    if scalar is not None:
        return scalar
    return _render_container(value)


def _render_container(value: object) -> str:
    if isinstance(value, Mapping):
        return "empty object" if not value else f"{len(value)} fields"
    if is_sequence(value):
        return _render_sequence(value)
    return _truncate(str(value))


def _render_sequence(value: Sequence[object]) -> str:
    if not value:
        return "empty list"
    inline = [_render_scalar(child) for child in value]
    if len(value) <= _INLINE_LIST_LIMIT and all(rendered is not None for rendered in inline):
        return _truncate(", ".join(rendered for rendered in inline if rendered is not None))
    return f"{len(value)} entries"


def section_key(path: str) -> str:
    """Return the first path segment used to group changes into sections."""
    for index, character in enumerate(path):
        if character in {".", "["}:
            return path[:index]
    return path


def notable_category(path: str, kind: DiffChangeKind) -> str | None:
    """Return the rule category that makes a change notable, if any."""
    lowered = path.lower()
    for category, tokens in _NOTABLE_RULES:
        if any(token in lowered for token in tokens):
            return category
    if kind is DiffChangeKind.REMOVED:
        return "removal"
    return None


@dataclass(frozen=True, slots=True)
class DiffPath:
    """One location, as the text a diff displays and as the segments Guardian compares.

    The text joins keys with ``.`` and wraps list items in ``[]``, so a key that itself contains either reads like
    two locations. The segments keep every key and item whole.
    """

    text: str = ""
    segments: tuple[str, ...] = ()

    def key(self, key: object) -> "DiffPath":
        return DiffPath(f"{self.text}.{key}" if self.text else str(key), (*self.segments, str(key)))

    def item(self, key: object) -> "DiffPath":
        return DiffPath(f"{self.text}[{key}]", (*self.segments, str(key)))


class DiffBuilder:
    """Accumulate diff entries while walking two configuration documents."""

    def __init__(self, *, max_entries: int = MAX_ENTRIES) -> None:
        self.entries: list[DiffEntry] = []
        # The segments of each entry, index for index.
        self.paths: list[tuple[str, ...]] = []
        self.counts = DiffCounts()
        self.truncated = False
        self.secret_fields = 0
        self._max_entries = max_entries

    # -- emission ---------------------------------------------------------
    def add(  # noqa: PLR0913 - one call site per entry shape
        self,
        path: DiffPath,
        kind: DiffChangeKind,
        before: object,
        after: object,
        *,
        secret: bool = False,
        secret_unknown: bool = False,
        reordered: bool = False,
        note: str | None = None,
    ) -> None:
        """Record one classified change."""
        self._count(kind)
        if secret:
            self.secret_fields += 1
        if len(self.entries) >= self._max_entries:
            self.truncated = True
            return
        rendered_before = DIFF_SECRET_MASK if secret and before is not ABSENT else render_value(before)
        rendered_after = DIFF_SECRET_MASK if secret and after is not ABSENT else render_value(after)
        category = None if secret_unknown else notable_category(path.text, kind)
        self.paths.append(path.segments)
        self.entries.append(
            DiffEntry(
                field=path.text,
                kind=kind,
                before=rendered_before,
                after=rendered_after,
                note=note
                or _build_note(
                    path.text,
                    kind,
                    rendered_before,
                    rendered_after,
                    category=category,
                    secret=secret,
                    secret_unknown=secret_unknown,
                ),
                section=section_key(path.text),
                notable=category is not None,
                secret=secret,
                secret_unknown=secret_unknown,
                reordered=reordered,
            )
        )

    def _count(self, kind: DiffChangeKind) -> None:
        self.counts.changed += 1
        if kind is DiffChangeKind.ADDED:
            self.counts.added += 1
        elif kind is DiffChangeKind.REMOVED:
            self.counts.removed += 1
        else:
            self.counts.modified += 1

    # -- traversal --------------------------------------------------------
    def walk(self, path: DiffPath, before: object, after: object) -> None:
        """Compare two values and emit every changed leaf below them."""
        if is_secret(before) or is_secret(after):
            self._walk_secret(path, before, after)
            return
        if isinstance(before, _Absent):
            self.walk_one_sided(path, after, DiffChangeKind.ADDED)
            return
        if isinstance(after, _Absent):
            self.walk_one_sided(path, before, DiffChangeKind.REMOVED)
            return
        if isinstance(before, Mapping) and isinstance(after, Mapping):
            self._walk_mapping(path, before, after)
            return
        if is_sequence(before) and is_sequence(after):
            self._walk_sequence(path, before, after)
            return
        if stable_json(before) != stable_json(after):
            self.add(path, DiffChangeKind.MODIFIED, before, after)

    def walk_one_sided(self, path: DiffPath, value: object, kind: DiffChangeKind) -> None:
        """Emit one entry per leaf of a subtree that exists on a single side."""
        if is_secret(value):
            before = value if kind is DiffChangeKind.REMOVED else ABSENT
            after = value if kind is DiffChangeKind.ADDED else ABSENT
            self.add(path, kind, before, after, secret=True)
            return
        if isinstance(value, Mapping) and value:
            for key, child in value.items():
                self.walk_one_sided(path.key(key), child, kind)
            return
        if is_sequence(value) and value:
            for index, child in enumerate(value):
                self.walk_one_sided(path.item(index), child, kind)
            return
        before = value if kind is DiffChangeKind.REMOVED else ABSENT
        after = value if kind is DiffChangeKind.ADDED else ABSENT
        self.add(path, kind, before, after)

    def _walk_secret(self, path: DiffPath, before: object, after: object) -> None:
        if isinstance(after, _Absent):
            self.add(path, DiffChangeKind.REMOVED, before, ABSENT, secret=True)
            return
        if isinstance(before, _Absent):
            self.add(path, DiffChangeKind.ADDED, ABSENT, after, secret=True)
            return
        if is_secret(before) and is_secret(after):
            decision = _compare_secrets(before, after)
            if decision is _SecretComparison.EQUAL:
                return
            self.add(
                path,
                DiffChangeKind.MODIFIED,
                before,
                after,
                secret=True,
                secret_unknown=decision is _SecretComparison.UNKNOWN,
            )
            return
        self.add(path, DiffChangeKind.MODIFIED, before, after, secret=True)

    def _walk_mapping(self, path: DiffPath, before: Mapping[str, object], after: Mapping[str, object]) -> None:
        for key in _ordered_keys(before, after):
            self.walk(
                path.key(key),
                before.get(key, ABSENT),
                after.get(key, ABSENT),
            )

    def _walk_sequence(self, path: DiffPath, before: Sequence[object], after: Sequence[object]) -> None:
        identity = _identity_key(before, after)
        if identity is not None:
            self._walk_identified(path, before, after, identity)
            return
        self._walk_positional(path, before, after)

    def _walk_identified(
        self,
        path: DiffPath,
        before: Sequence[object],
        after: Sequence[object],
        identity: str,
    ) -> None:
        before_map = _identity_map(before, identity)
        after_map = _identity_map(after, identity)
        before_keys = list(before_map)
        after_keys = list(after_map)
        if set(before_keys) == set(after_keys) and before_keys != after_keys:
            self._add_reorder(path, before_keys, after_keys)
        for key in before_keys:
            if key not in after_map:
                self.walk_one_sided(path.item(key), before_map[key], DiffChangeKind.REMOVED)
        for key in after_keys:
            if key in before_map:
                self.walk(path.item(key), before_map[key], after_map[key])
            else:
                self.walk_one_sided(path.item(key), after_map[key], DiffChangeKind.ADDED)

    def _walk_positional(self, path: DiffPath, before: Sequence[object], after: Sequence[object]) -> None:
        if _is_pure_reorder(before, after):
            self._add_reorder(
                path,
                [render_value(item) or "null" for item in before],
                [render_value(item) or "null" for item in after],
            )
            return
        for index in range(min(len(before), len(after))):
            self.walk(path.item(index), before[index], after[index])
        for index in range(len(after), len(before)):
            self.walk_one_sided(path.item(index), before[index], DiffChangeKind.REMOVED)
        for index in range(len(before), len(after)):
            self.walk_one_sided(path.item(index), after[index], DiffChangeKind.ADDED)

    def _add_reorder(self, path: DiffPath, before_keys: Sequence[str], after_keys: Sequence[str]) -> None:
        note = (
            f"{path.text} entries were reordered; the same {len(after_keys)} "
            f"{'item' if len(after_keys) == 1 else 'items'} are still present."
        )
        category = notable_category(path.text, DiffChangeKind.MODIFIED)
        if category is not None:
            note = f"{note} {_CATEGORY_CLAUSES[category]}"
        self._count(DiffChangeKind.MODIFIED)
        if len(self.entries) >= self._max_entries:
            self.truncated = True
            return
        self.paths.append(path.segments)
        self.entries.append(
            DiffEntry(
                field=path.text,
                kind=DiffChangeKind.MODIFIED,
                before=_render_order(before_keys),
                after=_render_order(after_keys),
                note=note,
                section=section_key(path.text),
                notable=category is not None,
                reordered=True,
            )
        )


class _SecretComparison(Enum):
    """Outcome of comparing two encrypted values."""

    EQUAL = "equal"
    DIFFERENT = "different"
    UNKNOWN = "unknown"


def _compare_secrets(before: object, after: object) -> _SecretComparison:
    before_fingerprint = _secret_fingerprint(before)
    after_fingerprint = _secret_fingerprint(after)
    if before_fingerprint is not None and after_fingerprint is not None:
        return _SecretComparison.EQUAL if before_fingerprint == after_fingerprint else _SecretComparison.DIFFERENT
    before_payload = _secret_payload(before)
    after_payload = _secret_payload(after)
    if before_payload is not None and before_payload == after_payload:
        return _SecretComparison.EQUAL
    return _SecretComparison.UNKNOWN


def _render_order(keys: Sequence[str]) -> str:
    if len(keys) <= _REORDER_DISPLAY_LIMIT:
        return _truncate(", ".join(keys))
    head = ", ".join(keys[:_REORDER_DISPLAY_LIMIT])
    return _truncate(f"{head}, … ({len(keys)} total)")


def _ordered_keys(before: Mapping[str, object], after: Mapping[str, object]) -> list[str]:
    keys = list(before)
    keys.extend(key for key in after if key not in before)
    return keys


def _identity_map(items: Sequence[object], identity: str) -> dict[str, object]:
    mapping: dict[str, object] = {}
    for item in items:
        if isinstance(item, Mapping):
            mapping[str(item[identity])] = item
    return mapping


def _identity_key(before: Sequence[object], after: Sequence[object]) -> str | None:
    if not before or not after:
        return None
    if not all(isinstance(item, Mapping) for item in before):
        return None
    if not all(isinstance(item, Mapping) for item in after):
        return None
    for candidate in IDENTITY_KEYS:
        if _identifies(before, candidate) and _identifies(after, candidate):
            return candidate
    return None


def _identifies(items: Sequence[object], candidate: str) -> bool:
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, Mapping):
            return False
        value = item.get(candidate, ABSENT)
        if isinstance(value, _Absent) or value is None or isinstance(value, (Mapping, list, tuple)):
            return False
        key = str(value)
        if key in seen:
            return False
        seen.add(key)
    return True


def _is_pure_reorder(before: Sequence[object], after: Sequence[object]) -> bool:
    if len(before) != len(after) or not before:
        return False
    before_items = [stable_json(item) for item in before]
    after_items = [stable_json(item) for item in after]
    return before_items != after_items and sorted(before_items) == sorted(after_items)


def _build_note(  # noqa: PLR0913 - deterministic template selection
    path: str,
    kind: DiffChangeKind,
    before: str | None,
    after: str | None,
    *,
    category: str | None,
    secret: bool,
    secret_unknown: bool,
) -> str:
    note = _base_note(path, kind, before, after, secret=secret, secret_unknown=secret_unknown)
    if category is not None:
        return f"{note} {_CATEGORY_CLAUSES[category]}"
    return note


def _base_note(  # noqa: PLR0913 - deterministic template selection
    path: str,
    kind: DiffChangeKind,
    before: str | None,
    after: str | None,
    *,
    secret: bool,
    secret_unknown: bool,
) -> str:
    if secret_unknown:
        return f"{path} may have changed; both values are stored encrypted and cannot be compared."
    if secret:
        verb = {
            DiffChangeKind.ADDED: "was added",
            DiffChangeKind.REMOVED: "was removed",
            DiffChangeKind.MODIFIED: "changed",
        }[kind]
        return f"{path} {verb}; the value is stored encrypted and is never displayed."
    if kind is DiffChangeKind.ADDED:
        return f"{path} was added with value {after}." if after else f"{path} was added."
    if kind is DiffChangeKind.REMOVED:
        return f"{path} was removed; its previous value was {before}." if before else f"{path} was removed."
    return f"{path} changed from {before} to {after}."


def comparison_document(
    configuration: Mapping[str, object], ignored: Collection[str] = COMPARISON_IGNORED_FIELDS
) -> dict[str, object]:
    """Drop volatile metadata for comparisons, preserving immutable snapshots."""
    return {
        key: canonicalize(value, ignored_fields=ignored) for key, value in configuration.items() if key not in ignored
    }


@dataclass(frozen=True, slots=True)
class ChangedPaths:
    """Where two configurations differ, as whole path segments. It never carries a value.

    ``complete`` is false when the walker stopped at :data:`MAX_ENTRIES`, so later changes are not listed.
    """

    paths: tuple[tuple[str, ...], ...]
    complete: bool


def _walk_changes(before: Mapping[str, object], after: Mapping[str, object], ignored: Collection[str]) -> DiffBuilder:
    builder = DiffBuilder()
    builder.walk(DiffPath(), comparison_document(before, ignored), comparison_document(after, ignored))
    return builder


def changed_paths(before: Mapping[str, object], after: Mapping[str, object], ignored: Collection[str]) -> ChangedPaths:
    """The locations the visible diff reports, walked the same way, as segment tuples without their values."""
    builder = _walk_changes(before, after, ignored)
    return ChangedPaths(paths=tuple(builder.paths), complete=not builder.truncated)


def changed_entries(
    before: Mapping[str, object], after: Mapping[str, object], ignored: Collection[str]
) -> tuple[tuple[tuple[str, ...], DiffEntry], ...]:
    """Each changed location's segments with its display entry, whose values are already masked and shortened."""
    builder = _walk_changes(before, after, ignored)
    return tuple(zip(builder.paths, builder.entries, strict=True))


def redact_document(configuration: Mapping[str, object]) -> dict[str, object]:
    """Return a redacted comparison view, omitting only comparison metadata."""
    return redact_configuration(comparison_document(configuration))


def count_document_lines(*documents: Mapping[str, object]) -> int:
    """Return the tallest pretty-printed line count across documents."""
    rendered = (json.dumps(redact_document(document), indent=2, sort_keys=True, default=str) for document in documents)
    return max((len(text.splitlines()) for text in rendered), default=0)


def _pointer(path: Sequence[str]) -> str:
    escaped = [segment.replace("~", "~0").replace("/", "~1") for segment in path]
    return "/" + "/".join(escaped) if escaped else ""


def build_json_patch(
    before: Mapping[str, object],
    after: Mapping[str, object],
) -> list[dict[str, object]]:
    """Build an RFC 6902 JSON Patch between two redacted documents."""
    operations: list[dict[str, object]] = []
    _patch_mapping([], redact_document(before), redact_document(after), operations)
    return operations


def _patch_value(
    path: list[str],
    before: object,
    after: object,
    operations: list[dict[str, object]],
) -> None:
    if isinstance(before, Mapping) and isinstance(after, Mapping):
        _patch_mapping(path, before, after, operations)
        return
    if is_sequence(before) and is_sequence(after):
        _patch_sequence(path, before, after, operations)
        return
    if stable_json(before) != stable_json(after):
        operations.append({"op": "replace", "path": _pointer(path), "value": after})


def _patch_mapping(
    path: list[str],
    before: Mapping[str, object],
    after: Mapping[str, object],
    operations: list[dict[str, object]],
) -> None:
    for key in _ordered_keys(before, after):
        child = [*path, str(key)]
        if key not in after:
            operations.append({"op": "remove", "path": _pointer(child)})
        elif key not in before:
            operations.append({"op": "add", "path": _pointer(child), "value": after[key]})
        else:
            _patch_value(child, before[key], after[key], operations)


def _patch_sequence(
    path: list[str],
    before: Sequence[object],
    after: Sequence[object],
    operations: list[dict[str, object]],
) -> None:
    for index in range(min(len(before), len(after))):
        _patch_value([*path, str(index)], before[index], after[index], operations)
    operations.extend(
        {"op": "remove", "path": _pointer([*path, str(index)])} for index in range(len(before) - 1, len(after) - 1, -1)
    )
    operations.extend(
        {"op": "add", "path": _pointer([*path, "-"]), "value": after[index]} for index in range(len(before), len(after))
    )
