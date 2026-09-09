"""Deterministic, secret-safe configuration diff engine.

The engine is pure and synchronous. Both documents are pushed through
:func:`redact_configuration` semantics before anything is emitted, so no
encrypted value can reach a response body, an export, a log line, or an AI
prompt built from the result.
"""

import json
from collections.abc import Iterable, Mapping, Sequence
from enum import Enum
from typing import Final, TypeIs

from mist_config_guardian_backend.schemas.diff import (
    DIFF_SECRET_MASK,
    ConfigurationDiff,
    DiffChangeKind,
    DiffCounts,
    DiffEntry,
    DiffSection,
)
from mist_config_guardian_backend.snapshots.canonical import canonicalize
from mist_config_guardian_backend.snapshots.secrets import redact_configuration

ENCRYPTED_MARKER: Final = "$encrypted"
FINGERPRINT_MARKER: Final = "$fingerprint"
IDENTITY_KEYS: Final = ("id", "_id", "name", "mac", "port_id")
COMPACT_MODE_LIMIT: Final = 8
MAX_ENTRIES: Final = 5000
MAX_NOTABLE: Final = 10
COMPARISON_IGNORED_FIELDS: Final = frozenset(
    {"created_time", "modified_time", "image1_url", "image2_url", "image3_url", "url", "thumbnail_url"}
)

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

_SECTION_LABELS: Final[dict[str, str]] = {
    "band_24": "Band 2.4 GHz",
    "band_5": "Band 5 GHz",
    "band_6": "Band 6 GHz",
}

_ACRONYMS: Final[frozenset[str]] = frozenset(
    {
        "acl",
        "ap",
        "bgp",
        "dhcp",
        "dhcpd",
        "dns",
        "idp",
        "ip",
        "lan",
        "mtu",
        "nac",
        "nat",
        "ntp",
        "poe",
        "psk",
        "qos",
        "radius",
        "rf",
        "snmp",
        "ssid",
        "ssh",
        "tacacs",
        "vlan",
        "vpn",
        "wan",
        "wlan",
    }
)


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


def _is_sequence(value: object) -> TypeIs[Sequence[object]]:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


def redact_value(value: object) -> object:
    """Redact any configuration fragment, not only a top-level document."""
    if is_secret(value):
        return DIFF_SECRET_MASK
    if isinstance(value, Mapping):
        return redact_configuration(value)
    if _is_sequence(value):
        return [redact_value(child) for child in value]
    return value


def _stable(value: object) -> str:
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
    if _is_sequence(value):
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


def section_label(key: str) -> str:
    """Return a human label for a section key."""
    if key in _SECTION_LABELS:
        return _SECTION_LABELS[key]
    words = [word for word in key.replace("-", "_").split("_") if word]
    if not words:
        return key
    rendered = [word.upper() if word.lower() in _ACRONYMS else word.lower() for word in words]
    first = rendered[0]
    if first.lower() not in _ACRONYMS:
        first = first.capitalize()
    return " ".join([first, *rendered[1:]])


def notable_category(path: str, kind: DiffChangeKind) -> str | None:
    """Return the rule category that makes a change notable, if any."""
    lowered = path.lower()
    for category, tokens in _NOTABLE_RULES:
        if any(token in lowered for token in tokens):
            return category
    if kind is DiffChangeKind.REMOVED:
        return "removal"
    return None


def _child_path(path: str, key: object) -> str:
    return f"{path}.{key}" if path else str(key)


class _DiffBuilder:
    """Accumulate diff entries while walking two configuration documents."""

    def __init__(self, *, max_entries: int = MAX_ENTRIES) -> None:
        self.entries: list[DiffEntry] = []
        self.counts = DiffCounts()
        self.truncated = False
        self.secret_fields = 0
        self._max_entries = max_entries

    # -- emission ---------------------------------------------------------
    def add(  # noqa: PLR0913 - one call site per entry shape
        self,
        path: str,
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
        category = None if secret_unknown else notable_category(path, kind)
        self.entries.append(
            DiffEntry(
                field=path,
                kind=kind,
                before=rendered_before,
                after=rendered_after,
                note=note
                or _build_note(
                    path,
                    kind,
                    rendered_before,
                    rendered_after,
                    category=category,
                    secret=secret,
                    secret_unknown=secret_unknown,
                ),
                section=section_key(path),
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
    def walk(self, path: str, before: object, after: object) -> None:
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
        if _is_sequence(before) and _is_sequence(after):
            self._walk_sequence(path, before, after)
            return
        if _stable(before) != _stable(after):
            self.add(path, DiffChangeKind.MODIFIED, before, after)

    def walk_one_sided(self, path: str, value: object, kind: DiffChangeKind) -> None:
        """Emit one entry per leaf of a subtree that exists on a single side."""
        if is_secret(value):
            before = value if kind is DiffChangeKind.REMOVED else ABSENT
            after = value if kind is DiffChangeKind.ADDED else ABSENT
            self.add(path, kind, before, after, secret=True)
            return
        if isinstance(value, Mapping) and value:
            for key, child in value.items():
                self.walk_one_sided(_child_path(path, key), child, kind)
            return
        if _is_sequence(value) and value:
            for index, child in enumerate(value):
                self.walk_one_sided(f"{path}[{index}]", child, kind)
            return
        before = value if kind is DiffChangeKind.REMOVED else ABSENT
        after = value if kind is DiffChangeKind.ADDED else ABSENT
        self.add(path, kind, before, after)

    def _walk_secret(self, path: str, before: object, after: object) -> None:
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

    def _walk_mapping(self, path: str, before: Mapping[str, object], after: Mapping[str, object]) -> None:
        for key in _ordered_keys(before, after):
            self.walk(
                _child_path(path, key),
                before.get(key, ABSENT),
                after.get(key, ABSENT),
            )

    def _walk_sequence(self, path: str, before: Sequence[object], after: Sequence[object]) -> None:
        identity = _identity_key(before, after)
        if identity is not None:
            self._walk_identified(path, before, after, identity)
            return
        self._walk_positional(path, before, after)

    def _walk_identified(
        self,
        path: str,
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
                self.walk_one_sided(f"{path}[{key}]", before_map[key], DiffChangeKind.REMOVED)
        for key in after_keys:
            if key in before_map:
                self.walk(f"{path}[{key}]", before_map[key], after_map[key])
            else:
                self.walk_one_sided(f"{path}[{key}]", after_map[key], DiffChangeKind.ADDED)

    def _walk_positional(self, path: str, before: Sequence[object], after: Sequence[object]) -> None:
        if _is_pure_reorder(before, after):
            self._add_reorder(
                path,
                [render_value(item) or "null" for item in before],
                [render_value(item) or "null" for item in after],
            )
            return
        for index in range(min(len(before), len(after))):
            self.walk(f"{path}[{index}]", before[index], after[index])
        for index in range(len(after), len(before)):
            self.walk_one_sided(f"{path}[{index}]", before[index], DiffChangeKind.REMOVED)
        for index in range(len(before), len(after)):
            self.walk_one_sided(f"{path}[{index}]", after[index], DiffChangeKind.ADDED)

    def _add_reorder(self, path: str, before_keys: Sequence[str], after_keys: Sequence[str]) -> None:
        note = (
            f"{path} entries were reordered; the same {len(after_keys)} "
            f"{'item' if len(after_keys) == 1 else 'items'} are still present."
        )
        category = notable_category(path, DiffChangeKind.MODIFIED)
        if category is not None:
            note = f"{note} {_CATEGORY_CLAUSES[category]}"
        self._count(DiffChangeKind.MODIFIED)
        if len(self.entries) >= self._max_entries:
            self.truncated = True
            return
        self.entries.append(
            DiffEntry(
                field=path,
                kind=DiffChangeKind.MODIFIED,
                before=_render_order(before_keys),
                after=_render_order(after_keys),
                note=note,
                section=section_key(path),
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
    before_items = [_stable(item) for item in before]
    after_items = [_stable(item) for item in after]
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


def _section_path(key: str, before: Mapping[str, object], after: Mapping[str, object]) -> str:
    value = after.get(key, before.get(key, ABSENT))
    if isinstance(value, Mapping):
        return f"{key}{{}}"
    if _is_sequence(value):
        return f"{key}[]"
    return key


def _section_detail(counts: DiffCounts) -> str:
    parts = [
        (counts.added, "added"),
        (counts.modified, "modified"),
        (counts.removed, "removed"),
    ]
    return ", ".join(f"{count} {label}" for count, label in parts if count) or "no changes"


def _summary(counts: DiffCounts) -> str:
    noun = "field" if counts.changed == 1 else "fields"
    return (
        f"{counts.changed} {noun} changed · {counts.added} added · "
        f"{counts.modified} modified · {counts.removed} removed"
    )


def _build_sections(
    entries: Iterable[DiffEntry],
    before: Mapping[str, object],
    after: Mapping[str, object],
) -> list[DiffSection]:
    grouped: dict[str, list[DiffEntry]] = {}
    for entry in entries:
        grouped.setdefault(entry.section, []).append(entry)
    sections: list[DiffSection] = []
    for key, section_entries in grouped.items():
        counts = DiffCounts(changed=len(section_entries))
        for entry in section_entries:
            if entry.kind is DiffChangeKind.ADDED:
                counts.added += 1
            elif entry.kind is DiffChangeKind.REMOVED:
                counts.removed += 1
            else:
                counts.modified += 1
        notable = sum(1 for entry in section_entries if entry.notable)
        sections.append(
            DiffSection(
                key=key,
                name=section_label(key),
                path=_section_path(key, before, after),
                counts=counts,
                detail=_section_detail(counts),
                notable=notable,
                entries=section_entries,
            )
        )
    sections.sort(key=lambda section: (0 if section.notable else 1, section.name.casefold()))
    return sections


def _notable_entries(entries: Sequence[DiffEntry]) -> list[DiffEntry]:
    notable = [entry for entry in entries if entry.notable]
    notable.sort(key=lambda entry: 0 if entry.kind is DiffChangeKind.REMOVED else 1)
    return notable[:MAX_NOTABLE]


def diff_configurations(
    before: Mapping[str, object],
    after: Mapping[str, object],
    *,
    include_entries: bool = True,
    sections: Sequence[str] | None = None,
    max_entries: int = MAX_ENTRIES,
) -> ConfigurationDiff:
    """Compare two stored configurations and return a redacted structured diff.

    ``include_entries=False`` returns section metadata and counts only, and
    ``sections`` restricts entry bodies to the named sections so a large diff
    can be fetched one section at a time.
    """
    before = comparison_document(before)
    after = comparison_document(after)
    builder = _DiffBuilder(max_entries=max_entries)
    builder.walk("", before, after)
    builder.entries.sort(key=lambda entry: (entry.secret, entry.secret_unknown))
    counts = builder.counts
    mode = "chips" if counts.changed <= COMPACT_MODE_LIMIT else "sections"
    all_sections = _build_sections(builder.entries, before, after)
    wanted = set(sections) if sections is not None else None
    for section in all_sections:
        if not include_entries or (wanted is not None and section.key not in wanted):
            section.entries = []
            section.entries_included = False
    return ConfigurationDiff(
        mode=mode,
        summary=_summary(counts),
        counts=counts,
        entries=list(builder.entries) if include_entries and mode == "chips" else [],
        notable=_notable_entries(builder.entries) if include_entries else [],
        sections=all_sections,
        entries_included=include_entries,
        truncated=builder.truncated,
        secret_fields=builder.secret_fields,
    )


def comparison_document(configuration: Mapping[str, object]) -> dict[str, object]:
    """Drop volatile metadata for comparisons, preserving immutable snapshots."""
    return {
        key: canonicalize(value, ignored_fields=COMPARISON_IGNORED_FIELDS)
        for key, value in configuration.items()
        if key not in COMPARISON_IGNORED_FIELDS
    }


def redact_document(configuration: Mapping[str, object]) -> dict[str, object]:
    """Return the redacted form of a stored configuration document."""
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
    if _is_sequence(before) and _is_sequence(after):
        _patch_sequence(path, before, after, operations)
        return
    if _stable(before) != _stable(after):
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
