"""The configuration diff the API returns: the shared walker's entries grouped into sections and summarized.

The walk itself, and the redacted document, line count and JSON Patch helpers, live in ``snapshots.diffing``, which
reads no settings and touches no database. This module re-exports the names its callers import from here.
"""

from collections.abc import Iterable, Mapping, Sequence
from typing import Final

from mist_config_guardian_backend.schemas.diff import ConfigurationDiff, DiffSection
from mist_config_guardian_backend.snapshots.diffing import (
    ABSENT,
    COMPARISON_IGNORED_FIELDS,
    ENCRYPTED_MARKER,
    FINGERPRINT_MARKER,
    MAX_ENTRIES,
    DiffBuilder,
    DiffChangeKind,
    DiffCounts,
    DiffEntry,
    DiffPath,
    build_json_patch,
    comparison_document,
    count_document_lines,
    is_sequence,
    redact_document,
)

__all__ = [
    "COMPARISON_IGNORED_FIELDS",
    "ENCRYPTED_MARKER",
    "FINGERPRINT_MARKER",
    "build_json_patch",
    "comparison_document",
    "count_document_lines",
    "diff_configurations",
    "redact_document",
    "section_label",
]

COMPACT_MODE_LIMIT: Final = 8
MAX_NOTABLE: Final = 10

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


def _section_path(key: str, before: Mapping[str, object], after: Mapping[str, object]) -> str:
    value = after.get(key, before.get(key, ABSENT))
    if isinstance(value, Mapping):
        return f"{key}{{}}"
    if is_sequence(value):
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
    builder = DiffBuilder(max_entries=max_entries)
    builder.walk(DiffPath(), before, after)
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
