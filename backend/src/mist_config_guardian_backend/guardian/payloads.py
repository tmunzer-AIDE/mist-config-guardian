"""Untrusted JSON in, bounded redacted JSON out.

Everything an external read returns is untrusted: it is redacted before it can be stored, shown or hashed, and it is
cut to a shape that fits an evidence item's byte budget. The redaction and schema-compaction rules are the ones the
legacy MCP guard proved in production, kept here so the Reader is the only place that applies them.

The transport bound (1 MB of wire bytes) and the evidence budget (4 KB per stored item) are different limits: the
first is what a transport may read at all, the second is what may be persisted and put in a prompt. A result that
arrives inside the transport bound and above the evidence budget is kept as a digest, not dropped.
"""

import re
from collections.abc import Iterator, Mapping, Sequence
from math import isfinite
from typing import Any

from pydantic import JsonValue

from mist_config_guardian_backend.guardian.contracts import EvidenceRepresentation
from mist_config_guardian_backend.guardian.evidence import json_size

# Dynamic JSON from an external read is validated at this boundary.
# ruff: noqa: ANN401

MAX_DEPTH = 12
MAX_FIELDS = 100
MAX_ITEMS = 50
MAX_STRING = 2_000
MAX_KEY = 120
DIGEST_ROWS = (10, 5, 2)

REDACTED = "[redacted]"
_SECRET = re.compile(
    r"password|passphrase|secret|token|private.?key|api.?key|credential|^psk$|^key$|certificate", re.IGNORECASE
)
_BEARER = re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+")
_UNSAFE_RUN = re.compile(r"[\x00-\x1f\x7f\s]+")
_SCHEMA_MAPS = frozenset({"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"})
_SCHEMA_PROSE = frozenset({"description", "examples", "title", "$comment"})
_REFERENCES = ("$ref", "$dynamicRef")


def secret_name(name: str) -> bool:
    """Whether an argument or field name names credential material."""
    return _SECRET.search(name) is not None


def redact(value: Any, *, secrets: Sequence[str] = (), depth: int = 0) -> JsonValue:  # noqa: PLR0911 - bounded recursive JSON redaction
    """Redact secrets and cut depth, width and string length, so no unbounded value reaches storage or a prompt."""
    if depth > MAX_DEPTH:
        return "[depth omitted]"
    if isinstance(value, Mapping):
        if "$encrypted" in value:
            return REDACTED
        return {
            str(key)[:MAX_KEY]: REDACTED if secret_name(str(key)) else redact(item, secrets=secrets, depth=depth + 1)
            for key, item in list(value.items())[:MAX_FIELDS]
        }
    if isinstance(value, list):
        return [redact(item, secrets=secrets, depth=depth + 1) for item in value[:MAX_ITEMS]]
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, REDACTED)
        return _BEARER.sub(f"Bearer {REDACTED}", value)[:MAX_STRING]
    if type(value) is float and not isfinite(value):
        return None
    if value is None or type(value) in {bool, int, float}:
        return value
    return str(value)[:MAX_KEY]


def redact_text(text: str, *, secrets: Sequence[str] = (), max_chars: int) -> str:
    """One bounded, single-line, credential-free copy of external text, for an evidence detail or a rejection."""
    redacted = redact(str(text), secrets=secrets)
    collapsed = _UNSAFE_RUN.sub(" ", str(redacted)).strip()
    return collapsed[:max_chars]


def payload_of(value: JsonValue) -> dict[str, JsonValue]:
    """Evidence payloads are objects; a result that is not one is carried under ``result``."""
    return value if isinstance(value, dict) else {"result": value}


def has_more(value: JsonValue) -> bool:
    """Whether the result itself says it is one page of a longer answer, which makes the collection partial."""
    if isinstance(value, dict):
        count = value.get("count")
        for key in ("results", "data"):
            if isinstance(value.get(key), list):
                count = len(value[key])
        if type(count) is int and type(value.get("total")) is int and value["total"] > count:
            return True
        return bool(value.get("has_more") or value.get("next_cursor")) or any(has_more(item) for item in value.values())
    return isinstance(value, list) and any(has_more(item) for item in value)


def row_counts(value: Any) -> dict[str, int]:
    """How many rows each list of the *whole validated result* held, before redaction or any cut."""
    payload = value if isinstance(value, Mapping) else {"result": value}
    return {str(key)[:MAX_KEY]: len(item) for key, item in payload.items() if isinstance(item, list)}


def omits(value: Any, depth: int = 0) -> bool:
    """Whether :func:`redact` would leave anything out. A redacted secret is not an omission; a cut row is.

    A payload this is true of is never stored as ``full``: it would claim to be the whole result while holding
    only what the bounds kept.
    """
    if depth > MAX_DEPTH:
        return True
    if isinstance(value, Mapping):
        return len(value) > MAX_FIELDS or any(
            len(str(key)) > MAX_KEY or omits(item, depth + 1)
            for key, item in value.items()
            if not secret_name(str(key)) and "$encrypted" not in value
        )
    if isinstance(value, list):
        return len(value) > MAX_ITEMS or any(omits(item, depth + 1) for item in value)
    return isinstance(value, str) and len(value) > MAX_STRING


def shrink(
    payload: dict[str, JsonValue], *, rows: Mapping[str, int] | None = None, allow_full: bool = True
) -> Iterator[tuple[dict[str, JsonValue], EvidenceRepresentation, str]]:
    """The payload, then ever smaller digests of it, ending at counts that always fit.

    ``rows`` are the counts of the whole validated result, so a digest never understates how much the read
    returned, however much of it the digest itself shows. ``allow_full`` is false when redaction already cut the
    result, because what is left is a digest of it whether or not it would fit.
    """
    if allow_full:
        yield payload, "full", ""
    size = json_size(payload)
    rows = dict(rows) if rows is not None else {key: len(v) for key, v in payload.items() if isinstance(v, list)}
    keys = {key: type(value).__name__ for key, value in payload.items()}
    detail = f"The result exceeded the evidence bounds ({size} redacted bytes); it is stored as a digest."
    for shown in DIGEST_ROWS:
        header = {"original_bytes": size, "rows": rows, "keys": keys, "rows_shown": shown}
        kept = {key: value[:shown] for key, value in payload.items() if isinstance(value, list)}
        yield {"digest": header, **kept}, "digest", detail
    yield {"digest": {"original_bytes": size, "rows": rows, "keys": keys, "rows_shown": 0}}, "digest", detail
    yield {"digest": {"original_bytes": size, "row_count": sum(rows.values())}}, "digest", detail


def local_references_only(schema: Any) -> bool:
    """A discovered schema must never send validation to a URL the catalogue chose."""
    if isinstance(schema, Mapping):
        if any(
            key in schema and (not isinstance(schema[key], str) or not schema[key].startswith("#"))
            for key in _REFERENCES
        ):
            return False
        return all(local_references_only(item) for item in schema.values())
    if isinstance(schema, list):
        return all(local_references_only(item) for item in schema)
    return True


def compact_schema(schema: Any, *, drop: Sequence[str] = (), names: bool = False) -> JsonValue:
    """Keep types, enums, required fields and defaults, and drop prose and the named properties.

    Keys inside ``properties``-like maps are argument names, so a property called ``description`` survives.
    """
    if isinstance(schema, Mapping):
        if names:
            return {str(key): compact_schema(value, drop=drop) for key, value in schema.items() if str(key) not in drop}
        return {
            str(key): _compact_child(key, value, drop=drop)
            for key, value in schema.items()
            if str(key) not in _SCHEMA_PROSE
        }
    if isinstance(schema, list):
        return [compact_schema(item, drop=drop) for item in schema]
    return schema


def _compact_child(key: object, value: Any, *, drop: Sequence[str]) -> JsonValue:
    # ``required`` lists argument names, so a dropped argument leaves the schema it is dropped from satisfiable.
    if str(key) == "required" and isinstance(value, list):
        return [str(item) for item in value if str(item) not in drop]
    return compact_schema(value, drop=drop, names=str(key) in _SCHEMA_MAPS)
