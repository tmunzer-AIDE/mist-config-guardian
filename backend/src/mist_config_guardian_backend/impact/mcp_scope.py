"""Organization/time boundaries and redaction for generic Mist MCP operations."""

import json
import re
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
from math import fsum, isfinite
from typing import Any, ClassVar, Literal, get_args

# Dynamic JSON from MCP is validated at this boundary.
# ruff: noqa: ANN401
from uuid import UUID

from jsonschema import Draft202012Validator, SchemaError, ValidationError

from mist_config_guardian_backend.impact.mcp_contracts import MAX_MCP_EVIDENCE_BYTES, McpEvidence, McpTool, McpToolName

MAX_ARGUMENT_BYTES = 4000
MAX_DEPTH = 12
MAX_FIELDS = 100
MAX_ITEMS = 50
MAX_STRING = 2000
MAX_KEY = 120
MAX_CURSOR_BYTES = 4096

IGNORED = frozenset({"created_time", "modified_time", "image1_url", "image2_url", "image3_url", "thumbnail_url"})
_SECRET = re.compile(
    r"password|passphrase|secret|token|private.?key|api.?key|credential|^psk$|^key$|certificate", re.IGNORECASE
)


def sanitize(value: Any, *, secrets: tuple[str, ...] = (), depth: int = 0) -> Any:  # noqa: PLR0911 - bounded recursive JSON redaction
    if depth > MAX_DEPTH:
        return "[depth omitted]"
    if isinstance(value, dict):
        if "$encrypted" in value:
            return "[redacted]"
        return {
            str(k)[:MAX_KEY]: "[redacted]" if _SECRET.search(str(k)) else sanitize(v, secrets=secrets, depth=depth + 1)
            for k, v in list(value.items())[:MAX_FIELDS]
        }
    if isinstance(value, list):
        return [sanitize(v, secrets=secrets, depth=depth + 1) for v in value[:MAX_ITEMS]]
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, "[redacted]")
        return value[:MAX_STRING]
    if type(value) is float and not isfinite(value):
        return None
    if value is None or type(value) in {bool, int, float}:
        return value
    return str(value)[:120]


DIGEST_MAX_CATEGORIES = 20
DIGEST_MAX_DEVICES = 50
DIGEST_CONTEXT_BYTES = 4000
DIGEST_SHOWN_ROWS = (25, 10, 5, 2, 0)
# Last-resort summary cuts: (value/bucket entries, numeric fields, devices) per summarized list.
_DIGEST_TRIMS = ((40, 10, 20), (10, 5, 5), (0, 0, 0))
_TIME_FIELDS = ("timestamp", "time", "start", "_time")
_EPOCH_MILLISECONDS = 100_000_000_000
_MAC = re.compile(r"[0-9a-f]{12}")
_CONTEXT_OMITTED = "Value exceeded the digest context bound."


@dataclass(frozen=True)
class NormalizedResult:
    data: Any
    partial: bool
    reduction: Literal["none", "digest", "omitted"] = "none"
    # Tool-error keys detected in the full sanitized result, before any digest or omission could drop them.
    tool_error: bool = False


def _tool_error_signal(value: Any) -> bool:
    return isinstance(value, dict) and bool(
        value.get("error") or value.get("success") is False or value.get("status") == "error"
    )


def _size(value: Any) -> int:
    """Same measure as the evidence bound: UTF-8 bytes of non-ASCII-escaped JSON."""
    return len(json.dumps(value, ensure_ascii=False, default=str).encode())


def _row_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(item, dict) for item in value)


def _container(raw: Any) -> dict | None:
    return raw if isinstance(raw, dict) else {"rows": raw} if isinstance(raw, list) else None


def _truncated_rows(raw: Any) -> bool:
    container = _container(raw) or {}
    return any(_row_list(v) and len(v) > MAX_ITEMS for v in list(container.values())[:MAX_FIELDS])


_IDENTITY_KEYS = ("org_id", "site_id", "mac", "type", "device_type")


def _row_view(row: dict, *, secrets: tuple[str, ...]) -> dict:
    """The one sanitized copy of a row that both the authority check and the digest use.

    Identity keys survive the field bound and ``$encrypted`` redaction so the organization check always sees them;
    an encrypted row contributes nothing but its identity.
    """
    clean = sanitize(row, secrets=secrets)
    identity = {key: sanitize(row[key], secrets=secrets, depth=1) for key in _IDENTITY_KEYS if key in row}
    return {**(clean if isinstance(clean, dict) else {}), **identity}


def _row_views(raw: Any, *, secrets: tuple[str, ...]) -> dict[str, list[dict]]:
    """Every row a digest could aggregate, sanitized one by one so no list truncation hides a row."""
    container = _container(raw) or {}
    return {
        str(key)[:MAX_KEY]: [_row_view(row, secrets=secrets) for row in value]
        for key, value in list(container.items())[:MAX_FIELDS]
        if _row_list(value)
    }


def normalize_result_detail(
    result: dict,
    *,
    secrets: tuple[str, ...] = (),
    changed_at: datetime | None = None,
    authority: Callable[[Any], object] | None = None,
) -> NormalizedResult:
    """``authority`` raises to reject the whole result; it sees the same row copies a digest aggregates, first."""
    raw = result.get("structuredContent")
    if raw is None:
        texts = [c.get("text", "") for c in result.get("content", []) if c.get("type") == "text"]
        try:
            raw = json.loads("\n".join(texts))
        except ValueError:
            raw = {"text": "\n".join(texts)}
    cleaned = sanitize(raw, secrets=secrets)
    size = _size(cleaned)
    tool_error = _tool_error_signal(cleaned)
    # Oversized results, and row lists sanitize would silently cut, are summarized over every returned row.
    if size > MAX_MCP_EVIDENCE_BYTES or _truncated_rows(raw):
        rows = _row_views(raw, secrets=secrets)
        if authority is not None:
            authority([cleaned, *(row for views in rows.values() for row in views)])
        digest = digest_result(raw, secrets=secrets, changed_at=changed_at, rows=rows)
        if digest is not None:
            return NormalizedResult(digest, partial=True, reduction="digest", tool_error=tool_error)
        if size > MAX_MCP_EVIDENCE_BYTES:
            omitted = {"omitted": "MCP result exceeded the evidence bound; narrow the query."}
            return NormalizedResult(omitted, partial=True, reduction="omitted", tool_error=tool_error)
    # Any reduction is explicit; a bounded page never establishes fleet completeness.
    partial = json.dumps(raw, default=str) != json.dumps(cleaned, default=str)
    return NormalizedResult(cleaned, partial=partial or _has_more(cleaned), tool_error=tool_error)


def normalize_result(
    result: dict, *, secrets: tuple[str, ...] = (), changed_at: datetime | None = None
) -> tuple[Any, bool]:
    normalized = normalize_result_detail(result, secrets=secrets, changed_at=changed_at)
    return normalized.data, normalized.partial


def _number(value: Any) -> float | None:
    """Finite JSON numbers only; booleans, NaN, infinities and unrepresentable integers are not measurements."""
    if type(value) not in {int, float}:
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if isfinite(number) else None


def _epoch(value: Any) -> float | None:
    number = _number(value)
    if number is None or number <= 0:
        return None
    return number / 1000 if number >= _EPOCH_MILLISECONDS else number


def _summarize_rows(rows: list[dict], *, changed_at: datetime | None) -> dict:
    """Aggregate already-sanitized row views; nothing here reads a raw MCP value."""
    time_field = next((f for f in _TIME_FIELDS if any(_epoch(r.get(f)) is not None for r in rows)), None)
    pivot = changed_at.timestamp() if changed_at else None
    categories: dict[str, Counter[str]] = {}
    high_cardinality: set[str] = set()
    buckets: dict[tuple[str, str], list[int]] = {}
    numeric: dict[str, list[float]] = {}
    devices: dict[tuple[str, str], dict] = {}
    for row in rows:
        instant = _epoch(row.get(time_field)) if time_field else None
        side = None if instant is None or pivot is None else int(instant >= pivot)
        for name, value in row.items():
            if name == time_field or _SECRET.search(name):
                continue
            if isinstance(value, str):
                if name in high_cardinality:
                    continue
                text = value[:120]
                counts = categories.setdefault(name, Counter())
                counts[text] += 1
                if len(counts) > DIGEST_MAX_CATEGORIES:
                    # Identifiers and free text are not categories; stop tracking them to bound memory.
                    high_cardinality.add(name)
                    del categories[name]
                    buckets = {k: v for k, v in buckets.items() if k[0] != name}
                elif side is not None:
                    buckets.setdefault((name, text), [0, 0])[side] += 1
            elif (number := _number(value)) is not None:
                numeric.setdefault(name, []).append(number)
        mac = str(row.get("mac", "")).replace(":", "").lower()
        if _MAC.fullmatch(mac) and len(devices) < DIGEST_MAX_DEVICES:
            # Any scalar identity is kept, so a non-string org_id still stops ``observe`` from learning the device.
            identity = {
                k: row[k]
                for k in ("org_id", "site_id", "type", "device_type")
                if row.get(k) is not None and not isinstance(row[k], (dict, list))
            }
            devices.setdefault((str(identity.get("site_id", "")), mac), {**identity, "mac": mac})
    return {
        "row_count": len(rows),
        "time_field": time_field,
        "changed_at": int(pivot) if pivot is not None else None,
        "value_counts": [
            {"field": name, "value": value, "count": count}
            for name, counts in sorted(categories.items())
            for value, count in counts.most_common()
        ],
        "change_buckets": [
            {"field": name, "value": value, "before_change": before, "after_change": after}
            for (name, value), (before, after) in sorted(buckets.items())
        ],
        "numeric": [
            {
                "field": name,
                "count": len(xs),
                "min": min(xs),
                "max": max(xs),
                # Divide before summing so large finite values cannot overflow to infinity.
                "avg": round(fsum(x / len(xs) for x in xs), 3),
            }
            for name, xs in sorted(numeric.items())
        ],
        "devices": list(devices.values()),
    }


def _digest_context(items: list[tuple[str, Any]], lists: dict[str, Any], *, secrets: tuple[str, ...]) -> dict:
    context = {}
    for name, value in items:
        if name in lists:
            continue
        clean = "[redacted]" if _SECRET.search(name) else sanitize(value, secrets=secrets)
        # An oversized value stays visibly present (e.g. an ``error`` key) rather than silently disappearing.
        context[name] = clean if _size(clean) <= DIGEST_CONTEXT_BYTES else {"omitted": _CONTEXT_OMITTED}
    return context


def digest_result(
    raw: Any,
    *,
    secrets: tuple[str, ...] = (),
    changed_at: datetime | None = None,
    rows: dict[str, list[dict]] | None = None,
) -> dict | None:
    """Summarize every returned row server-side so oversized evidence stays bounded and citable.

    ``rows`` are the sanitized row views already checked by the caller's authority; shown rows and every
    aggregate come from exactly those copies.
    """
    container = _container(raw)
    if container is None:
        return None
    items = [(str(k)[:MAX_KEY], v) for k, v in list(container.items())[:MAX_FIELDS]]
    lists = _row_views(raw, secrets=secrets) if rows is None else rows
    if not lists:
        return None
    context = _digest_context(items, lists, secrets=secrets)
    summaries = {k: _summarize_rows(v, changed_at=changed_at) for k, v in lists.items()}
    header = {
        "reason": "Result exceeded the evidence bound or row limit; Guardian summarized every returned row.",
        "original_bytes": _size(raw),
    }

    def assemble(shown: int, extra: dict, trimmed: list[str]) -> dict:
        body = {
            **extra,
            **{k: v[:shown] for k, v in lists.items()},
            **{f"{k}_summary": s for k, s in summaries.items()},
        }
        digest = {"digest": {**header, "rows_shown_per_list": shown, "trimmed": trimmed}}
        return {**digest, **{k: v for k, v in body.items() if k != "digest"}}

    for shown in DIGEST_SHOWN_ROWS:
        if _size(digest := assemble(shown, context, [])) <= MAX_MCP_EVIDENCE_BYTES:
            return digest
    for entries, fields, identities in _DIGEST_TRIMS:
        for summary in summaries.values():
            summary.update(
                value_counts=summary["value_counts"][:entries],
                change_buckets=summary["change_buckets"][:entries],
                numeric=summary["numeric"][:fields],
                devices=summary["devices"][:identities],
            )
        for extra, trimmed in ((context, ["summaries"]), ({}, ["summaries", "context"])):
            if _size(digest := assemble(0, extra, trimmed)) <= MAX_MCP_EVIDENCE_BYTES:
                return digest
    return None


def _has_more(value: Any) -> bool:
    if isinstance(value, dict):
        count = value.get("count")
        for key in ("results", "data"):
            if isinstance(value.get(key), list):
                count = len(value[key])
        if type(count) is int and type(value.get("total")) is int and value["total"] > count:
            return True
        return bool(value.get("has_more") or value.get("next_cursor")) or any(_has_more(v) for v in value.values())
    if isinstance(value, list):
        return any(_has_more(v) for v in value)
    return False


def catalog(rows: list[dict]) -> tuple[McpTool, ...]:
    result = []
    for row in rows:
        if row.get("name") not in get_args(McpToolName) or row.get("annotations", {}).get("readOnlyHint") is not True:
            continue
        schema = row.get("inputSchema")
        if not isinstance(schema, dict):
            msg = "Tool schema must be an object"
            raise McpScopeError(msg)
        _local_references(schema)
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError:
            msg = "MCP returned an invalid JSON schema"
            raise McpScopeError(msg) from None
        result.append(
            McpTool(
                name=row["name"],
                description=row.get("description", "")[:16000],
                input_schema=schema,
                schema_hash=sha256(json.dumps(schema, sort_keys=True).encode()).hexdigest(),
            )
        )
    return tuple(result)


class McpScopeError(ValueError):
    """Guardian-authored rejection text; ``category`` is a ModelResponseError value."""

    category: ClassVar[str] = "argument_out_of_scope"


class McpToolNotDiscoveredError(McpScopeError):
    category: ClassVar[str] = "tool_not_discovered"


class McpCitationError(McpScopeError):
    category: ClassVar[str] = "citation_invalid"


class McpOutputTooLargeError(McpScopeError):
    category: ClassVar[str] = "output_too_large"


class McpToolCallLimitError(McpScopeError):
    category: ClassVar[str] = "tool_call_limit"


_BEARER = re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+")
_LOCATION = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,40}$")


def bounded_text(value: str, *, secrets: tuple[str, ...] = (), max_bytes: int) -> str:
    """Redact credentials and bearer values, then cut to a UTF-8 byte bound."""
    text = _BEARER.sub("Bearer [redacted]", str(sanitize(str(value), secrets=secrets)))
    return text.encode()[:max_bytes].decode(errors="ignore")


def safe_location(parts: Iterable[object]) -> str:
    """Render a validation path; model-authored key names that are not plain identifiers are masked."""
    rendered = [str(part) if isinstance(part, int) or _LOCATION.fullmatch(str(part)) else "?" for part in parts]
    return ".".join(rendered) or "<root>"


class McpScope:
    def __init__(
        self,
        *,
        org_id: UUID,
        changed_at: datetime,
        as_of: datetime,
        sites: Iterable[str] = (),
        configuration_incomplete: bool = False,
    ) -> None:
        self.configuration_incomplete = configuration_incomplete
        self.org_id = str(org_id)
        self.start = changed_at - timedelta(hours=1)
        self.end = as_of
        self.sites = {str(UUID(s)) for s in sites}
        self.devices: set[tuple[str, str]] = set()
        self.cursors: dict[str, tuple[str, dict]] = {}

    def arguments(self, tool: McpTool, supplied: dict) -> dict:  # noqa: C901, PLR0912 - independent scope constraints
        if len(json.dumps(supplied).encode()) > MAX_ARGUMENT_BYTES:
            msg = "Tool arguments exceed the bounded request size"
            raise McpScopeError(msg)
        args = dict(supplied)
        if cursor := args.get("next_cursor"):
            previous = self.cursors.get(cursor)
            if not previous or previous[0] != tool.name:
                msg = "Cursor must come from this investigation and tool"
                raise McpScopeError(msg)
            args = {**previous[1], "next_cursor": cursor}
        self._scopes(args)
        properties = tool.input_schema.get("properties", {})
        if not isinstance(properties, dict):
            msg = "Tool properties must be an object"
            raise McpScopeError(msg)
        if set(args) - set(properties):
            msg = "Unknown MCP argument"
            raise McpScopeError(msg)
        if "org_id" in properties:
            args["org_id"] = self.org_id
        if tool.name != "get_mist_constants" and "org_id" not in properties:
            msg = "Tool cannot be organization scoped"
            raise McpScopeError(msg)
        if "limit" in properties:
            if type(args.get("limit", 25)) is not int or args.get("limit", 25) < 1:
                msg = "Limit must be a positive integer"
                raise McpScopeError(msg)
            args["limit"] = min(args.get("limit", 25), 50)
        if "duration" in args:
            msg = "Use explicit start_time and end_time within the audit window"
            raise McpScopeError(msg)
        if "start_time" in properties and (
            "start_time" in args or tool.name in {"search_mist_data", "get_mist_insights"}
        ):
            args.setdefault("start_time", str(int(self.start.timestamp())))
            args.setdefault("end_time", str(int(self.end.timestamp())))
            try:
                start, end = float(args["start_time"]), float(args["end_time"])
                if not self.start.timestamp() - 1 <= start < end <= self.end.timestamp():
                    raise ValueError  # noqa: TRY301 - normalize invalid numeric windows
            except (ValueError, TypeError):
                msg = "Query time range must stay within the audit evidence window"
                raise McpScopeError(msg) from None
        try:
            Draft202012Validator(tool.input_schema).validate(args)
        except ValidationError as exc:
            msg = (
                f"Arguments do not match the discovered MCP schema at {safe_location(exc.absolute_path)}: "
                f"'{exc.validator}' constraint"
            )
            raise McpScopeError(msg) from None
        return args

    def _scopes(self, value: Any) -> None:  # noqa: C901 - recursive time, tenant and credential constraints
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "org_id" and str(child) != self.org_id:
                    msg = "Cross-organization query rejected"
                    raise McpScopeError(msg)
                if key == "site_id" and str(child) not in self.sites:
                    msg = "Discover this site through an organization-scoped MCP result first"
                    raise McpScopeError(msg)
                if key in {"duration", "headers", "authorization", "url", "base_url", "host"}:
                    msg = "Unbounded time or transport overrides are not permitted"
                    raise McpScopeError(msg)
                if key in {"start", "end", "start_time", "end_time"}:
                    try:
                        instant = float(child)
                    except (TypeError, ValueError):
                        msg = "Nested query timestamps must be explicit epoch values"
                        raise McpScopeError(msg) from None
                    if not self.start.timestamp() - 1 <= instant <= self.end.timestamp():
                        msg = "Nested query timestamp is outside the investigation window"
                        raise McpScopeError(msg)
                if _SECRET.search(key):
                    msg = "Credential arguments are not accepted"
                    raise McpScopeError(msg)
                self._scopes(child)
        elif isinstance(value, list):
            for child in value:
                self._scopes(child)

    def validate_response(self, value: Any) -> None:
        if isinstance(value, dict):
            if "org_id" in value and (value["org_id"] is not None and str(value["org_id"]) != self.org_id):
                msg = "MCP returned a foreign organization identity"
                raise McpScopeError(msg)
            for child in value.values():
                self.validate_response(child)
        elif isinstance(value, list):
            for child in value:
                self.validate_response(child)

    @staticmethod
    def contains_device(evidence: McpEvidence, site: UUID, mac: str) -> bool:
        def walk(value: object, inherited: str | None = None) -> bool:
            if isinstance(value, dict):
                here = str(value.get("site_id", inherited or evidence.arguments.get("site_id", "")))
                if here == str(site) and str(value.get("mac", "")).replace(":", "").lower() == mac:
                    return True
                return any(walk(child, here) for child in value.values())
            return isinstance(value, list) and any(walk(child, inherited) for child in value)

        return walk(evidence.data)

    def observe(self, tool: str, args: dict, data: Any) -> None:  # noqa: C901 - validated response traversal
        # Only successful scoped calls may register discovery identities and cursors.
        def walk(value: Any, inherited_site: str | None = None) -> None:  # noqa: C901 - discovery fields
            if isinstance(value, dict):
                if value.get("org_id") not in {None, self.org_id}:
                    return
                site = value.get("site_id", inherited_site or args.get("site_id"))
                if tool == "get_mist_config" and args.get("resource_type") == "sites" and value.get("id"):
                    try:
                        site = str(UUID(str(value["id"])))
                        self.sites.add(site)
                    except ValueError:
                        pass
                if site:
                    try:
                        site = str(UUID(str(site)))
                        self.sites.add(site)
                    except ValueError:
                        site = None
                kind = str(value.get("type", value.get("device_type", "")))
                physical = kind in {"ap", "switch", "gateway"} or (
                    args.get("search_type") == "device_events" and kind.startswith(("AP_", "SW_", "GW_"))
                )
                if physical and site in self.sites and re.fullmatch(r"[0-9a-fA-F]{12}", str(value.get("mac", ""))):
                    self.devices.add((site, value["mac"].lower()))
                cursor = value.get("next_cursor")
                if isinstance(cursor, str) and len(cursor) <= MAX_CURSOR_BYTES:
                    self.cursors[cursor] = (tool, {k: v for k, v in args.items() if k != "next_cursor"})
                for child in value.values():
                    walk(child, site)
            elif isinstance(value, list):
                for child in value:
                    walk(child, inherited_site)

        walk(data)


def _local_references(value: Any) -> None:
    """JSON schema validation must never fetch a URL supplied by the MCP catalogue."""
    if isinstance(value, dict):
        if any(
            k in value and (not isinstance(value[k], str) or not value[k].startswith("#"))
            for k in ("$ref", "$dynamicRef")
        ):
            msg = "Only local schema references are accepted"
            raise McpScopeError(msg)
        for child in value.values():
            _local_references(child)
    elif isinstance(value, list):
        for child in value:
            _local_references(child)


_SCHEMA_MAPS = frozenset({"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"})
_SCHEMA_PROSE = frozenset({"description", "examples", "title", "$comment"})


def compact_schema(schema: Any, *, names: bool = False) -> Any:
    """Keep types, enums, required fields and defaults; full property documentation stays in describe.

    Keys inside ``properties``-like maps are argument names, so a property called ``description`` survives.
    """
    if isinstance(schema, dict):
        if names:
            return {key: compact_schema(value) for key, value in schema.items()}
        return {
            key: compact_schema(value, names=key in _SCHEMA_MAPS)
            for key, value in schema.items()
            if key not in _SCHEMA_PROSE
        }
    if isinstance(schema, list):
        return [compact_schema(value) for value in schema]
    return schema


def has_omissions(value: Any, depth: int = 0) -> bool:
    """Distinguish truncation from expected credential redaction in configuration context."""
    if depth > MAX_DEPTH:
        return True
    if isinstance(value, dict):
        return len(value) > MAX_FIELDS or any(
            len(str(k)) > MAX_KEY or has_omissions(v, depth + 1) for k, v in value.items() if not _SECRET.search(str(k))
        )
    if isinstance(value, list):
        return len(value) > MAX_ITEMS or any(has_omissions(v, depth + 1) for v in value)
    return isinstance(value, str) and len(value) > MAX_STRING
