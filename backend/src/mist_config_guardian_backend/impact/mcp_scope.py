"""Organization/time boundaries and redaction for generic Mist MCP operations."""

import json
import re
from collections.abc import Iterable
from datetime import datetime, timedelta
from hashlib import sha256
from math import isfinite
from typing import Any, ClassVar, get_args

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


def normalize_result(result: dict, *, secrets: tuple[str, ...] = ()) -> tuple[Any, bool]:
    raw = result.get("structuredContent")
    if raw is None:
        texts = [c.get("text", "") for c in result.get("content", []) if c.get("type") == "text"]
        try:
            raw = json.loads("\n".join(texts))
        except ValueError:
            raw = {"text": "\n".join(texts)}
    cleaned = sanitize(raw, secrets=secrets)
    # Any reduction is explicit; a bounded page never establishes fleet completeness.
    partial = json.dumps(raw, default=str) != json.dumps(cleaned, default=str)
    if len(json.dumps(cleaned, ensure_ascii=False).encode()) > MAX_MCP_EVIDENCE_BYTES:
        return {"omitted": "MCP result exceeded the evidence bound; narrow the query."}, True
    return cleaned, partial or _has_more(cleaned)


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
