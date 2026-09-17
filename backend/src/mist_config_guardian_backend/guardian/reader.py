"""The Reader: the single guarded path for every external read an attempt makes.

Rule plug-ins and the MCP agent never reach a network themselves. They ask the Reader, which checks the phase
deadline, charges the per-attempt budget, assigns the E-id at reservation, enforces the organization and the site
authority fixed at attempt start, redacts what comes back and bounds it into one :class:`Evidence` item.

The Reader is an I/O *boundary*, not an I/O module: both transports are injected protocols, so the module imports
no client, no settings and no database, and the pure-core tests keep it honest. Its guarantees:

- **Allowlist.** An MCP tool, and the discriminating argument that decides its evidence kind, must be in the frozen
  table in :mod:`.mcp_allowlist` *and* in the catalogue discovered for this attempt.
- **Schema.** Arguments validate against the discovered input schema, whose ``$ref``s must be local.
- **Organization.** Guardian injects ``org_id``; another organization is rejected, in an argument and in a result.
- **Site.** Authority is fixed when the attempt starts. An org-wide result can never add a site to a site-scoped
  investigation, and service-health reads of a site-scoped investigation name one of its sites.
- **Time.** A historical read asks for exactly ``before``, exactly ``after``, or the two combined. ``duration`` is
  rejected. Current state is read only through a tool that takes no time range at all.
- **Transport.** At most 1 MB of wire bytes, separate from the 4 KB an evidence item may keep.
- **Cache.** Only a successful call is cached, keyed by tool and canonical arguments; a hit returns the same E-id
  at no budget cost, and a failed call stays retryable.

Nothing here logs: every detail that reaches storage or a prompt is redacted and bounded first.
"""

import json
import re
import time
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal, Protocol

from jsonschema import Draft202012Validator, SchemaError, ValidationError
from jsonschema.protocols import Validator
from pydantic import Field, JsonValue, StringConstraints, model_validator

from mist_config_guardian_backend.guardian import mcp_allowlist, payloads
from mist_config_guardian_backend.guardian.contracts import (
    MAX_DETAIL_CHARS,
    MAX_MCP_CALLS,
    MAX_RULE_READS,
    Contract,
    DeviceMac,
    Evidence,
    EvidenceKind,
    EvidenceScope,
    EvidenceWindow,
    Identifier,
    PluginId,
    RunBudget,
    Text,
)
from mist_config_guardian_backend.guardian.evidence import (
    MCP_EVIDENCE_ITEM_BUDGET,
    RULE_EVIDENCE_ITEM_BUDGET,
    EvidenceRegistry,
    json_size,
)

# Dynamic JSON from an external read is validated at this boundary, and every ``timeout`` here is the transport's
# own request bound, which an asyncio timeout would not give the transport a chance to apply.
# ruff: noqa: ANN401, ASYNC109

CALL_TIMEOUT_CEILING = 20.0
MAX_TRANSPORT_BYTES = 1_000_000
MAX_CATALOGUE_TOOLS = 100
WINDOW_CAP = timedelta(minutes=60)

Phase = Literal["rule", "agent"]
WindowName = Literal["before", "after", "combined"]
WINDOW_NAMES: tuple[WindowName, ...] = ("before", "after", "combined")
RejectionCategory = Literal["tool_not_allowed", "argument_invalid", "out_of_scope", "call_budget"]

_REJECTED_ARGUMENTS: Mapping[str, str] = {
    "duration": "Ask for one of the fixed windows with start_time and end_time; duration is not accepted.",
    "next_cursor": "A cursor ignores every other argument, including scope; narrow the query instead.",
    "page": "Paging is not available in an attempt; narrow the query instead.",
}
_RULE_TIME_PARAMS = frozenset({"start", "end", "start_time", "end_time", "duration"})
_TIME_ARGUMENTS = ("start_time", "end_time")
_PATH_SCOPE = re.compile(r"/(orgs|sites)/([^/]+)")
# The only route a rule read may take without naming an organization or a site: Mist's platform constants.
_ORG_NEUTRAL_PREFIX = "/api/v1/const/"
_SAFE_LOCATION = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,40}$")
_INTEGER_TYPES = frozenset({"integer", "number"})


class TransportError(RuntimeError):
    """An injected transport could not deliver a result. Its text is redacted and bounded before it is stored."""


class DeadlineExpiredError(RuntimeError):
    """The phase deadline has passed, so no external call may start."""


class ReadRejectedError(ValueError):
    """A read the Reader refuses to make. ``category`` is the rejection category the agent is told."""

    def __init__(self, detail: str, *, category: RejectionCategory) -> None:
        self.category: RejectionCategory = category
        self.detail = payloads.redact_text(detail, max_chars=MAX_DETAIL_CHARS)
        super().__init__(f"{category}: {self.detail}")


@dataclass(frozen=True, slots=True)
class ReadWindows:
    """The attempt's fixed evidence windows. Every historical read uses one of them, unchanged."""

    changed_at: datetime
    as_of: datetime
    duration: timedelta
    before: EvidenceWindow
    after: EvidenceWindow
    combined: EvidenceWindow

    def named(self, name: WindowName) -> EvidenceWindow:
        """The window one name stands for."""
        return {"before": self.before, "after": self.after, "combined": self.combined}[name]

    @property
    def epochs(self) -> dict[WindowName, tuple[int, int]]:
        """Each window as the pair of epoch seconds the agent is given."""
        return {name: _epochs(self.named(name)) for name in WINDOW_NAMES}

    def match(self, start: Any, end: Any) -> tuple[WindowName, EvidenceWindow] | None:
        """The window a requested range is exactly, or ``None`` for every other range."""
        requested = (_seconds(start), _seconds(end))
        if None in requested:
            return None
        return next(((name, self.named(name)) for name in WINDOW_NAMES if self.epochs[name] == requested), None)


def evidence_windows(changed_at: datetime, as_of: datetime) -> ReadWindows:
    """``duration = min(60 min, as_of - changed_at)``, with equal windows on each side of the change."""
    duration = min(WINDOW_CAP, max(as_of - changed_at, timedelta(0)))
    return ReadWindows(
        changed_at=changed_at,
        as_of=as_of,
        duration=duration,
        before=EvidenceWindow(start=changed_at - duration, end=changed_at),
        after=EvidenceWindow(start=changed_at, end=changed_at + duration),
        combined=EvidenceWindow(start=changed_at - duration, end=changed_at + duration),
    )


@dataclass(frozen=True, slots=True)
class SiteAuthority:
    """The sites an attempt may read, fixed from the expected devices and changed objects when it starts."""

    site_ids: frozenset[str] = frozenset()
    org_wide: bool = False

    def allows(self, site_id: str) -> bool:
        """Whether a site was authorized at attempt start. Nothing a result says can add one."""
        return site_id in self.site_ids


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """One discovered, allowlisted, read-only tool, with the scope facts frozen in the allowlist.

    ``requires_org``, ``site_scopable`` and ``time_ranged`` come from :mod:`.mcp_allowlist`, never from the
    advertised schema, and a schema that contradicts them is rejected at discovery: a server could otherwise
    disable organization injection, the site rule or the window rule by dropping one argument from what it
    advertises.
    """

    name: str
    discriminator: str
    input_schema: dict[str, JsonValue]
    prompt_schema: dict[str, JsonValue]
    validator: Validator
    properties: Mapping[str, Mapping[str, Any]]
    requires_org: bool
    site_scopable: bool
    time_ranged: bool


@dataclass(frozen=True, slots=True)
class _Envelope:
    """Everything about one read that is fixed before it is made, and identical for its success and its failure."""

    identity: str
    source: str
    kind: EvidenceKind
    title: str
    captured_at: datetime
    window: EvidenceWindow | None
    scope: EvidenceScope

    def evidence(self, **fields: Any) -> Evidence:
        """One evidence item of this read: the envelope, plus what the result turned out to be."""
        return Evidence(
            id=self.identity,
            source=self.source,
            kind=self.kind,
            title=self.title,
            captured_at=self.captured_at,
            window=self.window,
            scope=self.scope,
            **fields,
        )


@dataclass(frozen=True, slots=True)
class ToolCatalogue:
    """What this attempt may call, and why anything discovered was left out."""

    tools: Mapping[str, ToolSpec]
    rejected: Mapping[str, str]


class McpTransport(Protocol):
    """The MCP client the Reader is given. It raises :class:`TransportError` and bounds the wire itself."""

    async def list_tools(self, *, timeout: float, max_bytes: int) -> Mapping[str, Any]:
        """Return the raw ``tools/list`` result."""
        ...

    async def call_tool(
        self, name: str, arguments: Mapping[str, JsonValue], *, timeout: float, max_bytes: int
    ) -> Mapping[str, Any]:
        """Return the raw ``tools/call`` result."""
        ...


class RuleTransport(Protocol):
    """The bounded Mist read a rule plug-in needs. It raises :class:`TransportError` and bounds the wire itself."""

    async def fetch(self, path: str, params: Mapping[str, str], *, timeout: float, max_bytes: int) -> Any:
        """Return one parsed Mist response."""
        ...


class RuleRead(Contract):
    """One read a rule plug-in asks for. The Reader owns the time range; the plug-in names which window."""

    plugin: PluginId
    title: Text
    kind: Literal["service_health", "configuration", "reference"]
    path: Annotated[str, StringConstraints(min_length=1, max_length=300, pattern=r"^/[A-Za-z0-9/_.\-]*$")]
    params: dict[str, str] = Field(default_factory=dict)
    site_id: Identifier | None = None
    device_macs: tuple[DeviceMac, ...] = ()
    window: WindowName | None = None
    # Platform constants belong to no organization. Every other read names one of Guardian's own scopes, so a
    # route that carries no organization and no site (``/self``, ``/self/apitokens``) cannot be read at all.
    org_neutral: bool = False

    @model_validator(mode="after")
    def path_is_one_plain_route(self) -> "RuleRead":
        if ".." in self.path or "//" in self.path:
            msg = "A read path names one plain route"
            raise ValueError(msg)
        return self


class Reader:
    """One attempt's bounded, tenant-safe access to Mist, through injected transports."""

    def __init__(  # noqa: PLR0913 - one injected collaborator or fixed bound per argument
        self,
        *,
        org_id: str,
        authority: SiteAuthority,
        windows: ReadWindows,
        registry: EvidenceRegistry,
        deadlines: Mapping[str, float],
        rule_allowances: Mapping[str, int],
        mcp_transport: McpTransport | None = None,
        rule_transport: RuleTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
        secrets: Sequence[str] = (),
    ) -> None:
        self._org_id = org_id
        self._authority = authority
        self._windows = windows
        self._registry = registry
        self._deadlines = deadlines
        self._rule_allowances = rule_allowances
        self._mcp = mcp_transport
        self._rules = rule_transport
        self._clock = clock
        self._secrets = tuple(secrets)
        self._catalogue: ToolCatalogue | None = None
        self._catalogue_calls = 0
        self._mcp_calls = 0
        self._rule_reads = 0
        self._plugin_reads: Counter[str] = Counter()
        self._dropped: dict[str, str] = {}
        self._cache: dict[str, Evidence] = {}

    @property
    def org_id(self) -> str:
        """The organization Guardian injects into every read."""
        return self._org_id

    @property
    def authority(self) -> SiteAuthority:
        """The site authority fixed at attempt start; it never grows."""
        return self._authority

    @property
    def windows(self) -> ReadWindows:
        """The attempt's fixed evidence windows."""
        return self._windows

    @property
    def budget(self) -> RunBudget:
        """What this attempt has spent. Model turns belong to the agent loop, not to the Reader."""
        return RunBudget(mcp_calls=self._mcp_calls, rule_reads=self._rule_reads)

    @property
    def catalogue_calls(self) -> int:
        """Catalogue discoveries, which are tracked apart from the attempt's MCP call budget."""
        return self._catalogue_calls

    # -- MCP ---------------------------------------------------------------
    async def tools(self) -> ToolCatalogue:
        """Discover the allowlisted tools once per attempt; a failure leaves an empty, explained catalogue."""
        if self._catalogue is not None:
            return self._catalogue
        self._catalogue_calls += 1
        try:
            if self._mcp is None:
                msg = "No MCP transport is configured for this attempt."
                raise TransportError(msg)  # noqa: TRY301 - one place builds the empty catalogue
            result = await self._mcp.list_tools(timeout=self._timeout("agent"), max_bytes=MAX_TRANSPORT_BYTES)
        except (TransportError, DeadlineExpiredError) as exc:
            self._catalogue = ToolCatalogue(tools={}, rejected={"*": _detail(exc)})
            return self._catalogue
        self._catalogue = _dropping(_catalogue(result), self._dropped)
        return self._catalogue

    def drop_tools(self, names: Iterable[str], reason: str) -> ToolCatalogue:
        """Take tools out of this attempt's catalogue, for example when they do not fit the prompt's budget.

        A dropped tool is not allowlisted for the rest of the attempt: calling it is rejected like any other tool
        outside the allowlist, and the catalogue says why, so the attempt can report it as a gap.
        """
        self._dropped |= {str(name): reason for name in names}
        if self._catalogue is not None:
            self._catalogue = _dropping(self._catalogue, self._dropped)
        return self._catalogue or ToolCatalogue(tools={}, rejected=dict(self._dropped))

    async def call(self, tool: str, arguments: Mapping[str, JsonValue]) -> Evidence:
        """Make one allowlisted MCP call and record what it returned as evidence."""
        catalogue = await self.tools()
        kind = mcp_allowlist.evidence_kind(tool, arguments)
        spec = catalogue.tools.get(tool)
        if kind is None or spec is None:
            msg = f"{tool} is not an allowlisted read discovered for this attempt."
            raise ReadRejectedError(msg, category="tool_not_allowed")
        prepared, window, name = self._mcp_arguments(spec, arguments, kind)
        key = _canonical(tool, prepared)
        if (cached := self._cache.get(key)) is not None:
            return cached
        timeout = self._timeout("agent")
        if self._mcp_calls >= MAX_MCP_CALLS:
            msg = f"This attempt's {MAX_MCP_CALLS} MCP calls are spent."
            raise ReadRejectedError(msg, category="call_budget")
        self._mcp_calls += 1
        site = prepared.get("site_id")
        envelope = _Envelope(
            identity=self._registry.reserve(f"mcp:{tool}"),
            source=f"mcp:{tool}",
            kind=kind,
            title=f"{tool} {prepared[spec.discriminator]}" + (f" ({name})" if name else ""),
            captured_at=self._windows.as_of,
            window=window,
            scope=EvidenceScope(site_ids=(str(site),) if isinstance(site, str) else ()),
        )
        try:
            if self._mcp is None:  # pragma: no cover - a catalogue exists only when a transport does
                msg = "No MCP transport is configured for this attempt."
                raise TransportError(msg)  # noqa: TRY301 - one place builds the error evidence
            result = await self._mcp.call_tool(tool, prepared, timeout=timeout, max_bytes=MAX_TRANSPORT_BYTES)
        except TransportError as exc:
            return self._failed(envelope, _detail(exc))
        raw, failure = _tool_result(result)
        if failure is not None:
            return self._failed(envelope, failure)
        return self._recorded(envelope, raw, budget=MCP_EVIDENCE_ITEM_BUDGET, cache_key=key)

    # -- rule reads --------------------------------------------------------
    async def read(self, request: RuleRead) -> Evidence:
        """Make one bounded Mist read for a rule plug-in and record it as that plug-in's evidence."""
        params = self._rule_params(request)
        timeout = self._timeout("rule")
        allowance = self._rule_allowances.get(request.plugin)
        if allowance is None or self._plugin_reads[request.plugin] >= allowance:
            msg = f"Plug-in {request.plugin} has spent its reads for this attempt."
            raise ReadRejectedError(msg, category="call_budget")
        if self._rule_reads >= MAX_RULE_READS:
            msg = f"This attempt's {MAX_RULE_READS} rule reads are spent."
            raise ReadRejectedError(msg, category="call_budget")
        self._rule_reads += 1
        self._plugin_reads[request.plugin] += 1
        envelope = _Envelope(
            identity=self._registry.reserve(f"rule:{request.plugin}"),
            source=f"rule:{request.plugin}",
            kind=request.kind,
            title=request.title,
            captured_at=self._windows.as_of,
            window=self._windows.named(request.window) if request.window else None,
            scope=EvidenceScope(
                site_ids=(request.site_id,) if request.site_id else (), device_macs=request.device_macs
            ),
        )
        try:
            if self._rules is None:
                msg = "No Mist transport is configured for this attempt."
                raise TransportError(msg)  # noqa: TRY301 - one place builds the error evidence
            raw = await self._rules.fetch(request.path, params, timeout=timeout, max_bytes=MAX_TRANSPORT_BYTES)
        except TransportError as exc:
            return self._failed(envelope, _detail(exc))
        return self._recorded(envelope, raw, budget=RULE_EVIDENCE_ITEM_BUDGET)

    # -- internals ---------------------------------------------------------
    def _timeout(self, phase: Phase) -> float:
        """The call timeout, and the deadline check: no external call starts after its phase has ended."""
        remaining = self._deadlines[phase] - self._clock()
        if remaining <= 0:
            msg = f"The {phase} phase deadline has passed."
            raise DeadlineExpiredError(msg)
        return min(CALL_TIMEOUT_CEILING, remaining)

    def _mcp_arguments(
        self, spec: ToolSpec, arguments: Mapping[str, JsonValue], kind: EvidenceKind
    ) -> tuple[dict[str, JsonValue], EvidenceWindow | None, WindowName | None]:
        prepared = {name: value for name, value in arguments.items() if self._argument_allowed(spec, name)}
        if spec.requires_org:
            supplied = prepared.get("org_id")
            if supplied is not None and str(supplied) != self._org_id:
                msg = "Guardian reads one organization; another was requested."
                raise ReadRejectedError(msg, category="out_of_scope")
            prepared["org_id"] = self._org_id
        self._check_site(spec, prepared, kind)
        window, name = self._check_window(spec, prepared)
        try:
            spec.validator.validate(prepared)
        except ValidationError as exc:
            msg = f"The arguments do not match the discovered schema at {_location(exc.absolute_path)}."
            raise ReadRejectedError(msg, category="argument_invalid") from None
        return prepared, window, name

    @staticmethod
    def _argument_allowed(spec: ToolSpec, name: str) -> bool:
        if (reason := _REJECTED_ARGUMENTS.get(name)) is not None:
            raise ReadRejectedError(reason, category="argument_invalid")
        if payloads.secret_name(name):
            msg = "Credential arguments are not accepted."
            raise ReadRejectedError(msg, category="argument_invalid")
        if name not in spec.properties:
            msg = f"{name} is not an argument of {spec.name}."
            raise ReadRejectedError(msg, category="argument_invalid")
        return True

    def _check_site(self, spec: ToolSpec, prepared: Mapping[str, JsonValue], kind: EvidenceKind) -> None:
        site = prepared.get("site_id")
        if site is not None and not self._authority.allows(str(site)):
            msg = "That site is outside this investigation's site authority."
            raise ReadRejectedError(msg, category="out_of_scope")
        service_health = kind == "service_health"
        if site is None and spec.site_scopable and service_health and not self._authority.org_wide:
            msg = "A site-scoped investigation reads service health one authorized site at a time."
            raise ReadRejectedError(msg, category="out_of_scope")

    def _check_window(
        self, spec: ToolSpec, prepared: dict[str, JsonValue]
    ) -> tuple[EvidenceWindow | None, WindowName | None]:
        if not spec.time_ranged:
            return None, None
        matched = self._windows.match(prepared.get("start_time"), prepared.get("end_time"))
        if matched is None:
            msg = "A historical read asks for exactly the before window, the after window, or the two combined."
            raise ReadRejectedError(msg, category="out_of_scope")
        name, window = matched
        for argument, value in zip(_TIME_ARGUMENTS, _epochs(window), strict=True):
            prepared[argument] = _as_schema_type(spec.properties[argument], value)
        return window, name

    def _rule_params(self, request: RuleRead) -> dict[str, str]:
        for name in request.params:
            if name in _RULE_TIME_PARAMS:
                msg = "A plug-in names the window it reads; the Reader sets the time range."
                raise ReadRejectedError(msg, category="argument_invalid")
            if payloads.secret_name(name):
                msg = "Credential parameters are not accepted."
                raise ReadRejectedError(msg, category="argument_invalid")
        self._check_rule_scope(request)
        params = dict(request.params)
        if request.window is not None:
            start, end = _epochs(self._windows.named(request.window))
            params |= {"start": str(start), "end": str(end)}
        return params

    def _check_rule_scope(self, request: RuleRead) -> None:
        identities: Iterable[tuple[str, str]] = [
            *_PATH_SCOPE.findall(request.path),
            *(("orgs", value) for name, value in request.params.items() if name == "org_id"),
            *(("sites", value) for name, value in request.params.items() if name == "site_id"),
            *(("sites", request.site_id) for _ in (1,) if request.site_id),
        ]
        if request.org_neutral:
            if not request.path.startswith(_ORG_NEUTRAL_PREFIX) or request.kind != "reference":
                msg = f"Only a reference read under {_ORG_NEUTRAL_PREFIX} may be organization neutral."
                raise ReadRejectedError(msg, category="out_of_scope")
        elif not identities:
            msg = "A rule read names one of this investigation's organizations or sites in its path."
            raise ReadRejectedError(msg, category="out_of_scope")
        for collection, identity in identities:
            if collection == "orgs" and identity != self._org_id:
                msg = "Guardian reads one organization; another was requested."
                raise ReadRejectedError(msg, category="out_of_scope")
            if collection == "sites" and not self._authority.allows(identity):
                msg = "That site is outside this investigation's site authority."
                raise ReadRejectedError(msg, category="out_of_scope")

    def _recorded(self, envelope: _Envelope, raw: Any, *, budget: int, cache_key: str | None = None) -> Evidence:
        """Keep what this investigation may see, redact it, and bound it into the largest form that fits.

        Authority and completeness are decided on the validated result, before redaction, so a row beyond the
        redaction bounds is still seen. One row naming another site costs that row, not the whole read: it is left
        out and counted, and the item stays citable for the rows that remain.
        """
        kept, omitted = self._within_authority(raw)
        if (foreign := self._foreign(kept)) is not None:
            # Not a row: the result itself belongs to another organization or site, so none of it is usable.
            return self._failed(envelope, foreign)
        if omitted and not _holds_rows(kept):
            msg = f"All {omitted} rows named an organization or a site outside this investigation's authority."
            return self._failed(envelope, msg)
        note = (
            f"{omitted} rows outside this investigation's organization or site authority were left out."
            if omitted
            else ""
        )
        redacted = payloads.redact(kept, secrets=self._secrets)
        collection = "partial" if omitted or payloads.has_more(raw) else "complete"
        chosen: Evidence | None = None
        for candidate, representation, detail in payloads.shrink(
            payloads.payload_of(redacted),
            rows=payloads.row_counts(raw),
            allow_full=not omitted and not payloads.omits(raw),
        ):
            chosen = envelope.evidence(
                collection=collection,
                representation=representation,
                payload=candidate,
                detail=" ".join(part for part in (note, detail) if part)[:MAX_DETAIL_CHARS],
            )
            if json_size(chosen) <= budget:
                break
        if chosen is None:  # pragma: no cover - shrink always offers at least a count-only digest
            msg = "The result could not be bounded."
            return self._failed(envelope, msg)
        recorded = self._registry.record(chosen)
        if cache_key is not None:
            self._cache[cache_key] = recorded
        return recorded

    def _failed(self, envelope: _Envelope, detail: str) -> Evidence:
        """Error evidence: it keeps its E-id and its reason, and it can never satisfy an obligation."""
        text = payloads.redact_text(detail, secrets=self._secrets, max_chars=MAX_DETAIL_CHARS)
        return self._registry.record(
            envelope.evidence(
                collection="error",
                representation="full",
                payload={},
                detail=text or "The read failed.",
            )
        )

    def _within_authority(self, raw: Any, depth: int = 0) -> tuple[Any, int]:
        """The result without the rows outside this organization or its sites, and how many were left out.

        Rows are read before redaction, so a row past the redaction bounds is weighed like any other instead of
        disappearing into the kept ones. Below the redaction depth nothing survives into the stored payload, so
        the walk stops there.
        """
        if depth > payloads.MAX_DEPTH:
            return raw, 0
        if isinstance(raw, list):
            kept: list[Any] = []
            omitted = 0
            for item in raw:
                if isinstance(item, Mapping) and self._foreign(item) is not None:
                    omitted += 1
                    continue
                filtered, dropped = self._within_authority(item, depth + 1)
                kept.append(filtered)
                omitted += dropped
            return kept, omitted
        if isinstance(raw, Mapping):
            result: dict[str, Any] = {}
            omitted = 0
            for key, value in raw.items():
                result[str(key)], dropped = self._within_authority(value, depth + 1)
                omitted += dropped
            return result, omitted
        return raw, 0

    def _foreign(self, value: Any, depth: int = 0) -> str | None:
        """The first reason a value leaves this investigation's organization or its authorized sites."""
        if depth > payloads.MAX_DEPTH:
            return None
        if isinstance(value, Mapping):
            organization = value.get("org_id")
            if isinstance(organization, str) and organization and organization != self._org_id:
                return "The result carried a foreign organization identity."
            site = value.get("site_id")
            if isinstance(site, str) and site and not self._authority.org_wide and not self._authority.allows(site):
                return "The result named a site outside this investigation's site authority."
            return next((found for found in (self._foreign(item, depth + 1) for item in value.values()) if found), None)
        if isinstance(value, list):
            return next((found for found in (self._foreign(item, depth + 1) for item in value) if found), None)
        return None


def _holds_rows(value: Any, depth: int = 0) -> bool:
    """Whether any list in the result still holds a row, which is what authority filtering takes away."""
    if depth > payloads.MAX_DEPTH:
        return False
    if isinstance(value, list):
        return any(isinstance(item, Mapping) or _holds_rows(item, depth + 1) for item in value)
    if isinstance(value, Mapping):
        return any(_holds_rows(item, depth + 1) for item in value.values())
    return False


def _dropping(catalogue: ToolCatalogue, dropped: Mapping[str, str]) -> ToolCatalogue:
    if not dropped:
        return catalogue
    return ToolCatalogue(
        tools={name: spec for name, spec in catalogue.tools.items() if name not in dropped},
        rejected={**catalogue.rejected, **{name: dropped[name] for name in dropped if name in catalogue.tools}},
    )


def _catalogue(result: Mapping[str, Any]) -> ToolCatalogue:
    rows = result.get("tools") if isinstance(result, Mapping) else None
    if not isinstance(rows, list):
        return ToolCatalogue(tools={}, rejected={"*": "The MCP catalogue was not a list of tools."})
    tools: dict[str, ToolSpec] = {}
    rejected: dict[str, str] = {}
    for row in rows[:MAX_CATALOGUE_TOOLS]:
        name = row.get("name") if isinstance(row, Mapping) else None
        entry = mcp_allowlist.ALLOWLIST.get(name) if isinstance(name, str) else None
        if entry is None:
            continue
        spec, reason = _tool_spec(entry, row)
        if spec is None:
            rejected[entry.name] = reason
        else:
            tools[entry.name] = spec
    return ToolCatalogue(tools=tools, rejected=rejected)


def _tool_spec(  # noqa: PLR0911 - one return per reason a discovered tool cannot be used
    entry: mcp_allowlist.AllowedTool, row: Mapping[str, Any]
) -> tuple[ToolSpec | None, str]:
    annotations = row.get("annotations")
    if not isinstance(annotations, Mapping) or annotations.get("readOnlyHint") is not True:
        return None, "The catalogue does not mark this tool read-only."
    schema = row.get("inputSchema")
    if not isinstance(schema, dict):
        return None, "The tool has no input schema object."
    if not payloads.local_references_only(schema):
        return None, "The input schema carries a nonlocal reference."
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError:
        return None, "The input schema is not a valid JSON Schema."
    properties = schema.get("properties")
    properties = properties if isinstance(properties, Mapping) else {}
    if entry.discriminator not in properties:
        return None, "The input schema has no discriminating argument."
    if (missing := _contradicted(entry, properties)) is not None:
        return None, f"The advertised schema contradicts the frozen allowlist: it has no {missing}."
    compact = payloads.compact_schema(schema, drop=("org_id",))
    return (
        ToolSpec(
            name=entry.name,
            discriminator=entry.discriminator,
            input_schema=schema,
            prompt_schema=compact if isinstance(compact, dict) else {},
            validator=Draft202012Validator(schema),
            properties={str(key): value if isinstance(value, Mapping) else {} for key, value in properties.items()},
            requires_org=entry.requires_org,
            site_scopable=entry.site_scopable,
            time_ranged=entry.time_ranged,
        ),
        "",
    )


def _contradicted(entry: mcp_allowlist.AllowedTool, properties: Mapping[str, Any]) -> str | None:
    """The scope argument a frozen fact promises and the advertised schema leaves out, if any.

    Guardian's guards read the frozen facts, so a schema that cannot carry them is refused rather than silently
    read without an organization, a site or a window.
    """
    if entry.requires_org and "org_id" not in properties:
        return "org_id, which Guardian injects"
    if entry.site_scopable and "site_id" not in properties:
        return "site_id, which the site authority needs"
    if entry.time_ranged and not set(_TIME_ARGUMENTS) <= set(properties):
        return "start_time and end_time, which every historical read must carry"
    return None


def _tool_result(result: Mapping[str, Any]) -> tuple[Any, str | None]:
    """The JSON a tool returned, or the reason it is not usable evidence.

    The error flags are read from the envelope and the raw result, before redaction or a digest could drop them, so
    a failed call is never offered as successful, citable evidence.
    """
    content = result.get("content") if isinstance(result, Mapping) else None
    text = " ".join(
        str(item.get("text", "")) for item in (content or []) if isinstance(item, Mapping) and item.get("text")
    )
    raw = result.get("structuredContent") if isinstance(result, Mapping) else None
    if raw is None:
        try:
            raw = json.loads(text)
        except ValueError:
            return None, f"The tool returned no JSON result. {text}"
    if bool(result.get("isError")) or _error_signal(raw):
        return None, f"The tool reported an error. {text or str(raw)[:500]}"
    return raw, None


def _error_signal(value: Any) -> bool:
    """Structural error flags only; no untrusted text is read here."""
    return isinstance(value, Mapping) and bool(
        value.get("error") or value.get("success") is False or value.get("status") == "error"
    )


def _detail(error: BaseException) -> str:
    return payloads.redact_text(str(error), max_chars=MAX_DETAIL_CHARS)


def _canonical(tool: str, arguments: Mapping[str, JsonValue]) -> str:
    return json.dumps([tool, arguments], sort_keys=True, separators=(",", ":"), default=str)


def _epochs(window: EvidenceWindow) -> tuple[int, int]:
    return int(window.start.timestamp()), int(window.end.timestamp())


def _seconds(value: Any) -> int | None:
    """Epoch seconds as an integer, from an integer or a plain numeric string; anything else is not a time."""
    if type(value) is int:
        return value
    if type(value) is float and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value)
    return None


def _as_schema_type(schema: Mapping[str, Any], value: int) -> JsonValue:
    return value if schema.get("type") in _INTEGER_TYPES else str(value)


def _location(parts: Iterable[object]) -> str:
    """A validation path an argument name cannot forge into prose."""
    rendered = [str(part) if isinstance(part, int) or _SAFE_LOCATION.fullmatch(str(part)) else "?" for part in parts]
    return ".".join(rendered) or "the request"
