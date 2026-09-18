"""Guardian's Reader: the single guarded path for external reads.

Every test drives the Reader through injected fake transports. Nothing here reaches a network, a database or a
provider. The frozen allowlist ported into ``src`` is cross-checked against the Task 1 fixture so the two cannot
drift.
"""

# The fake transports mirror the Reader's protocols, whose ``timeout`` is an HTTP bound, not an asyncio one.
# ruff: noqa: ASYNC109

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError
from pytest_httpx import HTTPXMock

from guardian_verification import MCP_ALLOWLIST_FIXTURE, load_fixture
from mist_config_guardian_backend.guardian import mcp_allowlist as allowlist
from mist_config_guardian_backend.guardian import payloads
from mist_config_guardian_backend.guardian.evidence import (
    MCP_EVIDENCE_ITEM_BUDGET,
    RULE_EVIDENCE_ITEM_BUDGET,
    EvidenceRegistry,
    json_size,
)
from mist_config_guardian_backend.guardian.reader import (
    CALL_TIMEOUT_CEILING,
    MAX_TRANSPORT_BYTES,
    DeadlineExpiredError,
    Reader,
    ReadRejectedError,
    RuleRead,
    SiteAuthority,
    ToolCatalogue,
    ToolSpec,
    TransportError,
    evidence_windows,
)
from mist_config_guardian_backend.integrations.mist_mcp import MistMcpClient, MistMcpError

ORG = "4ac1dcf4-9d8b-7211-65c4-057819f0862b"
OTHER_ORG = "00000000-0000-0000-0000-0000000000ff"
SITE = "978c48e6-6ef6-11e6-8bbf-02e208b2d34f"
OTHER_SITE = "11111111-2222-3333-4444-555555555555"
MAC = "5c5b35000001"
CHANGED_AT = datetime(2026, 9, 16, 4, 41, 35, tzinfo=UTC)
AS_OF = CHANGED_AT + timedelta(minutes=60)
WINDOWS = evidence_windows(CHANGED_AT, AS_OF)
BEFORE = (int(WINDOWS.before.start.timestamp()), int(WINDOWS.before.end.timestamp()))
AFTER = (int(WINDOWS.after.start.timestamp()), int(WINDOWS.after.end.timestamp()))
COMBINED = (int(WINDOWS.combined.start.timestamp()), int(WINDOWS.combined.end.timestamp()))

MCP_URL = "https://mcp.example.test/mcp/mist?cloud=api.mist.com"
CATALOGUE = json.loads((Path(__file__).parent / "fixtures" / "mist_mcp_catalog.json").read_text())


class FakeClock:
    """A monotonic clock a test moves by hand."""

    def __init__(self, now: float = 0.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class FakeMcp:
    """The MCP transport the Reader is given; it records what the Reader asked for."""

    def __init__(self, results=None, tools=CATALOGUE) -> None:
        self._results = results if results is not None else (lambda *_args: {"ok": True})
        self._tools = tools
        self.calls: list[tuple[str, dict, float, int]] = []
        self.discoveries: list[tuple[float, int]] = []

    async def list_tools(self, *, timeout: float, max_bytes: int) -> dict:
        self.discoveries.append((timeout, max_bytes))
        if isinstance(self._tools, Exception):
            raise self._tools
        return {"tools": self._tools}

    async def call_tool(self, name: str, arguments: dict, *, timeout: float, max_bytes: int) -> dict:
        self.calls.append((name, dict(arguments), timeout, max_bytes))
        result = self._results(name, arguments) if callable(self._results) else self._results
        if isinstance(result, Exception):
            raise result
        return (
            result
            if isinstance(result, dict) and {"content", "structuredContent"} & set(result)
            else {"structuredContent": result}
        )


class FakeRuleTransport:
    def __init__(self, result=None) -> None:
        self._result = result if result is not None else {"results": []}
        self.reads: list[tuple[str, dict, float, int]] = []

    async def fetch(self, path: str, params: dict, *, timeout: float, max_bytes: int):
        self.reads.append((path, dict(params), timeout, max_bytes))
        result = self._result(path, params) if callable(self._result) else self._result
        if isinstance(result, Exception):
            raise result
        return result


def reader(  # noqa: PLR0913 - one Reader collaborator per argument, all defaulted
    *,
    mcp: FakeMcp | None = None,
    rules: FakeRuleTransport | None = None,
    authority: SiteAuthority | None = None,
    clock: FakeClock | None = None,
    deadlines: dict[str, float] | None = None,
    allowances: dict[str, int] | None = None,
    registry: EvidenceRegistry | None = None,
    secrets: tuple[str, ...] = (),
) -> Reader:
    return Reader(
        org_id=ORG,
        authority=authority if authority is not None else SiteAuthority(site_ids=frozenset({SITE})),
        windows=WINDOWS,
        registry=registry or EvidenceRegistry(),
        deadlines=deadlines or {"rule": 90.0, "agent": 210.0},
        rule_allowances=allowances if allowances is not None else {"wlan-removal": 2, "switch-port": 3},
        clock=clock or FakeClock(),
        mcp_transport=mcp if mcp is not None else FakeMcp(),
        rule_transport=rules if rules is not None else FakeRuleTransport(),
        secrets=secrets,
    )


def search(**overrides) -> dict:
    arguments = {"search_type": "device_events", "site_id": SITE, "start_time": BEFORE[0], "end_time": BEFORE[1]}
    return {key: value for key, value in (arguments | overrides).items() if value is not None}


def rule_read(**overrides) -> RuleRead:
    values = {
        "plugin": "wlan-removal",
        "title": "Client sessions for WLAN a1 before the change",
        "kind": "service_health",
        "path": f"/api/v1/sites/{SITE}/clients/sessions/search",
        "params": {"wlan_id": "a1", "limit": "1000"},
        "site_id": SITE,
        "window": "before",
    }
    return RuleRead.model_validate(values | overrides)


# --- the frozen allowlist, ported into src ------------------------------------


def test_the_src_allowlist_is_the_frozen_fixture() -> None:
    fixture = load_fixture(MCP_ALLOWLIST_FIXTURE)

    assert set(allowlist.ALLOWLIST) == set(fixture["tools"])
    for name, entry in fixture["tools"].items():
        tool = allowlist.ALLOWLIST[name]
        assert tool.discriminator == entry["discriminator"]
        assert dict(tool.kinds) == entry["kinds"]
        assert set(entry["excluded"]).isdisjoint(tool.kinds)
        assert tool.requires_org == entry["requires_org"]
        assert tool.site_scopable == entry["site_scopable"]
        assert tool.time_ranged == entry["time_ranged"]
    assert set(fixture["excluded_tools"]).isdisjoint(allowlist.ALLOWLIST)


@pytest.mark.parametrize(
    ("tool", "arguments", "kind"),
    [
        ("search_mist_data", {"search_type": "device_events"}, "service_health"),
        ("search_mist_data", {"search_type": "client_sessions"}, "service_health"),
        ("get_mist_stats", {"stats_type": "site_devices"}, "service_health"),
        ("get_mist_insights", {"insight_type": "sle"}, "service_health"),
        ("get_mist_config", {"resource_type": "networktemplates"}, "configuration"),
        ("get_mist_constants", {"constant_type": "device_events"}, "reference"),
    ],
)
def test_the_kind_table_answers_every_allowlisted_combination(tool, arguments, kind) -> None:
    assert allowlist.evidence_kind(tool, arguments) == kind


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("get_mist_config", {"resource_type": "psks"}),
        ("get_mist_config", {"resource_type": "webhooks"}),
        ("search_mist_data", {"search_type": "rogue_events"}),
        ("search_mist_data", {"search_type": "usermacs"}),
        ("get_mist_self", {}),
        ("find_mist_entity", {"query": "x"}),
        ("search_mist_data", {}),
        ("search_mist_data", {"search_type": 7}),
    ],
)
def test_the_kind_table_rejects_everything_outside_the_allowlist(tool, arguments) -> None:
    assert allowlist.evidence_kind(tool, arguments) is None


# --- catalogue discovery ------------------------------------------------------


async def test_discovery_is_tracked_apart_from_the_call_budget_and_happens_once() -> None:
    mcp = FakeMcp()
    guard = reader(mcp=mcp)

    first = await guard.tools()
    second = await guard.tools()

    assert first is second
    assert len(mcp.discoveries) == 1
    assert guard.catalogue_calls == 1
    assert guard.budget.mcp_calls == 0
    assert set(first.tools) == set(allowlist.ALLOWLIST)


async def test_discovery_keeps_only_read_only_allowlisted_tools_with_local_schemas() -> None:
    rows = [
        {"name": "get_mist_self", "inputSchema": {"type": "object"}, "annotations": {"readOnlyHint": True}},
        {
            "name": "get_mist_config",
            "inputSchema": {"type": "object", "properties": {"org_id": {"$ref": "https://evil.test/s.json"}}},
            "annotations": {"readOnlyHint": True},
        },
        {
            "name": "get_mist_constants",
            "inputSchema": {"type": "object", "properties": {"constant_type": {"type": "string"}}},
            "annotations": {"readOnlyHint": False},
        },
        {
            "name": "get_mist_stats",
            "inputSchema": {"type": "object", "properties": {"stats_type": {"type": 7}}},
            "annotations": {"readOnlyHint": True},
        },
    ]
    catalogue = await reader(mcp=FakeMcp(tools=rows)).tools()

    assert set(catalogue.tools) == set()
    assert "get_mist_self" not in catalogue.rejected
    assert "reference" in catalogue.rejected["get_mist_config"]
    assert "read-only" in catalogue.rejected["get_mist_constants"]
    assert "schema" in catalogue.rejected["get_mist_stats"]


def advertised(tool: str, properties: dict) -> list[dict]:
    """One catalogue row for ``tool`` that advertises exactly ``properties``."""
    return [
        {
            "name": tool,
            "inputSchema": {"type": "object", "properties": properties},
            "annotations": {"readOnlyHint": True},
        }
    ]


@pytest.mark.parametrize(
    ("tool", "properties", "named"),
    [
        ("search_mist_data", {"search_type": {}, "site_id": {}, "start_time": {}, "end_time": {}}, "org_id"),
        ("search_mist_data", {"search_type": {}, "org_id": {}, "start_time": {}, "end_time": {}}, "site_id"),
        ("search_mist_data", {"search_type": {}, "org_id": {}, "site_id": {}}, "start_time"),
        ("get_mist_constants", {"constant_type": {}, "org_id": {}}, "org_id"),
        ("get_mist_constants", {"constant_type": {}, "site_id": {}}, "site_id"),
        ("get_mist_config", {"resource_type": {}, "org_id": {}, "site_id": {}, "start_time": {}}, "start_time"),
        ("get_mist_config", {"resource_type": {}, "org_id": {}, "site_id": {}, "end_time": {}}, "end_time"),
    ],
)
async def test_a_schema_that_contradicts_the_frozen_allowlist_is_rejected(
    tool: str, properties: dict, named: str
) -> None:
    guard = reader(mcp=FakeMcp(tools=advertised(tool, properties)))

    catalogue = await guard.tools()

    assert catalogue.tools == {}
    assert named in catalogue.rejected[tool]
    assert "frozen allowlist" in catalogue.rejected[tool]
    with pytest.raises(ReadRejectedError) as rejection:
        await guard.call(tool, search())
    assert rejection.value.category == "tool_not_allowed"


async def test_a_rejection_reads_as_a_sentence_in_both_directions() -> None:
    """Operators and the agent both read this text, so neither direction may render as a broken phrase."""
    without_org = {"search_type": {}, "site_id": {}, "start_time": {}, "end_time": {}}
    missing = reader(mcp=FakeMcp(tools=advertised("search_mist_data", without_org)))
    added = reader(mcp=FakeMcp(tools=advertised("get_mist_constants", {"constant_type": {}, "site_id": {}})))

    dropped = (await missing.tools()).rejected["search_mist_data"]
    extra = (await added.tools()).rejected["get_mist_constants"]

    assert dropped == (
        "The advertised schema contradicts the frozen allowlist: it has no org_id, which the freeze says this "
        "tool takes."
    )
    assert extra == (
        "The advertised schema contradicts the frozen allowlist: it has site_id, which the freeze says this tool "
        "does not take."
    )


def smuggled(guard: Reader, tool: str, properties: dict) -> None:
    """Put a tool whose schema the freeze denies into the catalogue, as if discovery had let it through."""
    entry = allowlist.ALLOWLIST[tool]
    schema = {"type": "object", "properties": properties}
    guard._catalogue = ToolCatalogue(  # noqa: SLF001 - the second layer is only reachable past discovery
        tools={
            tool: ToolSpec(
                name=tool,
                discriminator=entry.discriminator,
                input_schema=schema,
                prompt_schema=schema,
                validator=Draft202012Validator(schema),
                properties=properties,
                requires_org=entry.requires_org,
                site_scopable=entry.site_scopable,
                time_ranged=entry.time_ranged,
            )
        },
        rejected={},
    )


async def test_a_foreign_organization_is_rejected_even_where_the_freeze_expects_none() -> None:
    mcp = FakeMcp()
    guard = reader(mcp=mcp)
    smuggled(guard, "get_mist_constants", {"constant_type": {}, "org_id": {}})

    with pytest.raises(ReadRejectedError) as rejection:
        await guard.call("get_mist_constants", {"constant_type": "device_events", "org_id": OTHER_ORG})

    assert rejection.value.category == "out_of_scope"
    assert mcp.calls == []


async def test_a_time_range_is_never_forwarded_by_a_tool_that_takes_none() -> None:
    mcp = FakeMcp()
    guard = reader(mcp=mcp)
    smuggled(guard, "get_mist_config", {"resource_type": {}, "org_id": {}, "start_time": {}, "end_time": {}})

    with pytest.raises(ReadRejectedError) as rejection:
        await guard.call(
            "get_mist_config",
            {"resource_type": "networktemplates", "start_time": BEFORE[0], "end_time": BEFORE[1]},
        )

    assert rejection.value.category == "out_of_scope"
    assert mcp.calls == []


async def test_a_site_outside_the_authority_is_rejected_even_where_the_freeze_expects_none() -> None:
    mcp = FakeMcp()
    guard = reader(mcp=mcp)
    smuggled(guard, "get_mist_constants", {"constant_type": {}, "site_id": {}})

    with pytest.raises(ReadRejectedError) as rejection:
        await guard.call("get_mist_constants", {"constant_type": "device_events", "site_id": OTHER_SITE})

    assert rejection.value.category == "out_of_scope"
    assert mcp.calls == []


async def test_the_guards_read_the_frozen_facts_and_not_the_advertised_schema() -> None:
    catalogue = await reader().tools()

    assert [catalogue.tools[name].requires_org for name in sorted(catalogue.tools)] == [True, False, True, True, True]
    assert catalogue.tools["get_mist_constants"].site_scopable is False
    assert catalogue.tools["get_mist_config"].time_ranged is False
    assert catalogue.tools["search_mist_data"].time_ranged is True


async def test_the_prompt_catalogue_drops_org_id_and_prose() -> None:
    catalogue = await reader().tools()
    search_tool = catalogue.tools["search_mist_data"]

    assert "org_id" not in search_tool.prompt_schema["properties"]
    assert "org_id" in search_tool.input_schema["properties"]
    assert "description" not in json.dumps(search_tool.prompt_schema)
    assert json_size(search_tool.prompt_schema) < json_size(search_tool.input_schema)


async def test_a_failed_discovery_leaves_the_catalogue_empty_and_retryable() -> None:
    mcp = FakeMcp(tools=TransportError("mcp unreachable"))
    guard = reader(mcp=mcp)

    catalogue = await guard.tools()

    assert catalogue.tools == {}
    assert "unreachable" in catalogue.rejected["*"]
    assert guard.catalogue_calls == 1
    with pytest.raises(ReadRejectedError) as rejection:
        await guard.call("search_mist_data", search())
    assert rejection.value.category == "tool_not_allowed"


async def test_a_dropped_tool_leaves_the_attempts_allowlist() -> None:
    guard = reader()
    await guard.tools()

    catalogue = guard.drop_tools(["search_mist_data"], "It did not fit the tool catalogue budget.")

    assert "search_mist_data" not in catalogue.tools
    assert "budget" in catalogue.rejected["search_mist_data"]
    assert "get_mist_config" in catalogue.tools
    with pytest.raises(ReadRejectedError) as rejection:
        await guard.call("search_mist_data", search())
    assert rejection.value.category == "tool_not_allowed"


async def test_tools_dropped_before_discovery_never_enter_the_catalogue() -> None:
    guard = reader()

    guard.drop_tools(["get_mist_stats"], "It did not fit the tool catalogue budget.")
    catalogue = await guard.tools()

    assert "get_mist_stats" not in catalogue.tools
    assert catalogue.rejected["get_mist_stats"]


# --- organization and site authority -----------------------------------------


async def test_guardian_injects_its_own_organization() -> None:
    mcp = FakeMcp()
    guard = reader(mcp=mcp)

    await guard.call("search_mist_data", search())

    assert mcp.calls[0][1]["org_id"] == ORG


@pytest.mark.parametrize("argument", [{"org_id": OTHER_ORG}, {"site_id": OTHER_SITE}])
async def test_a_foreign_organization_or_site_argument_is_rejected(argument) -> None:
    with pytest.raises(ReadRejectedError) as rejection:
        await reader().call("search_mist_data", search(**argument))

    assert rejection.value.category == "out_of_scope"


async def test_a_site_scoped_investigation_requires_one_of_its_sites() -> None:
    with pytest.raises(ReadRejectedError) as rejection:
        await reader().call("search_mist_data", search(site_id=None))

    assert rejection.value.category == "out_of_scope"


async def test_an_org_scoped_change_may_read_the_organization() -> None:
    guard = reader(authority=SiteAuthority(site_ids=frozenset({SITE}), org_wide=True))

    evidence = await guard.call("search_mist_data", search(site_id=None))

    assert evidence.collection == "complete"
    assert evidence.scope.site_ids == ()


async def test_an_org_wide_result_keeps_its_in_scope_rows_and_counts_the_rest() -> None:
    rows = {
        "results": [
            {"site_id": SITE, "mac": MAC, "name": "ap-1"},
            {"site_id": OTHER_SITE, "mac": "5c5b35000002", "name": "ap-42"},
            {"site_id": SITE, "mac": "5c5b35000003", "name": "ap-2"},
        ]
    }
    guard = reader(mcp=FakeMcp(results=rows))

    evidence = await guard.call("get_mist_config", {"resource_type": "devices"})

    assert evidence.citable is True
    assert evidence.collection == "partial"
    assert [row["mac"] for row in evidence.payload["results"]] == [MAC, "5c5b35000003"]
    assert evidence.payload["digest"]["rows"] == {"results": 3}
    assert "1 rows outside" in evidence.detail
    assert guard.budget.mcp_calls == 1
    assert guard.authority.site_ids == frozenset({SITE})
    with pytest.raises(ReadRejectedError):
        await guard.call("search_mist_data", search(site_id=OTHER_SITE))


async def test_a_result_of_nothing_but_foreign_rows_is_empty_and_not_citable() -> None:
    rows = {
        "total": 2,
        "results": [{"site_id": OTHER_SITE, "mac": MAC}, {"site_id": OTHER_SITE, "mac": "5c5b35000002"}],
        # Deeper than the redaction bounds, and holding no row: it cannot rescue an all-foreign result.
        "context": _nested(payloads.MAX_DEPTH + 2),
    }
    guard = reader(mcp=FakeMcp(results=rows))

    evidence = await guard.call("get_mist_config", {"resource_type": "devices"})

    assert evidence.citable is False
    assert evidence.payload == {}
    assert "All 2 rows" in evidence.detail
    assert guard.budget.mcp_calls == 1


async def test_rows_that_survive_deeper_in_the_result_keep_the_item_citable() -> None:
    rows = {
        "results": [{"site_id": OTHER_SITE, "mac": MAC}],
        "grouped": {"pages": [{"site_id": SITE, "mac": "5c5b35000004"}]},
    }

    evidence = await reader(mcp=FakeMcp(results=rows)).call("get_mist_config", {"resource_type": "devices"})

    assert evidence.citable is True
    assert evidence.collection == "partial"
    assert "1 rows outside" in evidence.detail


async def test_a_foreign_row_past_the_redaction_cap_is_still_weighed() -> None:
    rows = {"results": [{"site_id": SITE, "index": index} for index in range(payloads.MAX_ITEMS + 10)]}
    rows["results"][payloads.MAX_ITEMS + 5]["site_id"] = OTHER_SITE
    guard = reader(mcp=FakeMcp(results=rows))

    evidence = await guard.call("get_mist_config", {"resource_type": "devices"})

    assert evidence.collection == "partial"
    assert "1 rows outside" in evidence.detail
    assert evidence.payload["digest"]["rows"] == {"results": payloads.MAX_ITEMS + 10}
    assert all(row["site_id"] == SITE for row in evidence.payload["results"])


async def test_an_org_scoped_investigation_reads_every_site_of_its_organization() -> None:
    rows = {"results": [{"org_id": ORG, "site_id": OTHER_SITE, "mac": MAC}]}
    guard = reader(
        mcp=FakeMcp(results=rows),
        authority=SiteAuthority(site_ids=frozenset({SITE}), org_wide=True),
    )

    evidence = await guard.call("search_mist_data", search(site_id=None))

    assert evidence.collection == "complete"
    assert guard.authority.site_ids == frozenset({SITE})


async def test_nothing_below_the_redaction_depth_reaches_the_evidence_or_the_checks() -> None:
    deep: dict = {"site_id": OTHER_SITE, "next_cursor": "c1"}
    for _ in range(payloads.MAX_DEPTH + 3):
        deep = {"level": deep}
    guard = reader(mcp=FakeMcp(results={"results": [deep]}))

    evidence = await guard.call("search_mist_data", search())

    stored = json.dumps(evidence.model_dump(mode="json"))
    assert "[depth omitted]" in stored
    assert OTHER_SITE not in stored
    assert evidence.collection == "complete"


async def test_a_foreign_organization_outside_the_rows_rejects_the_whole_result() -> None:
    rows = {"org_id": OTHER_ORG, "results": [{"mac": MAC}]}

    evidence = await reader(mcp=FakeMcp(results=rows)).call("search_mist_data", search())

    assert evidence.collection == "error"
    assert evidence.citable is False
    assert "organization" in evidence.detail


async def test_a_row_of_another_organization_costs_that_row_only() -> None:
    rows = {"results": [{"org_id": OTHER_ORG, "mac": MAC}, {"org_id": ORG, "mac": "5c5b35000002"}]}

    evidence = await reader(mcp=FakeMcp(results=rows)).call("search_mist_data", search())

    assert evidence.citable is True
    assert [row["mac"] for row in evidence.payload["results"]] == ["5c5b35000002"]
    assert "1 rows outside" in evidence.detail


async def test_the_reader_tells_its_consumers_what_it_is_bound_to() -> None:
    guard = reader()

    assert guard.org_id == ORG
    assert guard.windows is WINDOWS
    assert guard.budget.model_turns == 0


async def test_the_organization_may_be_supplied_when_it_is_the_right_one() -> None:
    mcp = FakeMcp()

    evidence = await reader(mcp=mcp).call("search_mist_data", search(org_id=ORG))

    assert evidence.collection == "complete"
    assert mcp.calls[0][1]["org_id"] == ORG


async def test_a_structured_error_result_is_never_offered_as_successful_evidence() -> None:
    mcp = FakeMcp(results={"structuredContent": {"error": "Unknown search_type", "success": False}})

    evidence = await reader(mcp=mcp).call("search_mist_data", search())

    assert evidence.collection == "error"
    assert "Unknown search_type" in evidence.detail


# --- time windows -------------------------------------------------------------


@pytest.mark.parametrize(("window", "name"), [(BEFORE, "before"), (AFTER, "after"), (COMBINED, "combined")])
async def test_exactly_before_after_or_the_combined_window_is_accepted(window, name) -> None:
    guard = reader()

    evidence = await guard.call("search_mist_data", search(start_time=window[0], end_time=window[1]))

    assert evidence.window is not None
    assert (int(evidence.window.start.timestamp()), int(evidence.window.end.timestamp())) == window
    assert name in evidence.title


@pytest.mark.parametrize(
    "arguments",
    [
        {"start_time": BEFORE[0] + 1, "end_time": BEFORE[1]},
        {"start_time": BEFORE[0], "end_time": AFTER[1] + 1},
        {"start_time": COMBINED[0] - 3600, "end_time": COMBINED[1]},
        {"start_time": "yesterday", "end_time": "today"},
        {"start_time": BEFORE[0], "end_time": None},
        {"start_time": None, "end_time": None},
    ],
)
async def test_every_other_time_range_is_rejected(arguments) -> None:
    with pytest.raises(ReadRejectedError) as rejection:
        await reader().call("search_mist_data", search(**arguments))

    assert rejection.value.category == "out_of_scope"


async def test_a_duration_argument_is_rejected() -> None:
    with pytest.raises(ReadRejectedError) as rejection:
        await reader().call("search_mist_data", search(duration="1h"))

    assert rejection.value.category == "argument_invalid"


async def test_the_windows_stay_equal_at_the_forced_final_run() -> None:
    windows = evidence_windows(CHANGED_AT, CHANGED_AT + timedelta(minutes=120))

    assert windows.duration == timedelta(minutes=60)
    assert windows.before.end == windows.after.start == CHANGED_AT
    assert windows.after.end - windows.after.start == windows.before.end - windows.before.start


async def test_current_state_is_read_only_through_a_snapshot_tool() -> None:
    guard = reader()

    snapshot = await guard.call("get_mist_config", {"resource_type": "networktemplates"})

    assert snapshot.window is None
    assert snapshot.kind == "configuration"
    with pytest.raises(ReadRejectedError) as rejection:
        await guard.call("get_mist_stats", {"stats_type": "site_devices", "site_id": SITE})
    assert rejection.value.category == "out_of_scope"


# --- arguments ----------------------------------------------------------------


@pytest.mark.parametrize(
    "arguments",
    [
        {"search_type": "device_events", "limit": "many"},
        {"search_type": "device_events", "unknown": 1},
        {"search_type": "device_events", "next_cursor": "c1"},
        {"search_type": "device_events", "page": 2},
        {"search_type": "device_events", "api_key": "x"},
    ],
)
async def test_arguments_must_validate_against_the_discovered_schema(arguments) -> None:
    with pytest.raises(ReadRejectedError) as rejection:
        await reader().call("search_mist_data", search(**arguments))

    assert rejection.value.category == "argument_invalid"


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [("get_mist_config", {"resource_type": "psks"}), ("get_mist_self", {}), ("nope", {})],
)
async def test_a_tool_outside_the_allowlist_is_never_called(tool, arguments) -> None:
    mcp = FakeMcp()

    with pytest.raises(ReadRejectedError) as rejection:
        await reader(mcp=mcp).call(tool, arguments)

    assert rejection.value.category == "tool_not_allowed"
    assert mcp.calls == []


# --- nested argument objects (controller ruling R31) --------------------------


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("search_mist_data", {"search_type": "device_events", "filters": {"org_id": OTHER_ORG}}),
        ("search_mist_data", {"search_type": "device_events", "filters": {"site_id": OTHER_SITE}}),
        ("search_mist_data", {"search_type": "device_events", "filters": {"site_id": [SITE, OTHER_SITE]}}),
        ("search_mist_data", {"search_type": "device_events", "filters": {"nested": {"site_id": OTHER_SITE}}}),
        ("search_mist_data", {"search_type": "device_events", "filters": {"any": [{"org_id": OTHER_ORG}]}}),
        ("get_mist_stats", {"stats_type": "site_devices", "site_id": SITE, "filters": {"site_id": OTHER_SITE}}),
        (
            "get_mist_insights",
            {"insight_type": "sle", "site_id": SITE, "params": {"scope": "site", "scope_id": OTHER_SITE}},
        ),
        (
            "get_mist_insights",
            {"insight_type": "sle", "site_id": SITE, "params": {"scope": "org", "scope_id": OTHER_ORG}},
        ),
    ],
)
async def test_a_nested_object_never_reaches_another_organization_or_site(tool, arguments) -> None:
    mcp = FakeMcp()

    with pytest.raises(ReadRejectedError) as rejection:
        await reader(mcp=mcp).call(tool, {**arguments, "start_time": BEFORE[0], "end_time": BEFORE[1]})

    assert rejection.value.category == "out_of_scope"
    assert mcp.calls == []


@pytest.mark.parametrize(
    "filters",
    [
        {"duration": "1d"},
        {"start_time": 1},
        {"end_time": 1},
        {"nested": {"start": 1}},
        {"api_key": "x"},
    ],
)
async def test_a_nested_object_carries_no_time_range_and_no_credential(filters) -> None:
    mcp = FakeMcp()

    with pytest.raises(ReadRejectedError) as rejection:
        await reader(mcp=mcp).call("search_mist_data", search(filters=filters))

    assert rejection.value.category == "argument_invalid"
    assert mcp.calls == []


async def test_arguments_nested_deeper_than_the_redaction_bound_are_refused() -> None:
    deep: dict = {"org_id": ORG}
    for _ in range(payloads.MAX_DEPTH + 1):
        deep = {"nested": deep}

    with pytest.raises(ReadRejectedError) as rejection:
        await reader().call("search_mist_data", search(filters=deep))

    assert rejection.value.category == "argument_invalid"


async def test_a_nested_object_inside_this_investigations_scope_is_forwarded() -> None:
    mcp = FakeMcp()
    filters = {"org_id": ORG, "site_id": [SITE], "mac": MAC, "any": [{"model": "AP45"}, 5, None]}

    evidence = await reader(mcp=mcp).call("search_mist_data", search(filters=filters))

    assert evidence.collection == "complete"
    assert mcp.calls[0][1]["filters"] == filters


# --- budget, caching and deadlines -------------------------------------------


async def test_seven_calls_fit_and_the_eighth_is_refused() -> None:
    guard = reader()

    for index in range(7):
        await guard.call("search_mist_data", search(limit=index + 1))
    with pytest.raises(ReadRejectedError) as rejection:
        await guard.call("search_mist_data", search(limit=99))

    assert rejection.value.category == "call_budget"
    assert guard.budget.mcp_calls == 7


async def test_a_repeated_call_returns_its_evidence_without_spending_the_budget() -> None:
    mcp = FakeMcp()
    guard = reader(mcp=mcp)

    first = await guard.call("search_mist_data", search())
    again = await guard.call("search_mist_data", {"start_time": BEFORE[0], **search()})

    assert again.id == first.id
    assert guard.budget.mcp_calls == 1
    assert len(mcp.calls) == 1


async def test_a_failed_call_is_not_cached_and_can_be_retried() -> None:
    results = iter([TransportError("read timed out"), {"results": [{"mac": MAC}]}])
    mcp = FakeMcp(results=lambda *_: next(results))
    guard = reader(mcp=mcp)

    failed = await guard.call("search_mist_data", search())
    retried = await guard.call("search_mist_data", search())

    assert failed.collection == "error"
    assert "timed out" in failed.detail
    assert retried.collection == "complete"
    assert retried.id != failed.id
    assert guard.budget.mcp_calls == 2


async def test_a_call_after_its_phase_deadline_never_starts() -> None:
    clock = FakeClock(209.0)
    mcp = FakeMcp()
    guard = reader(mcp=mcp, clock=clock)
    await guard.tools()

    await guard.call("search_mist_data", search())
    clock.now = 210.5
    with pytest.raises(DeadlineExpiredError):
        await guard.call("search_mist_data", search(limit=2))

    assert [call[2] for call in mcp.calls] == [1.0]
    assert guard.budget.mcp_calls == 1


async def test_every_call_is_bounded_by_the_shorter_of_twenty_seconds_and_the_phase() -> None:
    mcp = FakeMcp()
    guard = reader(mcp=mcp, clock=FakeClock(0.0))

    await guard.tools()
    await guard.call("search_mist_data", search())

    assert mcp.discoveries[0] == (CALL_TIMEOUT_CEILING, MAX_TRANSPORT_BYTES)
    assert mcp.calls[0][2] == CALL_TIMEOUT_CEILING
    assert mcp.calls[0][3] == MAX_TRANSPORT_BYTES


# --- results: redaction, bounds and digests -----------------------------------


async def test_secret_material_never_reaches_the_evidence() -> None:
    rows = {
        "results": [
            {"mac": MAC, "psk": "super-secret", "radius": {"secret": {"$encrypted": "v1:ciphertext"}}},
        ]
    }

    evidence = await reader(mcp=FakeMcp(results=rows)).call("search_mist_data", search())

    serialized = json.dumps(evidence.model_dump(mode="json"))
    assert "super-secret" not in serialized
    assert "ciphertext" not in serialized
    assert "[redacted]" in serialized


async def test_a_result_over_the_transport_bound_is_an_error_and_not_citable() -> None:
    mcp = FakeMcp(results=TransportError("Response exceeded the 1000000 byte transport bound"))

    evidence = await reader(mcp=mcp).call("search_mist_data", search())

    assert evidence.collection == "error"
    assert evidence.citable is False
    assert "transport bound" in evidence.detail


async def test_a_tool_error_is_recorded_as_error_evidence() -> None:
    mcp = FakeMcp(results={"isError": True, "content": [{"type": "text", "text": "Bearer abcdefghijklmnop failed"}]})

    evidence = await reader(mcp=mcp).call("search_mist_data", search())

    assert evidence.collection == "error"
    assert "abcdefghijklmnop" not in evidence.detail
    assert evidence.payload == {}


async def test_a_large_result_is_digested_within_the_item_budget() -> None:
    rows = {"results": [{"mac": MAC, "type": "AP_CONFIGURED", "text": "x" * 200} for _ in range(400)]}
    registry = EvidenceRegistry()

    evidence = await reader(mcp=FakeMcp(results=rows), registry=registry).call("search_mist_data", search())

    assert evidence.representation == "digest"
    assert evidence.collection == "complete"
    assert evidence.payload["digest"]["rows"] == {"results": 400}
    assert json_size(evidence) <= MCP_EVIDENCE_ITEM_BUDGET
    assert registry.get(evidence.id) is evidence


async def test_a_result_the_redaction_bounds_cut_is_never_called_full() -> None:
    rows = {"results": [{"mac": MAC, "index": index} for index in range(payloads.MAX_ITEMS + 10)]}

    evidence = await reader(mcp=FakeMcp(results=rows)).call("search_mist_data", search())

    assert evidence.representation == "digest"
    assert evidence.payload["digest"]["rows"] == {"results": payloads.MAX_ITEMS + 10}
    assert len(evidence.payload["results"]) <= max(payloads.DIGEST_ROWS)


async def test_an_unfinished_page_is_collected_partially() -> None:
    rows = {"results": [{"mac": MAC}], "total": 900, "next_cursor": "abc"}

    evidence = await reader(mcp=FakeMcp(results=rows)).call("search_mist_data", search())

    assert evidence.collection == "partial"
    assert evidence.representation == "full"


async def test_a_result_that_is_not_json_is_an_error() -> None:
    mcp = FakeMcp(results={"content": [{"type": "text", "text": "<html>not json</html>"}]})

    evidence = await reader(mcp=mcp).call("search_mist_data", search())

    assert evidence.collection == "error"
    assert "no JSON" in evidence.detail


async def test_evidence_carries_its_server_owned_kind_scope_and_window() -> None:
    evidence = await reader().call("search_mist_data", search())

    assert evidence.id == "E1"
    assert evidence.source == "mcp:search_mist_data"
    assert evidence.kind == "service_health"
    assert evidence.scope.site_ids == (SITE,)
    assert evidence.captured_at == AS_OF
    assert evidence.window == WINDOWS.before


# --- rule reads ---------------------------------------------------------------


async def test_a_rule_read_carries_the_window_the_plugin_named() -> None:
    rules = FakeRuleTransport(result={"results": [{"mac": MAC}]})
    guard = reader(rules=rules)

    evidence = await guard.read(rule_read())

    path, params, timeout, max_bytes = rules.reads[0]
    assert params == {"wlan_id": "a1", "limit": "1000", "start": str(BEFORE[0]), "end": str(BEFORE[1])}
    assert timeout == CALL_TIMEOUT_CEILING
    assert max_bytes == MAX_TRANSPORT_BYTES
    assert path.endswith("/clients/sessions/search")
    assert evidence.source == "rule:wlan-removal"
    assert evidence.kind == "service_health"
    assert evidence.window == WINDOWS.before
    assert guard.budget.rule_reads == 1
    assert json_size(evidence) <= RULE_EVIDENCE_ITEM_BUDGET


async def test_a_read_that_declares_a_field_it_may_not_keep_never_sees_it_either() -> None:
    """A plug-in that must not hold a value, such as the MAC an LLDP neighbour claims, declares it away."""
    rules = FakeRuleTransport(result={"results": [{"mac": MAC, "neighbor_mac": "aabbccddeeff", "up": True}]})
    guard = reader(rules=rules)

    evidence = await guard.read(rule_read(window=None, omit_fields=("neighbor_mac",)))

    assert evidence.payload["results"] == [{"mac": MAC, "up": True}]
    assert "aabbccddeeff" not in evidence.model_dump_json()
    # The read itself is unchanged: the field is removed from the answer, not from the question.
    assert "neighbor_mac" not in rules.reads[0][1]


async def test_a_snapshot_rule_read_carries_no_window() -> None:
    guard = reader()

    evidence = await guard.read(rule_read(window=None, kind="configuration", title="Port configuration now"))

    assert evidence.window is None
    assert evidence.kind == "configuration"


@pytest.mark.parametrize("params", [{"start": "1"}, {"end": "2"}, {"duration": "1h"}, {"api_key": "k"}])
async def test_a_plugin_cannot_choose_its_own_time_range(params) -> None:
    with pytest.raises(ReadRejectedError) as rejection:
        await reader().read(rule_read(params=params))

    assert rejection.value.category == "argument_invalid"


@pytest.mark.parametrize(
    "overrides",
    [
        {"site_id": OTHER_SITE, "path": f"/api/v1/sites/{OTHER_SITE}/clients/sessions/search"},
        {"path": f"/api/v1/orgs/{OTHER_ORG}/devices/search", "site_id": None},
        {"path": f"/api/v1/sites/{OTHER_SITE}/stats/devices"},
    ],
)
async def test_a_rule_read_stays_inside_the_organization_and_its_sites(overrides) -> None:
    rules = FakeRuleTransport()

    with pytest.raises(ReadRejectedError) as rejection:
        await reader(rules=rules).read(rule_read(**overrides))

    assert rejection.value.category == "out_of_scope"
    assert rules.reads == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"path": "/api/v1/self", "site_id": None},
        {"path": "/api/v1/self/apitokens", "site_id": None},
        {"path": "/api/v1/const/device_events", "site_id": None, "kind": "reference", "window": None},
        {"path": "/api/v1/const/device_events", "site_id": None, "org_neutral": True, "window": None},
        {"path": f"/api/v1/sites/{SITE}/stats", "site_id": None, "org_neutral": True, "kind": "reference"},
    ],
)
async def test_a_rule_read_names_a_scope_or_is_a_declared_constant_read(overrides: dict) -> None:
    rules = FakeRuleTransport()

    with pytest.raises(ReadRejectedError) as rejection:
        await reader(rules=rules).read(rule_read(**overrides))

    assert rejection.value.category == "out_of_scope"
    assert rules.reads == []


@pytest.mark.parametrize(
    "params",
    [{"org_id": ORG}, {"site_id": SITE}, {"org_id": ORG, "site_id": SITE}],
)
async def test_a_tenant_correct_parameter_does_not_replace_a_scope_segment(params: dict) -> None:
    rules = FakeRuleTransport()

    with pytest.raises(ReadRejectedError) as rejection:
        await reader(rules=rules).read(rule_read(path="/api/v1/self", params=params, site_id=None, window=None))

    assert rejection.value.category == "out_of_scope"
    assert rules.reads == []


async def test_an_organization_read_may_carry_its_own_parameters() -> None:
    rules = FakeRuleTransport(result={"results": []})
    guard = reader(rules=rules)

    evidence = await guard.read(
        rule_read(
            path=f"/api/v1/orgs/{ORG}/devices/search",
            params={"org_id": ORG, "site_id": SITE, "type": "ap"},
            site_id=SITE,
        )
    )

    assert evidence.collection == "complete"
    assert rules.reads[0][1]["type"] == "ap"


async def test_a_declared_constant_read_is_reference_evidence_with_no_scope() -> None:
    rules = FakeRuleTransport(result={"results": ["AP_CONFIGURED"]})
    guard = reader(rules=rules)

    evidence = await guard.read(
        rule_read(
            path="/api/v1/const/device_events",
            params={},
            site_id=None,
            kind="reference",
            window=None,
            org_neutral=True,
            title="Device event types",
        )
    )

    assert evidence.kind == "reference"
    assert evidence.scope.site_ids == ()
    assert evidence.collection == "complete"
    assert guard.budget.rule_reads == 1


async def test_each_plugin_spends_its_own_allowance_inside_the_attempt_total() -> None:
    guard = reader(allowances={"wlan-removal": 2, "switch-port": 8})

    for index in range(2):
        await guard.read(rule_read(params={"limit": str(index)}))
    with pytest.raises(ReadRejectedError) as rejection:
        await guard.read(rule_read(params={"limit": "9"}))

    assert rejection.value.category == "call_budget"
    for index in range(6):
        await guard.read(rule_read(plugin="switch-port", params={"limit": str(index)}))
    with pytest.raises(ReadRejectedError) as attempt_total:
        await guard.read(rule_read(plugin="switch-port", params={"limit": "9"}))
    assert attempt_total.value.category == "call_budget"
    assert guard.budget.rule_reads == 8


async def test_an_unregistered_plugin_cannot_read() -> None:
    with pytest.raises(ReadRejectedError) as rejection:
        await reader(allowances={}).read(rule_read())

    assert rejection.value.category == "call_budget"


async def test_a_rule_read_failure_becomes_error_evidence_the_plugin_can_report() -> None:
    guard = reader(rules=FakeRuleTransport(result=TransportError("Mist returned HTTP 503")))

    evidence = await guard.read(rule_read())

    assert evidence.collection == "error"
    assert evidence.citable is False
    assert "503" in evidence.detail
    assert guard.budget.rule_reads == 1


async def test_a_rule_read_after_its_phase_deadline_never_starts() -> None:
    rules = FakeRuleTransport()
    guard = reader(rules=rules, clock=FakeClock(91.0))

    with pytest.raises(DeadlineExpiredError):
        await guard.read(rule_read())

    assert rules.reads == []
    assert guard.budget.rule_reads == 0


async def test_ids_are_assigned_at_reservation_and_never_renumbered() -> None:
    registry = EvidenceRegistry()
    clock = FakeClock()
    guard = reader(registry=registry, clock=clock, rules=FakeRuleTransport(result=TransportError("gone")))

    first = await guard.read(rule_read())
    clock.now = 91.0
    with pytest.raises(DeadlineExpiredError):
        await guard.read(rule_read(params={"limit": "2"}))
    clock.now = 100.0
    second = await guard.call("search_mist_data", search())

    assert (first.id, second.id) == ("E1", "E2")
    assert [item.id for item in registry.evidence] == ["E1", "E2"]


# --- degraded attempts --------------------------------------------------------


async def test_a_reader_without_transports_fails_every_read_without_crashing() -> None:
    guard = Reader(
        org_id=ORG,
        authority=SiteAuthority(site_ids=frozenset({SITE})),
        windows=WINDOWS,
        registry=EvidenceRegistry(),
        deadlines={"rule": 90.0, "agent": 210.0},
        rule_allowances={"wlan-removal": 2},
        clock=FakeClock(),
    )

    catalogue = await guard.tools()
    evidence = await guard.read(rule_read())

    assert "No MCP transport" in catalogue.rejected["*"]
    assert evidence.collection == "error"
    assert "No Mist transport" in evidence.detail
    with pytest.raises(ReadRejectedError):
        await guard.call("search_mist_data", search())


@pytest.mark.parametrize("path", ["/api/v1/sites/../orgs/x", "/api/v1//sites", "sites/1", "/api/v1/sites?x=1"])
def test_a_read_path_is_one_plain_route(path: str) -> None:
    with pytest.raises(ValidationError):
        rule_read(path=path)


@pytest.mark.parametrize(
    ("result", "reason"),
    [
        ({"tools": "everything"}, "*"),
        ({"tools": [{"name": "get_mist_config", "annotations": {"readOnlyHint": True}}]}, "get_mist_config"),
        (
            {
                "tools": [
                    {
                        "name": "get_mist_stats",
                        "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer"}}},
                        "annotations": {"readOnlyHint": True},
                    }
                ]
            },
            "get_mist_stats",
        ),
    ],
)
async def test_a_catalogue_that_cannot_be_used_is_explained(result: dict, reason: str) -> None:
    catalogue = await reader(mcp=FakeMcp(tools=result.get("tools"))).tools()

    assert catalogue.tools == {}
    assert catalogue.rejected[reason]


async def test_a_result_with_no_rows_still_degrades_to_counts() -> None:
    rows = {"configuration": {f"field-{index}": "y" * 300 for index in range(50)}}

    evidence = await reader(mcp=FakeMcp(results=rows)).call("get_mist_config", {"resource_type": "networktemplates"})

    assert evidence.representation == "digest"
    assert evidence.payload["digest"]["rows"] == {}
    assert json_size(evidence) <= MCP_EVIDENCE_ITEM_BUDGET


# --- payload helpers ----------------------------------------------------------


def _nested(levels: int) -> dict:
    value: dict = {"leaf": [1]}
    for _ in range(levels):
        value = {"level": value}
    return value


@pytest.mark.parametrize(
    ("value", "cut"),
    [
        ({"rows": [1] * (payloads.MAX_ITEMS + 1)}, True),
        ({"rows": [1] * payloads.MAX_ITEMS}, False),
        ({"note": "x" * (payloads.MAX_STRING + 1)}, True),
        ({"password": "x" * (payloads.MAX_STRING + 1)}, False),
        ({"radius": {"$encrypted": "x" * (payloads.MAX_STRING + 1)}}, False),
        (_nested(payloads.MAX_DEPTH + 2), True),
    ],
)
def test_a_result_the_bounds_would_cut_is_reported_as_cut(value: dict, cut) -> None:
    assert payloads.omits(value) is cut


def test_redaction_bounds_depth_width_and_length() -> None:
    deep: dict[str, object] = {"leaf": 1}
    for level in range(payloads.MAX_DEPTH + 2):
        deep = {f"level-{level}": deep}

    assert "[depth omitted]" in json.dumps(payloads.redact(deep))
    assert payloads.redact({"token": "abc"}) == {"token": "[redacted]"}
    assert payloads.redact(["x" * 5000])[0].endswith("x")
    assert len(payloads.redact(["x" * 5000])[0]) == payloads.MAX_STRING
    assert len(payloads.redact([1] * 500)) == payloads.MAX_ITEMS


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ({"radius": {"$encrypted": "v1:ciphertext"}}, {"radius": "[redacted]"}),
        ({"note": "the token is s3cr3t"}, {"note": "the token is [redacted]"}),
        ({"ratio": float("inf")}, {"ratio": None}),
        ({"when": datetime(2026, 9, 16, tzinfo=UTC)}, {"when": "2026-09-16 00:00:00+00:00"}),
    ],
)
def test_redaction_keeps_only_safe_json_values(value: dict, expected: dict) -> None:
    assert payloads.redact(value, secrets=("s3cr3t",)) == expected


def test_the_last_digest_always_fits_whatever_the_result_was() -> None:
    payload = {f"key-{index}": "x" * 500 for index in range(payloads.MAX_FIELDS)}

    candidates = list(payloads.shrink(payload, rows={"rows": 4}))

    assert candidates[0] == (payload, "full", "")
    assert json_size(candidates[-1][0]) < 100
    assert candidates[-1][0]["digest"]["row_count"] == 4


def test_epoch_seconds_are_read_from_integers_and_plain_digits() -> None:
    assert WINDOWS.match(float(BEFORE[0]), str(BEFORE[1]))[0] == "before"
    assert WINDOWS.match(BEFORE[0] + 0.5, BEFORE[1]) is None


def test_redacted_text_drops_bearer_credentials_and_control_characters() -> None:
    text = payloads.redact_text("Bearer abc.def-ghi rejected\n\ttoken", max_chars=200)

    assert "abc.def-ghi" not in text
    assert "\n" not in text


# --- the MCP client the Reader is given --------------------------------------


def _handshake(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        method="POST", url=MCP_URL, json={"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-03-26"}}
    )
    httpx_mock.add_response(method="POST", url=MCP_URL, status_code=202)


async def test_the_mcp_client_reads_at_most_the_transport_bound_it_is_given(httpx_mock: HTTPXMock) -> None:
    _handshake(httpx_mock)
    httpx_mock.add_response(method="POST", url=MCP_URL, content=b"x" * 2048)

    async with MistMcpClient(url=MCP_URL, token="service-token", cloud="api.mist.com", max_wire_bytes=1024) as client:
        with pytest.raises(MistMcpError) as failure:
            await client.call_tool("search_mist_data", {}, timeout=3.0)

    assert failure.value.code == "response_limit"
    assert httpx_mock.get_requests()[-1].extensions["timeout"]["read"] == 3.0


async def test_the_mcp_client_keeps_its_configured_timeout_when_none_is_given(httpx_mock: HTTPXMock) -> None:
    _handshake(httpx_mock)
    httpx_mock.add_response(method="POST", url=MCP_URL, json={"jsonrpc": "2.0", "id": 3, "result": {"tools": []}})

    async with MistMcpClient(url=MCP_URL, token="service-token", cloud="api.mist.com") as client:
        result = await client.list_tools()

    assert result == {"tools": []}
    assert httpx_mock.get_requests()[-1].extensions["timeout"]["read"] == 20


async def test_a_rule_read_hands_its_plugin_the_whole_result_and_stores_a_bounded_one() -> None:
    """Storage is bounded at the item budget; the judgement is not, so a large result is still an answer."""
    rows = [{"mac": MAC, "ssid": f"corp-{index}", "note": "x" * 200} for index in range(100)]
    rules = FakeRuleTransport(result={"results": rows, "total": len(rows)})
    guard = reader(rules=rules)

    evidence = await guard.read(rule_read())
    result = guard.full_result(evidence)

    assert evidence.representation == "digest"
    assert json_size(evidence) <= RULE_EVIDENCE_ITEM_BUDGET
    assert evidence.payload["digest"]["rows"]["results"] == len(rows)
    assert result["results"] == rows
    assert guard.full_result(evidence) is not evidence.payload


async def test_the_result_a_plugin_judges_from_is_filtered_redacted_and_stripped_like_the_stored_one() -> None:
    rows = [
        {"mac": MAC, "psk": "top-secret", "neighbor_mac": "aabbccddeeff", "token": "t"},
        {"mac": MAC, "site_id": OTHER_SITE},
    ]
    rules = FakeRuleTransport(result={"results": rows, "total": len(rows)})
    guard = reader(rules=rules, secrets=("top-secret",))

    evidence = await guard.read(rule_read(omit_fields=("neighbor_mac",)))
    result = guard.full_result(evidence)

    assert result["results"] == [{"mac": MAC, "psk": "[redacted]", "token": "[redacted]"}]
    assert evidence.collection == "partial"
    assert "aabbccddeeff" not in str(result)


async def test_a_failed_read_leaves_its_plugin_nothing_to_judge_from() -> None:
    rules = FakeRuleTransport(result=TransportError("Mist returned HTTP 503"))

    guard = reader(rules=rules)
    evidence = await guard.read(rule_read())

    assert evidence.collection == "error"
    assert guard.full_result(evidence) == {}


@pytest.mark.parametrize(
    ("limit", "collection"),
    [("4", "partial"), ("5", "complete"), ("all", "complete")],
)
async def test_a_bare_array_as_long_as_its_limit_is_one_page_of_a_longer_answer(limit, collection) -> None:
    rules = FakeRuleTransport(result=[{"mac": MAC} for _ in range(4)])

    evidence = await reader(rules=rules).read(rule_read(window=None, params={"limit": limit}))

    assert evidence.collection == collection
