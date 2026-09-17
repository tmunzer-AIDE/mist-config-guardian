"""Guardian's agent loop, driven by a fake model and a fake MCP transport.

Nothing here reaches a provider or a network. The tests cover the turn arithmetic, every rejection category, what
one prompt shows and withholds, what a step stores, and the two bounds the design asserts: the fixed part of a
prompt at 48 KB and the whole prompt at 96 KB.
"""

# The fake MCP transport mirrors the Reader's protocol, whose ``timeout`` is an HTTP bound, not an asyncio one.
# ruff: noqa: ASYNC109

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mist_config_guardian_backend.guardian.agent import (
    DROPPED_TOOL,
    HINTS_BUDGET,
    MAX_MODEL_TURNS,
    NO_CAPABILITY,
    NO_MCP_ENDPOINT,
    NO_RUNTIME,
    PROMPT_VERSION,
    REPORT_ONLY_TURNS,
    SYSTEM_PROMPT,
    AgentInputs,
    ModelError,
    ToolsView,
    availability,
    build_prompt,
    run_agent,
    tools_view,
)
from mist_config_guardian_backend.guardian.agent_schema import MAX_REPORT_ITEMS
from mist_config_guardian_backend.guardian.change import AtomView
from mist_config_guardian_backend.guardian.composition import cited, compose
from mist_config_guardian_backend.guardian.contracts import (
    BANDS,
    MAX_MCP_CALLS,
    MAX_SUMMARY_CHARS,
    MAX_TEXT_CHARS,
    Evidence,
    Target,
)
from mist_config_guardian_backend.guardian.evidence import (
    CHANGE_VIEW_BUDGET,
    CONCLUSIONS_BUDGET,
    DETERMINISTIC_VIEW_BUDGET,
    MODEL_OUTPUT_BUDGET,
    PROMPT_CAP,
    PROMPT_FIXED_BUDGET,
    STEPS_BUDGET,
    SYSTEM_PROMPT_BUDGET,
    TOOL_CATALOGUE_BUDGET,
    Bounded,
    EvidenceRegistry,
    json_size,
)
from mist_config_guardian_backend.guardian.ledger import DeterministicView, ObligationView
from mist_config_guardian_backend.guardian.reader import Reader, SiteAuthority, TransportError, evidence_windows

ORG = "4ac1dcf4-9d8b-7211-65c4-057819f0862b"
SITE = "978c48e6-6ef6-11e6-8bbf-02e208b2d34f"
MAC = "5c5b35000001"
OTHER_MAC = "5c5b35000002"
CHANGED_AT = datetime(2026, 9, 16, 4, 41, 35, tzinfo=UTC)
AS_OF = CHANGED_AT + timedelta(minutes=60)
WINDOWS = evidence_windows(CHANGED_AT, AS_OF)
BEFORE = (int(WINDOWS.before.start.timestamp()), int(WINDOWS.before.end.timestamp()))
CATALOGUE = json.loads((Path(__file__).parent / "fixtures" / "mist_mcp_catalog.json").read_text())
CATALOGUE_TOOL_NAMES = sorted(str(tool["name"]) for tool in CATALOGUE if isinstance(tool, dict))


class FakeMcp:
    """The MCP transport the Reader is given: it answers every call with one small row."""

    def __init__(self, result=None, tools=CATALOGUE) -> None:
        self._result = result if result is not None else (lambda *_: {"results": [{"mac": MAC, "type": "AP_DISC"}]})
        self._tools = tools
        self.calls: list[tuple[str, dict]] = []
        self.discoveries: list[tuple[float, int]] = []

    async def list_tools(self, *, timeout: float, max_bytes: int) -> dict:
        self.discoveries.append((timeout, max_bytes))
        if isinstance(self._tools, Exception):
            raise self._tools
        return {"tools": self._tools}

    async def call_tool(self, name: str, arguments: dict, *, timeout: float, max_bytes: int) -> dict:
        self.calls.append((name, dict(arguments), timeout, max_bytes))
        result = self._result(name, arguments) if callable(self._result) else self._result
        if isinstance(result, Exception):
            raise result
        return {"structuredContent": result}


class FakeModel:
    """One canned reply per turn; an exception is raised as a provider failure."""

    def __init__(self, *replies) -> None:
        self.replies = list(replies)
        self.prompts: list[tuple[str, str]] = []

    async def complete(self, system: str, user: str) -> str:
        self.prompts.append((system, user))
        if not self.replies:
            msg = "The fake model ran out of replies"
            raise AssertionError(msg)
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


class FakeClock:
    def __init__(self, now: float = 0.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def evidence(identity: str = "E1", **overrides) -> Evidence:
    values = {
        "id": identity,
        "source": "monitoring",
        "kind": "service_health",
        "title": "Monitoring ap-1",
        "captured_at": AS_OF,
        "collection": "complete",
        "representation": "full",
        "scope": {"site_ids": (SITE,), "device_macs": (MAC,)},
        "payload": {"mac": MAC, "peak": "warning"},
    }
    return Evidence.model_validate(values | overrides)


def registry_with(*items: Evidence) -> EvidenceRegistry:
    registry = EvidenceRegistry()
    for item in items:
        registry.reserve(item.source)
        registry.record(item)
    return registry


def inputs(coverage: str = "partial", *, atoms: int = 1, obligations: int = 1) -> AgentInputs:
    return AgentInputs(
        change=Bounded[AtomView](
            items=tuple(
                AtomView(
                    id=f"A{index + 1}",
                    object_type="networktemplate",
                    name="DNT-NTR template",
                    attribute="dns_servers",
                    path_count=3,
                    paths_complete=True,
                )
                for index in range(atoms)
            )
        ),
        deterministic=DeterministicView(
            coverage=coverage,
            unsatisfied=Bounded[ObligationView](
                items=tuple(
                    ObligationView(
                        id=f"O{index + 1}",
                        owner="dns",
                        kind="monitoring",
                        role="observation",
                        change_ref="A1",
                        target=Target(device_mac=MAC, site_id=SITE),
                        metric="time-to-connect",
                        status="unsatisfied",
                        reason="No data in either window",
                    )
                    for index in range(obligations)
                )
            ),
        ),
        hints={"dns": "Client resolution failures show up as DNS failure events."},
    )


def reader(*, mcp: FakeMcp | None = None, registry: EvidenceRegistry | None = None, clock=None) -> Reader:
    return Reader(
        org_id=ORG,
        authority=SiteAuthority(site_ids=frozenset({SITE})),
        windows=WINDOWS,
        registry=registry or EvidenceRegistry(),
        deadlines={"rule": 90.0, "agent": 210.0},
        rule_allowances={},
        clock=clock or FakeClock(),
        mcp_transport=mcp if mcp is not None else FakeMcp(),
    )


def call(**overrides) -> str:
    arguments = {"search_type": "device_events", "site_id": SITE, "start_time": BEFORE[0], "end_time": BEFORE[1]}
    return json.dumps({"action": "call", "tool": "search_mist_data", "arguments": arguments | overrides})


def report(**overrides) -> str:
    values = {
        "action": "report",
        "peak_impact": "warning",
        "current_impact": "none",
        "confidence": "low",
        "summary": "Clients reconnected inside the window.",
        "evidence": ["E1"],
    }
    return json.dumps(values | overrides)


async def attempt(*replies, registry=None, mcp=None, coverage="partial", deadline=1_000.0, clock=None, **kwargs):
    """One agent run over a fresh Reader, returning the run and the fake model that answered it."""
    registry = registry if registry is not None else registry_with(evidence())
    model = FakeModel(*replies)
    run = await run_agent(
        client=model,
        reader=reader(mcp=mcp, registry=registry, clock=clock),
        registry=registry,
        inputs=inputs(coverage),
        deadline=deadline,
        clock=clock or FakeClock(),
        **kwargs,
    )
    return run, model


async def run(*replies, **kwargs):
    result, _ = await attempt(*replies, **kwargs)
    return result


# --- availability -----------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"runtime": False, "mcp_endpoint": True, "capability": True}, NO_RUNTIME),
        ({"runtime": True, "mcp_endpoint": False, "capability": True}, NO_MCP_ENDPOINT),
        ({"runtime": True, "mcp_endpoint": True, "capability": False}, NO_CAPABILITY),
        ({"runtime": True, "mcp_endpoint": True, "capability": True}, None),
    ],
)
def test_the_agent_is_skipped_with_an_explicit_reason(kwargs, reason) -> None:
    assert availability(**kwargs) == reason


async def test_no_client_skips_the_agent_without_a_turn() -> None:
    registry = registry_with(evidence())

    result = await run_agent(
        client=None,
        reader=reader(registry=registry),
        registry=registry,
        inputs=inputs(),
        deadline=1_000.0,
        clock=FakeClock(),
    )

    assert result.conclusion.concluded is False
    assert result.conclusion.reason == NO_RUNTIME
    assert (result.steps, result.turns) == ((), 0)


# --- the turn budget --------------------------------------------------------------------------------------------


async def test_seven_calls_a_disallowed_call_a_rejected_report_and_a_repair_fit_in_ten_turns() -> None:
    mcp = FakeMcp()
    replies = [
        *(call(limit=index + 100) for index in range(MAX_MCP_CALLS)),
        call(limit=99),
        report(peak_impact="none", current_impact="none"),
        report(),
    ]

    result = await run(*replies, mcp=mcp)

    assert len(mcp.calls) == MAX_MCP_CALLS
    assert result.turns == MAX_MODEL_TURNS
    assert [step.rejection for step in result.steps] == [
        *([None] * MAX_MCP_CALLS),
        "report_required",
        "coverage_required",
        None,
    ]
    assert result.conclusion.concluded is True
    assert result.conclusion.peak == "warning"


async def test_a_call_in_the_last_three_turns_is_rejected_as_report_required() -> None:
    calls = MAX_MODEL_TURNS - REPORT_ONLY_TURNS
    replies = [*(call(limit=index + 100) for index in range(calls)), call(limit=90), report()]

    result = await run(*replies)

    assert result.steps[calls].rejection == "report_required"
    assert result.steps[calls].action == "call"
    assert result.steps[calls].evidence_id is None


async def test_a_report_is_accepted_on_the_first_turn() -> None:
    result = await run(report())

    assert result.turns == 1
    assert result.conclusion.concluded is True


async def test_ten_turns_without_a_report_leave_no_conclusion() -> None:
    result = await run(*[report(peak_impact="none", current_impact="none")] * MAX_MODEL_TURNS)

    assert result.turns == MAX_MODEL_TURNS
    assert result.conclusion.concluded is False
    assert str(MAX_MODEL_TURNS) in (result.conclusion.reason or "")


# --- rejection categories ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("reply", "category"),
    [
        ("not json at all", "json_invalid"),
        (json.dumps({"action": "sing"}), "schema_mismatch"),
        (json.dumps({"action": "call", "tool": "rm_rf", "arguments": {}}), "tool_not_allowed"),
        (
            json.dumps(
                {"action": "call", "tool": "search_mist_data", "arguments": {"search_type": "alarms", "duration": "1d"}}
            ),
            "argument_invalid",
        ),
        (call(site_id="11111111-2222-3333-4444-555555555555"), "out_of_scope"),
        (call(start_time=1, end_time=2), "out_of_scope"),
        (report(peak_impact="none", current_impact="none"), "coverage_required"),
        (report(current_impact="critical"), "severity_order"),
        (report(evidence=["E9"]), "citation_invalid"),
        (report(evidence=[]), "citation_required"),
        (report(confidence="medium", evidence=["E2"]), "citation_required"),
        (
            report(impacted_devices=[{"mac": OTHER_MAC, "impact": "warning", "evidence": ["E1"]}]),
            "device_not_in_evidence",
        ),
    ],
)
async def test_every_rejection_category_is_reported_to_the_agent(reply, category) -> None:
    registry = registry_with(evidence(), evidence("E2", source="deployment", kind="deployment", title="Deployment"))

    result, model = await attempt(reply, report(), registry=registry)

    assert result.steps[0].rejection == category
    assert result.steps[0].detail
    assert f"Action rejected ({category})" in model.prompts[1][1]


async def test_a_rejected_report_is_repaired_on_the_next_turn() -> None:
    result = await run(report(peak_impact="none", current_impact="none"), report())

    assert [step.rejection for step in result.steps] == ["coverage_required", None]
    assert result.conclusion.concluded is True
    assert result.conclusion.summary == "Clients reconnected inside the window."


async def test_peak_none_is_accepted_when_deterministic_coverage_is_complete() -> None:
    result = await run(report(peak_impact="none", current_impact="none"), coverage="complete")

    assert result.conclusion.concluded is True
    assert result.conclusion.peak == "none"


async def test_an_uncited_info_report_is_accepted() -> None:
    result = await run(report(peak_impact="info", current_impact="info", evidence=[]))

    assert result.conclusion.concluded is True
    assert result.conclusion.evidence_ids == ()


async def test_a_warning_finding_must_cite_an_item() -> None:
    uncited = report(findings=[{"text": "Clients dropped", "impact": "warning", "evidence": []}])

    result = await run(uncited, report())

    assert result.steps[0].rejection == "citation_required"


async def test_error_evidence_cannot_be_cited() -> None:
    failed = evidence("E2", source="mcp:search_mist_data", collection="error", detail="The tool reported an error.")
    registry = registry_with(evidence(), failed)

    result = await run(report(evidence=["E2"]), report(), registry=registry)

    assert result.steps[0].rejection == "citation_invalid"


async def test_a_device_named_in_a_digest_identity_is_accepted() -> None:
    digest = evidence(
        "E2",
        source="rule:switch-port",
        kind="configuration",
        representation="digest",
        scope={"site_ids": (SITE,), "device_macs": (OTHER_MAC,)},
        payload={"digest": {"rows": {"results": 300}}},
    )
    registry = registry_with(evidence(), digest)
    named = report(impacted_devices=[{"mac": OTHER_MAC, "impact": "warning", "evidence": ["E1", "E2"]}])

    result = await run(named, registry=registry)

    assert result.conclusion.concluded is True
    assert [device.mac for device in result.conclusion.impacted_devices] == [OTHER_MAC]


async def test_a_device_named_in_a_kept_row_is_accepted() -> None:
    rows = evidence(
        "E2",
        source="mcp:search_mist_data",
        scope={"site_ids": (SITE,)},
        payload={"results": [{"port": 5, "up": True, "mac": OTHER_MAC}]},
    )
    registry = registry_with(evidence(), rows)
    named = report(impacted_devices=[{"mac": OTHER_MAC, "impact": "warning", "evidence": ["E2"]}])

    result = await run(named, registry=registry)

    assert result.conclusion.concluded is True


async def test_a_device_mac_is_normalized_before_it_is_stored() -> None:
    named = report(impacted_devices=[{"mac": "5C:5B:35:00:00:01", "impact": "warning", "evidence": ["E1"]}])

    result = await run(named)

    assert [device.mac for device in result.conclusion.impacted_devices] == [MAC]


async def test_a_device_that_is_not_a_mac_is_rejected() -> None:
    named = report(impacted_devices=[{"mac": "the third switch", "impact": "warning", "evidence": ["E1"]}])

    result = await run(named, report())

    assert result.steps[0].rejection == "device_not_in_evidence"


async def test_a_device_above_the_reported_peak_is_a_severity_order_rejection() -> None:
    named = report(impacted_devices=[{"mac": MAC, "impact": "critical", "evidence": ["E1"]}])

    result = await run(named, report())

    assert result.steps[0].rejection == "severity_order"


# --- what a step stores -----------------------------------------------------------------------------------------


async def test_a_step_stores_the_redacted_and_truncated_output_with_its_prompt_identity() -> None:
    noisy = json.dumps({"action": "report", "summary": "Bearer abcdef0123456789\nsecond line", "x": "y" * 9_000})

    result = await run(noisy, report())

    step = result.steps[0]
    assert "abcdef0123456789" not in step.output
    assert len(step.output.encode()) <= MODEL_OUTPUT_BUDGET
    assert (step.prompt_version, step.prompt_size > 0, len(step.prompt_hash)) == (PROMPT_VERSION, True, 64)
    assert step.visible_evidence_ids == ("E1",)
    assert step.withheld_evidence_ids == ()


async def test_a_call_step_records_its_evidence_id_arguments_and_collection() -> None:
    result = await run(call(), report(evidence=["E2"]))

    step = result.steps[0]
    assert (step.action, step.tool, step.evidence_id, step.collection) == ("call", "search_mist_data", "E2", "complete")
    assert step.arguments["search_type"] == "device_events"
    assert step.duration_ms >= 0
    assert result.conclusion.evidence_ids == ("E2",)


async def test_a_secret_in_the_output_is_redacted_before_storage() -> None:
    noisy = json.dumps({"action": "report", "summary": "token s3cr3t-value"})

    result = await run(noisy, report(), secrets=("s3cr3t-value",))

    assert "s3cr3t-value" not in result.steps[0].output


async def test_oversized_call_arguments_are_stored_as_a_measurement() -> None:
    bulky = json.dumps(
        {"action": "call", "tool": "search_mist_data", "arguments": {"search_type": "x" * 4_000, "site_id": SITE}}
    )

    result = await run(bulky, report())

    assert json_size(result.steps[0].arguments) < 1_500


async def test_ten_stored_turns_serialize_within_the_steps_budget() -> None:
    """What Task 8 writes to the run document: ten turns of the largest output a step may keep."""
    noisy = json.dumps({"action": "report", "summary": "s" * 9_000, "impact": "y" * 9_000})

    result = await run(*[noisy] * MAX_MODEL_TURNS)

    steps = tuple(step.model_dump(mode="json") for step in result.steps)
    assert len(steps) == MAX_MODEL_TURNS
    assert json_size(steps) <= STEPS_BUDGET


# --- the stored conclusion stays within the conclusions budget ----------------------------------------------------


MANY_MACS = tuple(f"5c5b35{index:06d}" for index in range(MAX_REPORT_ITEMS))


def maximal_report() -> str:
    """The largest report the action schema allows: 20 findings, 20 devices, 20 gaps and a full summary."""
    return json.dumps(
        {
            "action": "report",
            "peak_impact": "critical",
            "current_impact": "critical",
            "confidence": "medium",
            "summary": "s" * MAX_SUMMARY_CHARS,
            "evidence": ["E1"],
            "findings": [
                {
                    "text": f"finding {index}: " + "f" * (MAX_TEXT_CHARS - 20),
                    "impact": BANDS[index % len(BANDS)],
                    "evidence": ["E1"],
                }
                for index in range(MAX_REPORT_ITEMS)
            ],
            "impacted_devices": [{"mac": mac, "impact": "critical", "evidence": ["E1"]} for mac in MANY_MACS],
            "gaps": [f"gap {index}: " + "g" * (MAX_TEXT_CHARS - 20) for index in range(MAX_REPORT_ITEMS)],
        }
    )


def wide_registry() -> EvidenceRegistry:
    return registry_with(evidence(scope={"site_ids": (SITE,), "device_macs": MANY_MACS}))


async def test_a_maximal_report_is_stored_within_the_conclusions_budget() -> None:
    result = await run(maximal_report(), registry=wide_registry())

    conclusion = result.conclusion
    assert conclusion.concluded is True
    assert json_size(conclusion) <= CONCLUSIONS_BUDGET
    assert conclusion.summary == "s" * MAX_SUMMARY_CHARS
    assert (conclusion.peak, conclusion.current, conclusion.confidence) == ("critical", "critical", "medium")
    assert len(conclusion.impacted_devices) == MAX_REPORT_ITEMS
    assert len(conclusion.findings) < MAX_REPORT_ITEMS


async def test_a_trimmed_report_keeps_its_worst_findings_and_states_what_was_dropped() -> None:
    result = await run(maximal_report(), registry=wide_registry())

    conclusion = result.conclusion
    kept = [finding.severity for finding in conclusion.findings]
    assert kept == sorted(kept, key=lambda band: -BANDS.index(band))
    assert "critical" in kept
    assert any("not stored" in gap for gap in conclusion.gaps)
    dropped = next(gap for gap in conclusion.gaps if "not stored" in gap)
    assert f"{MAX_REPORT_ITEMS - len(conclusion.findings)} finding" in dropped
    assert f"{MAX_REPORT_ITEMS - len([g for g in conclusion.gaps if g != dropped])} gap" in dropped


async def test_a_trimmed_report_keeps_the_citations_its_bands_rest_on() -> None:
    registry = wide_registry()
    health = {item.id for item in registry.evidence if item.kind == "service_health"}

    result = await run(maximal_report(), registry=registry)

    verdict = compose(coverage="partial", agent=result.conclusion, evidence=registry.evidence)
    assert cited(result.conclusion) & health
    assert (verdict.peak, verdict.current, verdict.confidence) == ("critical", "critical", "medium")
    # The counts reach the report through the verdict's gaps, under the agent's own name.
    assert any(gap.source == "agent" and "not stored" in gap.text for gap in verdict.gaps)


async def test_a_report_within_the_budget_is_stored_whole() -> None:
    result = await run(report(findings=[{"text": "Clients dropped", "impact": "warning", "evidence": ["E1"]}]))

    assert [finding.text for finding in result.conclusion.findings] == ["Clients dropped"]
    assert result.conclusion.gaps == ()


# --- failures ---------------------------------------------------------------------------------------------------


async def test_a_provider_failure_leaves_a_reason_and_no_conclusion() -> None:
    result = await run(ModelError("connection reset by peer"))

    assert result.conclusion.concluded is False
    assert "connection reset" in (result.conclusion.reason or "")
    assert result.turns == 1


async def test_an_expired_phase_deadline_stops_the_loop() -> None:
    result = await run(report(), deadline=210.0, clock=FakeClock(now=500.0))

    assert result.turns == 0
    assert result.conclusion.concluded is False
    assert "deadline" in (result.conclusion.reason or "")


async def test_a_deadline_that_expires_during_the_run_stops_further_calls() -> None:
    clock = FakeClock()

    class Moving(FakeMcp):
        async def call_tool(self, name, arguments, *, timeout, max_bytes):
            clock.now = 500.0
            return await super().call_tool(name, arguments, timeout=timeout, max_bytes=max_bytes)

    result = await run(call(), call(limit=101), report(), mcp=Moving(), deadline=210.0, clock=clock)

    assert result.turns == 1
    assert result.conclusion.concluded is False


async def test_a_deadline_that_expires_while_the_model_answers_still_records_that_turn() -> None:
    clock = FakeClock()
    registry = registry_with(evidence())

    class Moving(FakeModel):
        async def complete(self, system: str, user: str) -> str:
            clock.now = 500.0
            return await super().complete(system, user)

    result = await run_agent(
        client=Moving(call(), report()),
        reader=reader(registry=registry, clock=clock),
        registry=registry,
        inputs=inputs(),
        deadline=1_000.0,
        clock=clock,
    )

    assert result.turns == 1
    assert result.steps[0].action == "call"
    assert "deadline" in result.steps[0].detail
    assert result.conclusion.concluded is False


async def test_a_call_that_fails_in_transport_is_error_evidence_and_the_loop_continues() -> None:
    result = await run(call(), report(), mcp=FakeMcp(result=TransportError("upstream refused")))

    assert result.steps[0].collection == "error"
    assert result.steps[0].rejection is None
    assert result.conclusion.concluded is True


async def test_a_catalogue_failure_leaves_the_agent_able_to_report() -> None:
    result = await run(call(), report(), mcp=FakeMcp(tools=TransportError("no MCP")))

    assert result.steps[0].rejection == "tool_not_allowed"
    assert result.conclusion.concluded is True


# --- the prompt -------------------------------------------------------------------------------------------------


def big_evidence(identity: str, source: str, size: int, **overrides) -> Evidence:
    item = evidence(identity, source=source, payload={"rows": "x"}, **overrides)
    filler = max(size - json_size(item), 0)
    return item.model_copy(update={"payload": {"rows": "x" * filler}})


def worst_case_inputs() -> AgentInputs:
    """The change view, the deterministic conclusion and the plug-in hints, each filled to its own budget."""
    atoms, obligations = 1, 1
    while json_size(inputs(atoms=atoms + 1).change) <= CHANGE_VIEW_BUDGET:
        atoms += 1
    while json_size(inputs(obligations=obligations + 1).deterministic) <= DETERMINISTIC_VIEW_BUDGET:
        obligations += 1
    filled = inputs(atoms=atoms, obligations=obligations)
    hints: dict[str, str] = {}
    while (
        len(json.dumps({**hints, f"plug-in-{len(hints)}": "h" * 200}, separators=(",", ":")).encode()) <= HINTS_BUDGET
    ):
        hints[f"plug-in-{len(hints)}"] = "h" * 200
    # One hint past the budget, which the builder leaves out whole rather than cutting the section in half.
    hints[f"plug-in-{len(hints)}"] = "h" * 200
    return AgentInputs(change=filled.change, deterministic=filled.deterministic, hints=hints)


async def catalogue():
    return await reader().tools()


async def worst_case_tools() -> "object":
    """A catalogue padded to its whole budget, so the fixed part of a prompt is measured at its real worst case."""
    view = tools_view(await catalogue())
    padding = {"name": "z" * 40, "arguments": {"description": ""}}
    shown = list(view.shown)
    while json_size([*shown, padding]) <= TOOL_CATALOGUE_BUDGET:
        shown.append({**padding, "name": f"z{len(shown)}" + "z" * 38})
    filler = TOOL_CATALOGUE_BUDGET - json_size(shown) - 1
    if filler > 0:
        shown[-1] = {**shown[-1], "arguments": {"description": "z" * filler}}
    # Every allowlisted tool that a catalogue could refuse, so the "tools not available" section is at its widest.
    unavailable = dict.fromkeys(CATALOGUE_TOOL_NAMES, DROPPED_TOOL)
    return ToolsView(shown=tuple(shown), dropped=view.dropped, unavailable=unavailable)


def prompt_of(items, *, feedback="", turns_left=10, agent_inputs=None, tools=None):
    return build_prompt(
        inputs=agent_inputs or inputs(),
        tools=tools,
        evidence=items,
        windows=WINDOWS,
        turns_left=turns_left,
        calls_left=MAX_MCP_CALLS,
        feedback=feedback,
    )


WORST_CASE_EVIDENCE = [
    *(big_evidence(f"E{index + 1}", "monitoring", 1_800) for index in range(10)),
    big_evidence("E11", "deployment", 4_000, kind="deployment"),
    *(big_evidence(f"E{12 + index}", "rule:switch-port", 4_000) for index in range(8)),
    *(big_evidence(f"E{20 + index}", "mcp:search_mist_data", 4_000) for index in range(7)),
]


async def test_the_fixed_part_of_a_worst_case_prompt_stays_within_its_budget() -> None:
    fixed = [item for item in WORST_CASE_EVIDENCE if item.source in ("monitoring", "deployment")]

    prompt = prompt_of(fixed, feedback="r" * 4_000, agent_inputs=worst_case_inputs(), tools=await worst_case_tools())

    assert prompt.fixed_size <= PROMPT_FIXED_BUDGET
    assert prompt.withheld == ()
    assert prompt.size == prompt.fixed_size


async def test_a_worst_case_prompt_withholds_the_oldest_mcp_then_rule_payloads() -> None:
    prompt = prompt_of(
        WORST_CASE_EVIDENCE, feedback="r" * 4_000, agent_inputs=worst_case_inputs(), tools=await worst_case_tools()
    )

    assert prompt.size <= PROMPT_CAP
    assert prompt.fixed_size <= PROMPT_FIXED_BUDGET
    assert prompt.withheld[0] == "E20"
    assert not set(prompt.withheld) & {f"E{index + 1}" for index in range(11)}
    assert "E20: withheld (not citable)" in prompt.user
    assert set(prompt.visible) | set(prompt.withheld) == {item.id for item in WORST_CASE_EVIDENCE}


async def test_rule_payloads_are_withheld_only_after_every_mcp_payload() -> None:
    mcp_items = {item.id for item in WORST_CASE_EVIDENCE if item.source.startswith("mcp:")}
    catalogue_view = await worst_case_tools()

    prompt = prompt_of(
        WORST_CASE_EVIDENCE, feedback="r" * 4_000, agent_inputs=worst_case_inputs(), tools=catalogue_view
    )

    withheld = list(prompt.withheld)
    assert withheld == sorted(withheld, key=lambda identity: (identity not in mcp_items, int(identity[1:])))


async def test_withheld_evidence_cannot_be_cited() -> None:
    registry = registry_with(*WORST_CASE_EVIDENCE)
    model = FakeModel(report(evidence=["E20"]), report(evidence=["E1"]))

    result = await run_agent(
        client=model,
        reader=reader(registry=registry),
        registry=registry,
        inputs=worst_case_inputs(),
        deadline=1_000.0,
        clock=FakeClock(),
    )

    assert result.steps[0].rejection == "citation_invalid"
    assert "E20" in result.steps[0].withheld_evidence_ids
    assert result.conclusion.concluded is True


async def test_the_tool_catalogue_drops_what_does_not_fit_and_says_so() -> None:
    view = tools_view(await catalogue(), budget=1_500)

    assert view.dropped
    assert json_size(view.shown) <= 1_500
    assert all(name in view.unavailable for name in view.dropped)


async def test_a_dropped_tool_is_no_longer_callable_and_is_reported_as_a_gap() -> None:
    registry = registry_with(evidence())
    shared = reader(registry=registry)
    model = FakeModel(call(), report())

    result = await run_agent(
        client=model,
        reader=shared,
        registry=registry,
        inputs=inputs(),
        deadline=1_000.0,
        clock=FakeClock(),
        catalogue_budget=200,
    )

    assert result.steps[0].rejection == "tool_not_allowed"
    assert any("search_mist_data" in gap for gap in result.conclusion.gaps)


async def test_the_whole_catalogue_fits_its_own_budget() -> None:
    view = tools_view(await catalogue())

    assert json_size(view.shown) <= TOOL_CATALOGUE_BUDGET
    assert view.dropped == ()


async def test_the_prompt_shows_the_change_the_coverage_and_the_plugin_hints() -> None:
    prompt = prompt_of([evidence()], tools=tools_view(await catalogue()))

    assert "dns_servers" in prompt.user
    assert "No data in either window" in prompt.user
    assert '"coverage":"partial"' in prompt.user
    assert "Client resolution failures" in prompt.user


async def test_a_plug_in_that_offers_no_hint_leaves_the_section_out() -> None:
    silent = AgentInputs(change=inputs().change, deterministic=inputs().deterministic)

    prompt = prompt_of([evidence()], agent_inputs=silent, tools=tools_view(await catalogue()))

    assert "plug-in hints" not in prompt.user


async def test_the_prompt_states_the_turn_and_call_budget_and_the_windows() -> None:
    prompt = prompt_of([evidence()], turns_left=4, tools=tools_view(await catalogue()))

    assert "turns_left: 4" in prompt.user
    assert f"mcp_calls_left: {MAX_MCP_CALLS}" in prompt.user
    assert str(BEFORE[0]) in prompt.user


async def test_feedback_is_bounded_to_one_line() -> None:
    prompt = prompt_of([evidence()], feedback="line one\nline two " + "x" * 4_000, tools=tools_view(await catalogue()))

    assert "line one line two" in prompt.user
    assert prompt.fixed_size <= PROMPT_FIXED_BUDGET


def test_the_system_prompt_states_the_protocol_within_its_budget() -> None:
    assert len(SYSTEM_PROMPT.encode()) <= SYSTEM_PROMPT_BUDGET
    assert "report" in SYSTEM_PROMPT
    assert "service_health" in SYSTEM_PROMPT


async def test_the_prompt_says_that_no_read_shows_the_present() -> None:
    """Every allowlisted service-health tool is time-ranged, so the agent is told there is no snapshot read."""
    prompt = prompt_of([evidence()], tools=tools_view(await catalogue()))

    assert "no snapshot tool for current state" in prompt.system
    assert prompt.fixed_size <= PROMPT_FIXED_BUDGET
