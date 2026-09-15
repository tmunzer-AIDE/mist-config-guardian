"""Replay the production MCP loop with real-size schemas and results; the fake model checks what it receives."""

import asyncio
import inspect
import json
import logging
from dataclasses import dataclass
from datetime import timedelta
from time import monotonic
from types import SimpleNamespace

import pytest
from bson import BSON
from bson.codec_options import CodecOptions

from mist_config_guardian_backend.impact.agent import (
    MAX_MODEL_CALLS,
    MCP_MAX_INPUT_BYTES,
    MCP_MAX_INPUT_BYTES_TOTAL,
    ModelRequestRecord,
    ModelResponseError,
)
from mist_config_guardian_backend.impact.limits import MAX_AUDIT_CALLS
from mist_config_guardian_backend.impact.mcp_contracts import MAX_MCP_EVIDENCE_BYTES
from mist_config_guardian_backend.integrations.ai_provider import AiCompletion, AiProviderError
from mist_config_guardian_backend.services import impact_agent, mcp_dispatch, mcp_impact_agent
from mist_config_guardian_backend.services import impact_investigations as worker
from test_impact_change_context import MAC, device_inputs, use_data
from test_mcp_investigation import CATALOG, MIST_ORG, FakeClock, mcp_runtime
from test_wlan_investigation import NOW, SITE

CHANGED = int(NOW.timestamp())
SERVICE_TOKEN = "test-token"  # The organization service token mcp_runtime hands the worker.
PROVIDER_KEY = "test-provider-key"  # The AI provider key agent_runtime configures.
CONFIGURED_RESPONSE_TOKENS = 1500
EVENT_ROWS = 200
SLE_POINTS = 240
STP_CHANGE = [{"stp_config": {"before": {"enabled": True}, "after": {"enabled": False}}}]
INFO_REPORT = {
    "summary": "No disruption was established from the returned evidence.",
    "scope": "Operational data for the changed site.",
    "impact": "info",
    "confidence": "low",
    "coverage": "partial",
    "gaps": ["Causation and complete fleet coverage are not established."],
}


def window(arguments):
    return int(arguments["start_time"]), int(arguments["end_time"])


def device_events(arguments):
    """Mist-like device events spread evenly over the queried window; port-down events only after the change."""
    start, end = window(arguments)
    rows = []
    for n in range(EVENT_ROWS):
        timestamp = start + (end - start) * n // EVENT_ROWS
        after = timestamp >= CHANGED
        port = f"ge-0/0/{n % 48}"
        rows.append(
            {
                "org_id": MIST_ORG,
                "site_id": SITE,
                "mac": MAC if after and n % 4 == 0 else f"aabbccdd{n % 30:04x}",
                "device_type": "switch",
                "type": "SW_PORT_DOWN" if after else "SW_CONFIGURED",
                "timestamp": timestamp,
                "port_id": port,
                "model": "EX4100-48P",
                "version": "23.4R2-S3.9",
                "severity": "warn" if after else "info",
                # A credential echoed in free text must be redacted before any prompt, artifact or log.
                "text": f"{port} STP state change; Authorization: Bearer {SERVICE_TOKEN}"
                if n == 1
                else f"{port} {'link down after BPDU' if after else 'configured'} (event {n})",
            }
        )
    return {"search_type": arguments.get("search_type"), "total": EVENT_ROWS, "results": rows}


def sle_series(arguments):
    """An SLE-like series over the queried window that degrades after the change."""
    start, end = window(arguments)
    points = []
    for n in range(SLE_POINTS):
        timestamp = start + (end - start) * n // SLE_POINTS
        after = timestamp >= CHANGED
        points.append(
            {
                "timestamp": timestamp,
                "site_id": SITE,
                "metric": "switch-health",
                "status": "degraded" if after else "healthy",
                "value": 0.91 if after else 0.99,
            }
        )
    return {"metric": "switch-health", "results": points}


def results(tool, arguments):
    return sle_series(arguments) if tool == "get_mist_insights" else device_events(arguments)


@dataclass(frozen=True)
class Reply:
    """A model completion with an explicit provider finish reason."""

    action: dict
    finish_reason: str = "stop"


class Replay:
    """Fake provider and MCP client; the provider hands every received prompt to the scripted policy."""

    def __init__(self, policy, tools=results):
        self.policy = policy
        self.tools = tools
        self.prompts: list[dict] = []
        self.bodies: list[str] = []
        self.systems: list[str] = []
        self.sessions = 0
        self.tool_calls: list[tuple[str, dict]] = []

    def complete(self, messages, *, max_tokens, json_object):
        assert json_object
        assert max_tokens == CONFIGURED_RESPONSE_TOKENS
        system, body = messages[0].content, messages[1].content
        assert SERVICE_TOKEN not in system + body
        assert PROVIDER_KEY not in system + body
        self.systems.append(system)
        self.bodies.append(body)
        self.prompts.append(json.loads(body))
        reply = self.policy(self.prompts[-1], len(self.prompts))
        if isinstance(reply, Exception):
            raise reply
        reply = reply if isinstance(reply, Reply) else Reply(reply)
        return AiCompletion(
            content=json.dumps(reply.action),
            model="test-model",
            request_tokens=100,
            response_tokens=50,
            finish_reason=reply.finish_reason,
        )

    async def call_tool(self, name, arguments):
        assert arguments["org_id"] == MIST_ORG
        self.tool_calls.append((name, arguments))
        result = self.tools(name, arguments)
        return {"structuredContent": await result if inspect.isawaitable(result) else result}

    def install(self, monkeypatch):
        replay = self

        class Session:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

        class Provider(Session):
            def __init__(self, **kwargs):
                assert kwargs["api_key"] == PROVIDER_KEY
                replay.sessions += 1

            async def complete(self, messages, *, max_tokens=None, json_object=False):
                return replay.complete(messages, max_tokens=max_tokens, json_object=json_object)

        class Client(Session):
            def __init__(self, *, url, token, cloud):
                assert (url, token, cloud) == ("https://mcp.example.test/mcp/mist", SERVICE_TOKEN, "api.mist.com")

            async def list_tools(self):
                return {"tools": CATALOG}

            async def call_tool(self, name, arguments):
                return await replay.call_tool(name, arguments)

        monkeypatch.setattr(mcp_impact_agent, "OpenAiCompatibleProvider", Provider)
        monkeypatch.setattr(mcp_impact_agent, "MistMcpClient", Client)
        return self


def replay_runtime(monkeypatch, on_reserve=None):
    service, root, collection, artifacts, stored = mcp_runtime(monkeypatch)
    root.model_input_bytes_limit = MCP_MAX_INPUT_BYTES_TOTAL  # As ensure() sets for new agent_shadow roots.
    fixed_clock_update = collection.update_one.side_effect

    async def update(query, mutation):
        # mcp_runtime pins the lease to LATER; replays move the clock across the audit hour.
        if "mcp_dispatches" in mutation.get("$push", {}):
            if stored["calls_used"] >= query["calls_used"]["$lt"] or query["generation"] != stored["generation"]:
                return SimpleNamespace(matched_count=0)
            encoded = BSON(BSON.encode(mutation)).decode(codec_options=CodecOptions(tz_aware=True))
            stored["calls_used"] += 1
            stored["mcp_dispatches"].append(encoded["$push"]["mcp_dispatches"])
            if on_reserve is not None:
                on_reserve(len(stored["mcp_dispatches"]))
            return SimpleNamespace(matched_count=1)
        return await fixed_clock_update(query, mutation)

    collection.update_one.side_effect = update
    return service, root, collection, artifacts, stored


def at(monkeypatch, root, minutes):
    now = NOW + timedelta(minutes=minutes)
    for module in (worker, mcp_impact_agent, mcp_dispatch, impact_agent):
        monkeypatch.setattr(module, "utc_now", lambda now=now: now)
    root.lease_until = now + timedelta(minutes=3)


async def poll(monkeypatch, service, root, minutes):
    at(monkeypatch, root, minutes)
    await service._poll(root)  # noqa: SLF001 - the replay drives the production worker checkpoint


def advance(root, artifacts, stored):
    """What the next lease claim reads back from the root after a publication."""
    root.report_id, root.revision = artifacts[-1].id, artifacts[-1].revision
    root.model_calls_used = stored["model_calls_used"]
    root.model_input_bytes_reserved = stored["model_input_bytes_reserved"]
    root.calls_used = stored["calls_used"]


def call(tool, arguments, purpose):
    return {"tool": tool, "arguments": arguments, "purpose": purpose}


def spanning(context, search_type="device_events"):
    """One query over before_window.start_time..after_window.end_time, as the prompt procedure suggests."""
    return {
        "search_type": search_type,
        "site_id": SITE,
        "start_time": context["before_window"]["start_time"],
        "end_time": context["after_window"]["end_time"],
    }


def before_and_after(context, tool, kind):
    selector = "insight_type" if tool == "get_mist_insights" else "search_type"
    return [
        call(tool, {selector: kind, "site_id": SITE, **context[name]}, f"{kind} in the {name}.")
        for name in ("before_window", "after_window")
    ]


def encoded(value):
    """The evidence bound's measure: UTF-8 bytes of non-ASCII-escaped JSON."""
    return len(json.dumps(value, ensure_ascii=False).encode())


def assert_redacted(replay, stored, artifacts, caplog):
    texts = (
        *replay.systems,
        *replay.bodies,
        *(a.content_json for a in stored["model_artifacts"]),
        *(a.model_dump_json() for a in artifacts),
        json.dumps([stored["model_requests"], stored["mcp_dispatches"]], default=str),
        caplog.text,
    )
    for secret in (SERVICE_TOKEN, PROVIDER_KEY):
        assert not [text for text in texts if secret in text], secret


def warning_report(evidence):
    return {
        "action": "report",
        "report": {
            "summary": "Port-down events started only after the change.",
            "scope": "Device events for the changed switch site.",
            "impact": "warning",
            "confidence": "low",
            "coverage": "partial",
            "evidence": [evidence],
            "findings": [
                {
                    "statement": "Port-down events appear only in the after-change bucket.",
                    "evidence": [evidence],
                    "limitations": ["Causation is not established."],
                }
            ],
            "impacted_devices": [
                {
                    "device_mac": MAC,
                    "site_id": SITE,
                    "service": "switching",
                    "impact": "warning",
                    "evidence": [evidence],
                    "explanation": "Port-down events for this switch after the change.",
                }
            ],
            "views": [
                {
                    "evidence_id": evidence,
                    "kind": "bar",
                    "rows_path": ["results_summary", "change_buckets"],
                    "label_key": "value",
                    "value_key": "after_change",
                }
            ],
            "gaps": ["A coincident fault has not been excluded."],
        },
    }


# Four event searches, each before and after the change, fill all eight evidence slots of a follow-up run.
EVENT_KINDS = ("device_events", "alarms", "client_sessions", "nac_client_events")


def prompt_bytes(system, context):
    return len((system + json.dumps(context, separators=(",", ":"), sort_keys=True)).encode())


async def test_newest_observation_and_changed_values_reach_the_model(monkeypatch, caplog):
    """Measured at the production 96 KB bound: the +30 report prompt would need about 109 KB untrimmed."""
    service, root, _, artifacts, stored = replay_runtime(monkeypatch)
    caplog.set_level(logging.INFO, logger=worker.__name__)

    def policy(context, _turn):
        change = context["configuration_changes"]["changes"][0]
        assert change["attributes"] == STP_CHANGE
        assert not context["configuration_changes"].get("gaps")
        search = next(t for t in context["tools"] if t["name"] == "search_mist_data")
        assert "device_events" in search["input_schema"]["properties"]["search_type"]["enum"]
        observations = context["observations"]
        if context["previous_report"] is None:
            # +10: one spanning search and a cited warning that the +30 run must keep visible.
            if not observations:
                return {"action": "tool", "calls": [call("search_mist_data", spanning(context), "Events.")]}
            return warning_report(observations[0]["id"])
        if len(observations) < len(EVENT_KINDS) * 2:
            kind = EVENT_KINDS[len(observations) // 2]
            return {"action": "tool", "calls": before_and_after(context, "search_mist_data", kind)}
        # A payload hidden for prompt size stays citable.
        return {"action": "report", "report": {**INFO_REPORT, "evidence": [observations[0]["id"]]}}

    replay = Replay(policy).install(monkeypatch)
    for minutes in (10, 20, 30):
        await poll(monkeypatch, service, root, minutes)
        advance(root, artifacts, stored)
    cited, mcp = artifacts[0].mcp.evidence[0], artifacts[2].mcp
    assert mcp.state == "complete", mcp.reason
    assert len(mcp.evidence) == 8
    assert all(e.state == "partial" and "digest" in e.data for e in mcp.evidence)
    assert all(encoded(e.data) <= MAX_MCP_EVIDENCE_BYTES for e in mcp.evidence)
    assert mcp.diagnostics.results_digested == 8

    system, final = replay.systems[-1], replay.prompts[-1]
    sent = prompt_bytes(system, final)
    assert sent == len((system + replay.bodies[-1]).encode()) == stored["model_requests"][-1]["input_bytes"]
    assert sent == mcp.diagnostics.max_prompt_bytes <= MCP_MAX_INPUT_BYTES
    hidden = [row["data"] == mcp_impact_agent.HIDDEN_PAYLOAD for row in final["observations"]]
    count = sum(hidden)
    # Oldest payloads are hidden first; the newest observation and the previously cited evidence never are.
    assert hidden == [True] * count + [False] * (len(hidden) - count)
    assert final["observations"][-1]["data"] == mcp.evidence[-1].data
    assert final["previous_checkpoint"]["evidence"][0] | {"data": None} == {
        "id": str(cited.id),
        "tool": cited.tool,
        "arguments": cited.arguments,
        "state": "partial",
        "captured_at": cited.captured_at.isoformat(),
        "data": None,
    }
    assert final["previous_checkpoint"]["evidence"][0]["data"] == cited.data

    def restored(rows):
        observations = [
            {**row, "data": mcp.evidence[n].data} if n < rows else row for n, row in enumerate(final["observations"])
        ]
        return prompt_bytes(system, {**final, "observations": observations})

    # Measured, not assumed: the untrimmed prompt exceeds the bound, and hiding stopped as soon as it fit.
    assert restored(count) > MCP_MAX_INPUT_BYTES
    assert count >= 1
    assert restored(count - 1) > MCP_MAX_INPUT_BYTES or count == 1
    assert (mcp.diagnostics.observations_hidden_in_prompt, mcp.diagnostics.prompt_trim_steps) == (count, 3)
    assert "Bearer [redacted]" in replay.bodies[1]
    assert_redacted(replay, stored, artifacts, caplog)


LONG_VLANS = ",".join(str(vlan) for vlan in range(1, 450))  # About 1.7 KB, below every context value bound.


async def run_with_long_stp_change(monkeypatch):
    service, root, _, artifacts, stored = replay_runtime(monkeypatch)
    data = device_inputs()
    for version in [*data["before"], *data["after"]]:
        version.configuration.pop("port_config")
        version.configuration["stp_config"] = {"enabled": version.version == 1, "vlans": LONG_VLANS}
    data["after"][0].changed_fields = ["stp_config"]
    use_data(service, data)

    def policy(context, turn):
        if turn == 1:
            return {"action": "tool", "calls": [call("search_mist_data", spanning(context), "Events.")]}
        return {"action": "report", "report": {**INFO_REPORT, "evidence": [context["observations"][0]["id"]]}}

    replay = Replay(policy).install(monkeypatch)
    await poll(monkeypatch, service, root, 10)
    return replay, artifacts[0].mcp, stored


async def test_long_changed_values_are_shortened_before_the_newest_observation_is_hidden(monkeypatch):
    measured, _, stored = await run_with_long_stp_change(monkeypatch)
    change = measured.prompts[-1]["configuration_changes"]["changes"][0]
    assert change["attributes"][0]["stp_config"]["after"] == {"enabled": False, "vlans": LONG_VLANS}
    unbounded = stored["model_requests"][-1]["input_bytes"]
    assert stored["model_requests"][0]["input_bytes"] < unbounded
    # One byte below the measured report prompt; this run has no older observation whose payload could be hidden.
    monkeypatch.setattr(mcp_impact_agent, "MCP_MAX_INPUT_BYTES", unbounded - 1)
    replay, mcp, stored = await run_with_long_stp_change(monkeypatch)
    assert mcp.state == "complete", mcp.reason
    final = replay.prompts[-1]
    assert stored["model_requests"][-1]["input_bytes"] <= unbounded - 1
    assert final["observations"][0]["data"] == mcp.evidence[0].data
    stp = final["configuration_changes"]["changes"][0]["attributes"][0]["stp_config"]
    assert stp["before"].endswith("…[shortened]")
    assert stp["after"].endswith("…[shortened]")
    assert final["configuration_changes"]["gaps"] == [
        "Long changed values were shortened in this prompt; consult the recorded diff or MCP."
    ]
    assert (mcp.diagnostics.prompt_trim_steps, mcp.diagnostics.observations_hidden_in_prompt) == (4, 0)


async def test_oversized_search_becomes_a_citable_digest_that_supports_a_warning(monkeypatch):
    service, root, _, artifacts, _ = replay_runtime(monkeypatch)

    def policy(context, turn):
        if turn == 1:
            return {
                "action": "tool",
                "tool": "search_mist_data",
                "arguments": spanning(context),
                "purpose": "Compare device events over the equal before and after windows.",
            }
        observation = context["observations"][0]
        summary = observation["data"]["results_summary"]
        assert summary["row_count"] == EVENT_ROWS
        assert summary["changed_at"] == CHANGED
        buckets = {(b["field"], b["value"]): (b["before_change"], b["after_change"]) for b in summary["change_buckets"]}
        assert buckets[("type", "SW_CONFIGURED")] == (100, 0)
        assert buckets[("type", "SW_PORT_DOWN")] == (0, 100)
        # The changed switch appears only after the first shown rows, yet its identity is still in the digest.
        assert MAC not in json.dumps(observation["data"]["results"])
        identity = {"org_id": MIST_ORG, "site_id": SITE, "device_type": "switch", "type": "SW_PORT_DOWN", "mac": MAC}
        assert identity in summary["devices"]
        return warning_report(observation["id"])

    replay = Replay(policy).install(monkeypatch)
    await poll(monkeypatch, service, root, 10)
    artifact = artifacts[0]
    assert artifact.mcp.state == "complete", artifact.mcp.reason
    assert window(replay.tool_calls[0][1]) == (CHANGED - 600, CHANGED + 600)
    assert artifact.mcp.evidence[0].state == "partial"
    assert artifact.report.current_impact == "warning"
    assert artifact.report.verdict_source == "mcp_agent"
    assert [d.device_mac for d in artifact.report.impacted_devices] == [MAC]
    bar = next(d for d in artifact.report.datasets if d.kind == "bar")
    assert ("SW_PORT_DOWN", 100) in bar.rows
    assert ("SW_CONFIGURED", 0) in bar.rows


async def test_audit_hour_runs_the_agent_three_times_within_budget(monkeypatch, caplog):
    service, root, _, artifacts, stored = replay_runtime(monkeypatch)
    caplog.set_level(logging.INFO, logger=worker.__name__)
    windows = []

    def policy(context, _turn):
        if not context["observations"]:
            windows.append((window(context["before_window"]), window(context["after_window"])))
            return {"action": "tool", "calls": before_and_after(context, "search_mist_data", "device_events")}
        return {"action": "report", "report": INFO_REPORT}

    replay = Replay(policy).install(monkeypatch)
    for minutes in (1, 10, 20, 30, 40, 50, 60):
        await poll(monkeypatch, service, root, minutes)
        advance(root, artifacts, stored)
    assert replay.sessions == 3
    assert [a.mcp.state for a in artifacts] == [
        "not_scheduled",
        "complete",
        "not_scheduled",
        "complete",
        "not_scheduled",
        "not_scheduled",
        "complete",
    ]
    # Each run compares equal before/after windows ending at its own checkpoint.
    assert [(after[1] - after[0], before[1] - before[0]) for before, after in windows] == [
        (600, 600),
        (1800, 1800),
        (3600, 3600),
    ]
    assert all(before[1] == after[0] == CHANGED for before, after in windows)
    assert stored["model_calls_used"] == 6
    assert stored["model_calls_used"] <= MAX_MODEL_CALLS
    assert stored["calls_used"] == 9  # Three discoveries plus three before/after pairs.
    assert stored["calls_used"] <= MAX_AUDIT_CALLS
    reserved = sum(r["input_bytes"] for r in stored["model_requests"])
    assert stored["model_input_bytes_reserved"] == reserved <= MCP_MAX_INPUT_BYTES_TOTAL
    assert artifacts[4].mcp.carried.source_revision == artifacts[3].revision
    assert artifacts[6].mcp.agent_as_of == NOW + timedelta(hours=1)
    lines = [
        json.loads(r.getMessage().removeprefix("mcp_checkpoint "))
        for r in caplog.records
        if r.getMessage().startswith("mcp_checkpoint ")
    ]
    assert [line["state"] for line in lines] == [a.mcp.state for a in artifacts]
    assert_redacted(replay, stored, artifacts, caplog)


async def test_deadline_returns_partial_evidence(monkeypatch):
    service, root, collection, artifacts, _ = replay_runtime(monkeypatch)
    clock = FakeClock()
    monkeypatch.setattr(worker, "monotonic", clock)
    monkeypatch.setattr(mcp_impact_agent, "monotonic", clock)

    def policy(_context, turn):
        if turn == 1:
            return {
                "action": "tool",
                "tool": "get_mist_insights",
                "arguments": {"insight_type": "sle", "site_id": SITE},
                "purpose": "SLE series across the change.",
            }
        clock.now += 200  # The model spends the checkpoint's time budget.
        return {"action": "describe", "tools": ["get_mist_stats"]}

    Replay(policy).install(monkeypatch)
    await poll(monkeypatch, service, root, 10)
    mcp = artifacts[0].mcp
    assert mcp.state == "deadline_exceeded"
    assert [e.state for e in mcp.evidence] == ["partial"]
    summary = mcp.evidence[0].data["results_summary"]
    assert summary["row_count"] == SLE_POINTS
    assert {(n["field"], n["min"], n["max"]) for n in summary["numeric"]} == {("value", 0.91, 0.99)}
    buckets = {
        b["value"]: (b["before_change"], b["after_change"]) for b in summary["change_buckets"] if b["field"] == "status"
    }
    assert buckets["healthy"][1] == buckets["degraded"][0] == 0
    assert buckets["healthy"][0] + buckets["degraded"][1] == SLE_POINTS
    assert (mcp.diagnostics.turns, mcp.diagnostics.describes) == (2, 1)
    assert artifacts[0].report is not None
    assert [d.target_handle for d in artifacts[0].report.datasets] == [str(mcp.evidence[0].id)]
    assert collection.update_one.await_args_list[-1].args[1]["$set"]["report_id"] == artifacts[0].id


async def test_rule_warning_survives_agent_failure(monkeypatch):
    service, root, _, artifacts, _ = replay_runtime(monkeypatch)
    monkeypatch.setattr(
        worker,
        "compose_domains",
        lambda _plan, _evidence, assessment: assessment.model_copy(
            update={"impact": "warning", "confidence": "medium"}
        ),
    )
    replay = Replay(lambda _context, _turn: AiProviderError("provider unavailable")).install(monkeypatch)
    await poll(monkeypatch, service, root, 10)
    artifact = artifacts[0]
    assert artifact.mcp.state == "provider_error"
    assert replay.tool_calls == []
    assert artifact.assessment.impact == "warning"
    assert artifact.report.verdict_source == "rule"
    assert artifact.report.peak_impact == "warning"
    assert any(g.startswith("Rule-derived verdict") for g in artifact.assessment.gaps)


class OffsetClock:
    """Real monotonic time plus a jump the test applies, so asyncio timeouts elapse in real time."""

    def __init__(self) -> None:
        self.offset = 0.0

    def __call__(self) -> float:
        return monotonic() + self.offset


HANG_REMAINING_SECONDS = 0.25


async def test_in_flight_tool_call_is_cut_off_at_the_remaining_deadline(monkeypatch):
    clock = OffsetClock()
    deadlines = []

    def on_reserve(count):
        if count == 3:  # Discovery, the first call, then a slow reservation write before the hanging call.
            clock.offset = deadlines[0] - HANG_REMAINING_SECONDS - monotonic()

    service, root, collection, artifacts, stored = replay_runtime(monkeypatch, on_reserve)
    monkeypatch.setattr(worker, "monotonic", clock)
    monkeypatch.setattr(mcp_impact_agent, "monotonic", clock)
    run_mcp = worker.McpImpactAgent.run_mcp

    async def recording_run(agent, investigation, **kwargs):
        deadlines.append(kwargs["deadline"])
        return await run_mcp(agent, investigation, **kwargs)

    monkeypatch.setattr(worker.McpImpactAgent, "run_mcp", recording_run)

    def policy(context, turn):
        assert turn <= 2
        if turn == 1:
            return {
                "action": "tool",
                "calls": [call("search_mist_data", spanning(context), "Events across the change.")],
            }
        assert [o["state"] for o in context["observations"]] == ["partial"]
        return {
            "action": "tool",
            "calls": [call("get_mist_insights", {"insight_type": "sle", "site_id": SITE}, "SLE across the change.")],
        }

    replay = Replay(policy)

    async def tools(name, arguments):
        if len(replay.tool_calls) == 2:
            await asyncio.sleep(30)  # A stuck MCP read; only the remaining-deadline timeout can end it.
        return results(name, arguments)

    replay.tools = tools
    replay.install(monkeypatch)
    started = monotonic()
    await poll(monkeypatch, service, root, 10)
    assert monotonic() - started < 5
    mcp = artifacts[0].mcp
    assert mcp.state == "deadline_exceeded", mcp.reason
    assert [e.state for e in mcp.evidence] == ["partial", "error"]
    assert mcp.evidence[0].data["results_summary"]["row_count"] == EVENT_ROWS
    assert (mcp.evidence[1].tool, mcp.evidence[1].error) == ("get_mist_insights", "transport")
    assert mcp.evidence[1].error_detail == "Tool call exceeded the remaining checkpoint time."
    assert [d["state"] for d in stored["mcp_dispatches"]] == ["complete", "partial", "error"]
    assert all(d["finished_at"] is not None for d in stored["mcp_dispatches"])
    assert mcp.diagnostics.tool_calls == 2
    assert collection.update_one.await_args_list[-1].args[1]["$set"]["report_id"] == artifacts[0].id


async def test_carried_conclusion_renders_and_reaches_the_next_run(monkeypatch):
    service, root, _, artifacts, stored = replay_runtime(monkeypatch)
    first_prompts = []

    def policy(context, _turn):
        if not context["observations"]:
            first_prompts.append(context)
            return {
                "action": "tool",
                "tool": "search_mist_data",
                "arguments": spanning(context),
                "purpose": "Compare device events over the equal before and after windows.",
            }
        return warning_report(context["observations"][0]["id"])

    replay = Replay(policy).install(monkeypatch)
    for minutes in (10, 20):
        await poll(monkeypatch, service, root, minutes)
        advance(root, artifacts, stored)
    ran, carried = artifacts
    evidence = ran.mcp.evidence[0]
    assert replay.sessions == 1
    assert carried.mcp.state == "not_scheduled"
    assert carried.mcp.evidence == ()
    assert carried.mcp.carried.source_revision == ran.revision
    assert carried.mcp.carried.evidence == (evidence,)
    report = carried.report
    assert (report.current_impact, report.verdict_source) == ("warning", "mcp_agent")
    assert f"Carried forward from revision {ran.revision}" in report.sections.summary.explanation
    [dataset] = report.datasets
    assert (dataset.target_handle, dataset.kind, dataset.state) == (str(evidence.id), "bar", "partial")
    assert ("SW_PORT_DOWN", 100) in dataset.rows
    assert [(d.device_mac, d.role, d.target_handle) for d in report.impacted_devices] == [
        (MAC, "agent_observed_service", str(evidence.id))
    ]

    await poll(monkeypatch, service, root, 30)
    context = first_prompts[1]
    assert context["previous_report"] == ran.mcp.conclusion.model_dump(mode="json")
    previous = context["previous_checkpoint"]
    assert (previous["source_revision"], previous["state"], previous["conclusion_source_revision"]) == (
        carried.revision,
        "not_scheduled",
        ran.revision,
    )
    assert [(row["id"], row["data"]) for row in previous["evidence"]] == [(str(evidence.id), evidence.data)]
    assert artifacts[2].mcp.state == "complete", artifacts[2].mcp.reason
    assert artifacts[2].mcp.carried is None


@pytest.mark.parametrize(
    "truncated",
    [
        {"action": "describe", "tools": ["search_mist_data"]},
        {
            "action": "tool",
            "calls": [
                call("search_mist_data", {"search_type": "device_events", "site_id": SITE}, "Device events."),
                call("search_mist_data", {"search_type": "alarms", "site_id": SITE}, "Alarms."),
            ],
        },
    ],
    ids=["describe", "batched_tool"],
)
async def test_length_finish_rejects_describe_and_batched_tool_actions_without_mcp_calls(monkeypatch, truncated):
    service, root, _, artifacts, stored = replay_runtime(monkeypatch)

    def policy(context, turn):
        if turn == 1:
            return Reply(truncated, finish_reason="length")
        if turn == 2:
            assert replay.tool_calls == []
            assert context["feedback"].startswith("Action rejected (truncated): ")
            assert (context["described_tools"], context["observations"]) == ([], [])
            return {
                "action": "tool",
                "calls": [call("search_mist_data", spanning(context), "Events across the change.")],
            }
        return {"action": "report", "report": INFO_REPORT}

    replay = Replay(policy).install(monkeypatch)
    await poll(monkeypatch, service, root, 10)
    first = ModelRequestRecord.model_validate(stored["model_requests"][0])
    assert (first.state, first.response_error, first.action_artifact_id) == (
        "invalid_response",
        ModelResponseError.TRUNCATED,
        None,
    )
    assert len(replay.tool_calls) == 1
    assert [d["tool"] for d in stored["mcp_dispatches"]] == ["tools/list", "search_mist_data"]
    diagnostics = artifacts[0].mcp.diagnostics
    assert diagnostics.rejected_actions == {"truncated": 1}
    assert (diagnostics.finish_reasons, diagnostics.describes) == (("length", "stop", "stop"), 0)
    assert artifacts[0].mcp.state == "complete", artifacts[0].mcp.reason
