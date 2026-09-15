"""Production MCP loop with real advertised tool schemas, independent of rule coverage."""

import asyncio
import json
import logging
import subprocess
import sys
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import httpx
import pytest
from beanie import PydanticObjectId
from beanie.odm.utils.encoder import Encoder
from bson import BSON
from bson.codec_options import CodecOptions
from pydantic import ValidationError
from pymongo.errors import ConnectionFailure

from mist_config_guardian_backend.impact import skills
from mist_config_guardian_backend.impact.agent import (
    MCP_MAX_INPUT_BYTES_TOTAL,
    MCP_MAX_OUTPUT_TOKENS,
    ModelRequestRecord,
    ModelResponseError,
)
from mist_config_guardian_backend.impact.mcp_context import configuration_context
from mist_config_guardian_backend.impact.mcp_contracts import (
    McpCheckpoint,
    McpConclusion,
    McpDispatch,
    McpEvidence,
    McpReportAction,
    McpToolAction,
    McpView,
)
from mist_config_guardian_backend.impact.mcp_schedule import agent_due, last_agent_run, prior_conclusion
from mist_config_guardian_backend.impact.mcp_scope import (
    McpScope,
    McpScopeError,
    catalog,
    compact_schema,
    normalize_result,
)
from mist_config_guardian_backend.impact.mcp_views import selected_rows
from mist_config_guardian_backend.integrations.mist_mcp import MistMcpClient, MistMcpError
from mist_config_guardian_backend.models.investigation import InvestigationRevision, ModelRequestArtifact
from mist_config_guardian_backend.services import impact_agent, mcp_dispatch, mcp_impact_agent, model_request_reads
from mist_config_guardian_backend.services import impact_investigations as worker
from mist_config_guardian_backend.services.application_configuration import AiRuntimeConfiguration
from mist_config_guardian_backend.services.audit_impact_reads import project_published_impact
from mist_config_guardian_backend.services.impact_acceptance import replay_chain
from mist_config_guardian_backend.services.mcp_request_reads import mcp_request_details
from test_impact_agent import AI_URL, add_mist, agent_runtime, ai_response, read_context
from test_impact_change_context import MAC, device_inputs, use_data
from test_wlan_investigation import LATER, NOW, SITE, inputs

MIST_ORG = "33333333-3333-4333-8333-333333333333"
MCP_URL = "https://mcp.example.test/mcp/mist"
CATALOG = json.loads((Path(__file__).parent / "fixtures/mist_mcp_catalog.json").read_text())


def mcp_runtime(monkeypatch, attribute="stp_config"):
    service, root, collection, artifacts, stored = agent_runtime(monkeypatch)
    # Use the production service, never the historical v8 transcript fixture.
    service.__class__ = worker.ImpactInvestigationService
    org = worker.Organization.get.return_value
    org.mist_org_id = MIST_ORG
    settings = SimpleNamespace(impact_engine_mode="agent_shadow", mist_mcp_url=MCP_URL)
    monkeypatch.setattr(worker, "get_settings", lambda: settings)
    monkeypatch.setattr(mcp_impact_agent, "get_settings", lambda: settings)
    monkeypatch.setattr(mcp_impact_agent, "utc_now", lambda: LATER)
    monkeypatch.setattr(mcp_dispatch, "utc_now", lambda: LATER)
    data = device_inputs()
    for v in [*data["before"], *data["after"]]:
        v.configuration.pop("port_config")
        v.configuration[attribute] = {"enabled": v.version == 1}
    data["after"][0].changed_fields = [attribute]
    use_data(service, data)
    stored["mcp_dispatches"] = []
    normal = collection.update_one.side_effect

    async def update(query, mutation):
        encoded = BSON(BSON.encode(mutation)).decode(codec_options=CodecOptions(tz_aware=True))
        if "mcp_dispatches" in mutation.get("$push", {}):
            assert query["organization_id"] == root.organization_id
            assert query["lease_until"] == {"$gt": LATER}
            if stored["calls_used"] >= query["calls_used"]["$lt"] or query["generation"] != stored["generation"]:
                return SimpleNamespace(matched_count=0)
            stored["calls_used"] += 1
            stored["mcp_dispatches"].append(encoded["$push"]["mcp_dispatches"])
            return SimpleNamespace(matched_count=1)
        if "mcp_dispatches" in query:
            predicate = BSON(BSON.encode(query)).decode(codec_options=CodecOptions(tz_aware=True))["mcp_dispatches"][
                "$elemMatch"
            ]
            matches = [r for r in stored["mcp_dispatches"] if all(r[k] == v for k, v in predicate.items())]
            if not matches:
                return SimpleNamespace(matched_count=0)
            for key, value in encoded["$set"].items():
                matches[0][key.removeprefix("mcp_dispatches.$.")] = value
            return SimpleNamespace(matched_count=1)
        return await normal(query, mutation)

    collection.update_one.side_effect = update
    return service, root, collection, artifacts, stored


def mcp_responses(httpx_mock, stored, *, result=None, error=False, tools=None):
    calls = []

    def respond(request):
        assert request.headers["authorization"] == "Bearer test-token"
        assert request.headers["x-mist-base-url"] == "https://api.mist.com"
        body = json.loads(request.content)
        calls.append(body)
        if body["method"] == "notifications/initialized":
            return httpx.Response(202)
        if body["method"] == "initialize":
            assert stored["mcp_dispatches"][-1]["state"] == "reserved"
            payload = {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}}
        elif body["method"] == "tools/list":
            payload = {"tools": CATALOG if tools is None else tools}
        else:
            assert stored["mcp_dispatches"][-1]["state"] == "reserved"
            assert body["params"]["arguments"]["org_id"] == MIST_ORG
            payload = {
                "isError": error,
                "structuredContent": result
                if result is not None
                else {
                    "results": [
                        {
                            "org_id": MIST_ORG,
                            "site_id": SITE,
                            "mac": MAC,
                            "type": "SW_PORT_DOWN",
                            "timestamp": int(LATER.timestamp()),
                        }
                    ],
                    "total": 1,
                },
            }
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream", "mcp-session-id": "bounded-session"},
            content="event: message\ndata: "
            + json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": payload})
            + "\n\n",
        )

    httpx_mock.add_callback(
        respond, method="POST", url=httpx.URL(MCP_URL, params={"cloud": "api.mist.com"}), is_reusable=True
    )
    return calls


def report(context, impact="warning"):
    ids = [r["id"] for r in context["observations"] if r["state"] != "error"]
    return {
        "action": "report",
        "report": {
            "summary": "Possible service interruption after the configuration change.",
            "scope": "Port events for the changed switch during the audit window.",
            "impact": impact,
            "confidence": "low",
            "coverage": "partial" if impact != "none" else "complete",
            "evidence": ids,
            "findings": [
                {
                    "statement": "A switch port-down event was returned during the change window.",
                    "evidence": ids,
                    "limitations": ["Historical dependency and causation remain unconfirmed."],
                }
            ]
            if ids
            else [],
            "impacted_devices": [
                {
                    "device_mac": MAC,
                    "site_id": SITE,
                    "service": "forwarding",
                    "impact": impact,
                    "evidence": ids,
                    "explanation": "Port-down evidence for this switch.",
                }
            ]
            if ids and impact == "warning"
            else [],
            "gaps": ["A coincident fault has not been excluded."],
        },
    }


def investigator(request):
    context = read_context(request)
    if context["observations"]:
        return ai_response(report(context))
    if not context["described_tools"]:
        return ai_response({"action": "describe", "tools": ["search_mist_data"]})
    return ai_response(
        {
            "action": "tool",
            "tool": "search_mist_data",
            "arguments": {"search_type": "device_events", "site_id": SITE, "filters": {"mac": MAC}},
            "purpose": "Check for operational transitions after the change.",
        }
    )


@pytest.mark.parametrize("attribute", ["stp_config", "dns_servers", "an_unknown_future_attribute"])
async def test_unmapped_change_runs_real_mcp_and_publishes_agent_verdict(monkeypatch, httpx_mock, attribute):
    service, root, _, artifacts, stored = mcp_runtime(monkeypatch, attribute)
    calls = mcp_responses(httpx_mock, stored)
    httpx_mock.add_callback(investigator, method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert not artifact.plan.targets
    assert artifact.mcp.state == "complete", artifact.mcp.reason
    assert artifact.assessment.policy_version == "mcp-agent.v1"
    assert artifact.assessment.impact == "warning"
    assert artifact.deterministic_assessment.impact == "info"
    assert artifact.report.current_impact == "warning"
    assert artifact.report.source == "mcp_agent"
    assert artifact.report.impacted_devices[0].device_mac == MAC
    assert len([c for c in calls if c["method"] == "tools/call"]) == 1
    assert stored["calls_used"] == 2  # Discovery plus one operational call, zero deterministic calls.
    assert all(d["state"] == "complete" for d in stored["mcp_dispatches"])
    assert InvestigationRevision.model_validate_json(artifact.model_dump_json()) == artifact
    summary = project_published_impact(
        {**root.model_dump(), "_id": root.id, "report_id": artifact.id, "revision": artifact.revision},
        artifact.model_dump(),
    )
    assert summary.impact == "warning"
    assert await replay_chain(artifact) is None  # The old deterministic gate cannot certify this verdict.


def test_real_catalog_excludes_identity_tool_and_remote_schema_references():
    tools = catalog(CATALOG)
    assert len(tools) == 6
    assert "get_mist_self" not in {t.name for t in tools}
    row = {**CATALOG[0], "inputSchema": {"$ref": "https://attacker.example/schema"}}
    with pytest.raises(McpScopeError):
        catalog([row])


@pytest.mark.parametrize(
    "args",
    [
        {"org_id": str(uuid4())},
        {"site_id": str(uuid4())},
        {"filters": {"org_id": str(uuid4())}},
        {"duration": "7d"},
        {"start_time": "0"},
        {"next_cursor": "forged"},
        {"limit": True},
        {"url": "https://attacker.example"},
    ],
)
def test_generic_scope_blocks_foreign_or_unbounded_arguments(args):
    scope = McpScope(org_id=UUID(MIST_ORG), changed_at=NOW, as_of=LATER, sites=[SITE])
    tool = next(t for t in catalog(CATALOG) if t.name == "search_mist_data")
    with pytest.raises(McpScopeError):
        scope.arguments(tool, {"search_type": "device_events", **args})


def test_redaction_preserves_missing_and_zero_and_marks_omission():
    result, partial = normalize_result(
        {
            "structuredContent": {
                "password": "do-not-retain",
                "power_draw": 0,
                "missing": None,
                "nested": {"token": "secret"},
                "text": "token-secret",
            }
        },
        secrets=("token-secret",),
    )
    assert partial
    assert result["power_draw"] == 0
    assert result["missing"] is None
    assert "do-not-retain" not in json.dumps(result)
    assert "token-secret" not in json.dumps(result)


async def test_missing_mcp_endpoint_is_explicit_and_no_model_or_http(monkeypatch, httpx_mock):
    service, root, _, artifacts, _ = mcp_runtime(monkeypatch)
    monkeypatch.setattr(mcp_impact_agent, "get_settings", lambda: SimpleNamespace(mist_mcp_url=""))
    await service._poll(root)  # noqa: SLF001
    assert artifacts[0].mcp.state == "unavailable"
    assert "MIST_MCP_URL" in artifacts[0].mcp.reason
    assert artifacts[0].assessment.impact == "info"
    assert not httpx_mock.get_requests()


@pytest.mark.parametrize("committed", [False, True])
async def test_uncertain_mcp_reservation_never_opens_connection(monkeypatch, httpx_mock, committed):
    service, root, collection, artifacts, stored = mcp_runtime(monkeypatch)
    normal = collection.update_one.side_effect

    async def uncertain(query, mutation):
        if "mcp_dispatches" in mutation.get("$push", {}):
            if committed:
                await normal(query, mutation)
            msg = "uncertain acknowledgement"
            raise ConnectionFailure(msg)
        return await normal(query, mutation)

    collection.update_one.side_effect = uncertain
    with pytest.raises(ConnectionFailure):
        await service._poll(root)  # noqa: SLF001
    assert not httpx_mock.get_requests()
    assert not artifacts
    assert len(stored["mcp_dispatches"]) == int(committed)


async def test_revoked_credential_blocks_tool_after_model_selection(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    calls = mcp_responses(httpx_mock, stored)
    normal = worker.Organization.get

    async def organization(identity):
        result = await normal(identity)
        if stored["model_calls_used"] >= 2:
            return SimpleNamespace(status=result.status, encrypted_service_token="rotated")
        return result

    monkeypatch.setattr(worker.Organization, "get", AsyncMock(side_effect=organization))
    httpx_mock.add_callback(investigator, method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    assert artifacts[0].mcp.state == "dispatch_denied"
    assert "credential changed" in artifacts[0].mcp.reason
    assert not any(c["method"] == "tools/call" for c in calls)


def test_unobserved_device_or_citation_cannot_enter_report():
    scope = McpScope(org_id=UUID(MIST_ORG), changed_at=NOW, as_of=LATER, sites=[SITE])
    action = McpReportAction.model_validate(report({"observations": [{"id": str(uuid4()), "state": "complete"}]}))
    with pytest.raises(McpScopeError):
        mcp_impact_agent.McpImpactAgent._validate_conclusion(action, [], scope)  # noqa: SLF001
    with pytest.raises(ValidationError):
        McpConclusion(summary="No outage", impact="none", confidence="low", coverage="partial")


def test_chart_uses_only_returned_values_and_preserves_zero():

    evidence = McpEvidence(
        id=uuid4(),
        tool="get_mist_stats",
        arguments={},
        captured_at=LATER,
        schema_hash="test",
        state="complete",
        data={"results": [{"name": "a", "value": 0}, {"name": "b", "value": 3}]},
    )
    view = McpView(evidence_id=evidence.id, kind="bar", rows_path=("results",), label_key="name", value_key="value")
    assert selected_rows(evidence, view) == [("a", 0), ("b", 3)]
    with pytest.raises(McpScopeError):
        selected_rows(evidence, view.model_copy(update={"value_key": "invented"}))
    missing = evidence.model_copy(update={"data": {"results": [{"name": "a", "value": None}]}})
    with pytest.raises(McpScopeError):
        selected_rows(missing, view)


async def test_error_response_cannot_be_reported_as_healthy(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    mcp_responses(httpx_mock, stored, error=True, result={"error": "token and attacker instructions"})

    def response(request):
        context = read_context(request)
        if context["observations"]:
            action = report(context, "none")
            action["report"]["evidence"] = [context["observations"][0]["id"]]
            return ai_response(action)
        return investigator(request)

    httpx_mock.add_callback(response, method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    assert artifacts[0].mcp.state == "invalid_response"
    assert artifacts[0].assessment.impact == "info"
    assert artifacts[0].mcp.evidence[0].data is None
    assert artifacts[0].mcp.evidence[0].error_detail == "token and attacker instructions"
    assert "attacker instructions" not in artifacts[0].report.model_dump_json()
    assert "attacker instructions" not in artifacts[0].assessment.model_dump_json()


async def test_tool_error_detail_is_bounded_redacted_and_shown_to_model(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    message = "Invalid filter key 'foo' for device_events. Authorization: Bearer test-token " + "x" * 800
    mcp_responses(httpx_mock, stored, error=True, result={"error": message})
    contexts = []

    def respond(request):
        context = read_context(request)
        contexts.append(context)
        if context["observations"]:
            return ai_response(report(context, "info"))
        return investigator(request)

    httpx_mock.add_callback(respond, method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    evidence = artifacts[0].mcp.evidence[0]
    assert (evidence.state, evidence.error, evidence.data) == ("error", "tool_error", None)
    assert evidence.error_detail.startswith("Invalid filter key 'foo' for device_events.")
    assert "test-token" not in evidence.error_detail
    assert len(evidence.error_detail.encode()) <= 500
    assert contexts[-1]["observations"][0]["error_detail"] == evidence.error_detail
    assert artifacts[0].mcp.state == "complete"
    assert artifacts[0].mcp.conclusion.evidence == ()


def test_json_rpc_error_message_becomes_detail():
    with pytest.raises(MistMcpError) as caught:
        MistMcpClient._result({"error": {"code": -32602, "message": "Unknown search_type"}})  # noqa: SLF001
    assert (caught.value.code, caught.value.detail) == ("tool_error", "Unknown search_type")


def test_foreign_response_is_rejected_before_observation():
    scope = McpScope(org_id=UUID(MIST_ORG), changed_at=NOW, as_of=LATER, sites=[SITE])
    with pytest.raises(McpScopeError):
        scope.validate_response({"results": [{"org_id": str(uuid4()), "mac": MAC}]})


def test_cursor_is_bound_to_origin_arguments_and_tool():
    scope = McpScope(org_id=UUID(MIST_ORG), changed_at=NOW, as_of=LATER, sites=[SITE])
    tools = {t.name: t for t in catalog(CATALOG)}
    args = scope.arguments(tools["search_mist_data"], {"search_type": "device_events", "site_id": SITE})
    scope.observe("search_mist_data", args, {"next_cursor": "server-cursor"})
    assert scope.arguments(tools["search_mist_data"], {"next_cursor": "server-cursor"})["site_id"] == SITE
    with pytest.raises(McpScopeError):
        scope.arguments(tools["get_mist_config"], {"next_cursor": "server-cursor"})


async def test_deterministic_evidence_is_optional_citable_context(monkeypatch, httpx_mock):

    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    data = inputs()
    data["logicals"][0].object_type = "wlans"
    use_data(service, data)
    add_mist(httpx_mock)
    calls = mcp_responses(httpx_mock, stored)

    def response(request):
        context = read_context(request)
        optional = context["deterministic_context"]
        assert optional["tool"] == "guardian_deterministic"
        assert optional["data"]["assessment"]["coverage"] == "complete"
        return ai_response(
            {
                "action": "report",
                "report": {
                    "summary": "No clients were present in the recorded WLAN session baseline.",
                    "scope": "Historical sessions for the removed WLAN, not AP health.",
                    "impact": "none",
                    "confidence": "low",
                    "coverage": "complete",
                    "evidence": [optional["id"]],
                    "gaps": ["This does not evaluate unrelated services."],
                },
            }
        )

    httpx_mock.add_callback(response, method="POST", url=AI_URL)
    await service._poll(root)  # noqa: SLF001
    assert artifacts[0].mcp.state == "complete"
    assert artifacts[0].assessment.impact == "none"
    assert artifacts[0].mcp.deterministic_evidence is not None
    assert not any(c["method"] == "tools/call" for c in calls)
    assert stored["calls_used"] == 3  # Two existing rule reads + one MCP discovery; no duplicated telemetry.


@pytest.mark.parametrize(
    "tamper", [None, "organization_id", "request_id", "generation", "candidate_revision", "content_json"]
)
async def test_mcp_request_details_validate_full_pointer_and_digest(monkeypatch, httpx_mock, tamper):

    service, root, collection, _, stored = mcp_runtime(monkeypatch)
    mcp_responses(httpx_mock, stored)
    httpx_mock.add_callback(investigator, method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    record = stored["mcp_dispatches"][-1]
    request_id = McpDispatch.model_validate(record).id

    async def selected(query, *, projection):
        assert query == {"organization_id": root.organization_id, "audit_id": root.audit_id}
        assert projection["mcp_dispatches"]["$elemMatch"]["id"] == Encoder().encode(request_id)
        return {"_id": root.id, "mcp_dispatches": [record]}

    collection.find_one.side_effect = selected

    async def artifact(query):
        value = next((a for a in stored["model_artifacts"] if a.id == query["_id"]), None)
        if value and tamper:
            replacement = {
                "organization_id": PydanticObjectId(),
                "request_id": uuid4(),
                "generation": 999,
                "candidate_revision": 999,
                "content_json": "{}",
            }[tamper]
            value = value.model_copy(update={tamper: replacement})
        return value

    monkeypatch.setattr(ModelRequestArtifact, "find_one", AsyncMock(side_effect=artifact))
    result = await mcp_request_details(root.organization_id, PydanticObjectId(), request_id)
    assert result.input_state == ("unavailable" if tamper else "available")
    assert result.response_state == ("unavailable" if tamper else "available")
    if not tamper:
        assert json.loads(result.response_json)["id"] == str(request_id)
        assert json.loads(result.input_json)["org_id"] == MIST_ORG


async def test_mcp_artifact_completion_failure_stops_publication(monkeypatch, httpx_mock):

    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    mcp_responses(httpx_mock, stored)
    normal = ModelRequestArtifact.insert

    async def fail(artifact):
        if artifact.kind == "mcp_result":
            message = "uncertain evidence artifact insert"
            raise ConnectionFailure(message)
        return await normal(artifact)

    monkeypatch.setattr(ModelRequestArtifact, "insert", fail)
    with pytest.raises(ConnectionFailure):
        await service._poll(root)  # noqa: SLF001
    assert not artifacts
    assert stored["mcp_dispatches"][-1]["state"] == "reserved"


async def test_exhausted_model_budget_does_not_spend_on_mcp_discovery(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    root.model_calls_used = root.model_calls_limit
    await service._poll(root)  # noqa: SLF001
    assert artifacts[0].mcp.state == "budget_exhausted"
    assert not stored["mcp_dispatches"]
    assert not httpx_mock.get_requests()


async def test_followup_reuses_verified_tool_schema_and_historical_context(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    mcp_responses(httpx_mock, stored)

    def response(request):
        context = read_context(request)
        if context["previous_checkpoint"] and not context["observations"]:
            assert context["previous_checkpoint"]["source_revision"] == root.revision
            assert "search_mist_data" in {t["name"] for t in context["tools"]}
            args = context["previous_checkpoint"]["evidence"][0]["arguments"]
            return ai_response(
                {
                    "action": "tool",
                    "tool": "search_mist_data",
                    "arguments": args,
                    "purpose": "Recheck the previously investigated scope.",
                }
            )
        return investigator(request)

    httpx_mock.add_callback(response, method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    first = artifacts[-1]
    root.report_id = first.id
    root.revision = first.revision
    root.model_calls_used = stored["model_calls_used"]
    root.calls_used = stored["calls_used"]
    monkeypatch.setattr(worker, "agent_due", lambda *_args: True)  # Same fixed clock; force a second agent run.
    await service._poll(root)  # noqa: SLF001
    assert artifacts[-1].mcp.state == "complete"
    assert len(artifacts[-1].mcp.request_ids) == 2  # Query then report, not another catalogue explanation.
    assert artifacts[-1].previous_report_id == first.id


def test_two_hundred_configured_devices_stay_in_one_compact_context():
    summary = mcp_impact_agent.McpImpactAgent._deployment_summary(  # noqa: SLF001 - compact deployment contract
        {
            "state": "observed",
            "devices": [
                {
                    "site_id": SITE,
                    "device_type": "ap",
                    "outcome": "configured",
                    "correlation": "audit_id",
                    "device_mac": f"{n:012x}",
                }
                for n in range(200)
            ],
        }
    )
    assert len(summary["groups"]) == 1
    assert len(summary["groups"][0]["device_macs"]) == 200
    assert summary["expected_device_count"] is None
    assert len(json.dumps(summary).encode()) < 4000


def test_pagination_without_cursor_stays_partial():
    _, partial = normalize_result({"structuredContent": {"total": 200, "count": 1, "data": [{"type": "ap"}]}})
    assert partial


def test_client_macs_cannot_be_registered_as_impacted_devices():
    scope = McpScope(org_id=UUID(MIST_ORG), changed_at=NOW, as_of=LATER, sites=[SITE])
    scope.observe(
        "search_mist_data",
        {"search_type": "wireless_clients", "site_id": SITE},
        {"data": [{"mac": MAC, "type": "wireless_client"}]},
    )
    assert not scope.devices


def test_investigator_can_import_in_a_fresh_process():

    result = subprocess.run(
        [sys.executable, "-c", "from mist_config_guardian_backend.services.mcp_impact_agent import McpImpactAgent"],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr


def test_truncated_changed_values_are_explicit_but_credentials_remain_withheld():

    data = device_inputs()
    data["after"][0].configuration["port_config"] = {str(n): {"enabled": True} for n in range(101)}
    context = configuration_context(data["organization_id"], data["logicals"], data["before"], data["after"])
    assert context["gaps"]
    assert "abbreviated" in context["gaps"][0]


def test_nonfinite_numeric_response_is_missing_not_zero():
    cleaned, partial = normalize_result({"structuredContent": {"value": float("nan"), "zero": 0}})
    assert partial
    assert cleaned["value"] is None
    assert cleaned["zero"] == 0


async def test_optional_rules_leave_budget_for_mcp_investigation(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    data = inputs()
    data["logicals"] = []
    data["before"] = []
    data["after"] = []
    for _ in range(4):
        item = inputs()
        identity = PydanticObjectId()
        item["logicals"][0].id = identity
        item["logicals"][0].object_type = "wlans"
        wlan = str(uuid4())
        for v in [*item["before"], *item["after"]]:
            v.logical_object_id = identity
            v.configuration["id"] = wlan
        for key in ("logicals", "before", "after"):
            data[key].extend(item[key])
    use_data(service, data)
    add_mist(httpx_mock)
    mcp_responses(httpx_mock, stored)
    httpx_mock.add_callback(investigator, method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    assert len(artifacts[0].evidence) == 4  # The full deterministic plan has eight checks.
    assert artifacts[0].deterministic_assessment.coverage == "partial"
    assert artifacts[0].mcp.state == "complete"
    assert len(stored["mcp_dispatches"]) == 2
    assert stored["calls_used"] == 6


async def test_rejected_actions_return_specific_bounded_feedback(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    mcp_responses(httpx_mock, stored)
    foreign = str(uuid4())
    feedback = []

    def respond(request):
        context = read_context(request)
        feedback.append(context["feedback"])
        step = len(feedback)
        if step == 1:
            return ai_response(
                {"action": "tool", "tool": "secret-provider-text", "arguments": {}, "purpose": "Invalid tool."}
            )
        if step == 2:
            return ai_response({"action": "describe", "tools": ["search_mist_data"]})
        if step == 3:
            return ai_response(
                {
                    "action": "tool",
                    "tool": "search_mist_data",
                    "arguments": {"search_type": "device_events", "site_id": foreign},
                    "purpose": "Query an undiscovered site.",
                }
            )
        return ai_response(report({"observations": [{"id": str(uuid4()), "state": "complete"}]}))

    httpx_mock.add_callback(respond, method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    records = [ModelRequestRecord.model_validate(r) for r in stored["model_requests"]]
    assert records[0].response_error == ModelResponseError.SCHEMA_MISMATCH
    assert "Input should be" in records[0].response_detail
    assert "secret-provider-text" not in records[0].response_detail
    assert feedback[1].startswith("Action rejected (schema_mismatch): ")
    assert "secret-provider-text" not in feedback[1]
    assert records[2].response_error == ModelResponseError.ARGUMENT_OUT_OF_SCOPE
    assert feedback[3] == (
        "Action rejected (argument_out_of_scope): Discover this site through an organization-scoped MCP result first"
    )
    assert records[3].response_error == ModelResponseError.CITATION_INVALID
    assert all(len((r.response_detail or "").encode()) <= 300 for r in records)
    assert all(r.response_detail is None for r in records if r.state == "complete")
    assert artifacts[0].mcp.state == "invalid_response"


def test_invalid_json_detail_never_echoes_model_text():
    category, detail = mcp_impact_agent.McpImpactAgent._rejection(  # noqa: SLF001
        _validation_error('{"action":"report","report":{"summary":"secret-provider-text"'), ("test-token",)
    )
    assert category == ModelResponseError.INVALID_JSON
    assert "secret-provider-text" not in detail
    assert detail.startswith("<root>: Invalid JSON")


def _validation_error(text):
    try:
        mcp_impact_agent.ADAPTER.validate_json(text)
    except ValidationError as exc:
        return exc
    raise AssertionError


def test_unresolvable_chart_view_is_dropped_with_limitation():
    scope = McpScope(org_id=UUID(MIST_ORG), changed_at=NOW, as_of=LATER, sites=[SITE])
    evidence = McpEvidence(
        id=uuid4(),
        tool="get_mist_stats",
        arguments={},
        captured_at=LATER,
        schema_hash="test",
        state="complete",
        data={"results": [{"name": "a", "value": 1}]},
    )
    action = McpReportAction.model_validate(
        {
            "action": "report",
            "report": {
                "summary": "Statistics were retrieved.",
                "scope": "Organization statistics.",
                "impact": "info",
                "confidence": "low",
                "coverage": "partial",
                "evidence": [str(evidence.id)],
                "views": [
                    {
                        "evidence_id": str(evidence.id),
                        "kind": "bar",
                        "rows_path": ["results"],
                        "label_key": "name",
                        "value_key": "invented",
                    },
                    {
                        "evidence_id": str(uuid4()),
                        "kind": "table",
                        "rows_path": ["results"],
                        "label_key": "name",
                        "value_key": "value",
                    },
                ],
            },
        }
    )
    cleaned = mcp_impact_agent.McpImpactAgent._validate_conclusion(action, [evidence], scope)  # noqa: SLF001
    assert cleaned.report.views == ()
    assert cleaned.report.gaps == ("A proposed chart was omitted because it did not select returned evidence rows.",)


async def test_checkpoint_diagnostics_are_persisted_and_logged(monkeypatch, httpx_mock, caplog):
    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    mcp_responses(httpx_mock, stored)
    httpx_mock.add_callback(investigator, method="POST", url=AI_URL, is_reusable=True)
    caplog.set_level(logging.INFO, logger=worker.__name__)
    await service._poll(root)  # noqa: SLF001
    diagnostics = artifacts[0].mcp.diagnostics
    assert diagnostics.final_state == "complete"
    assert (diagnostics.turns, diagnostics.describes, diagnostics.tool_calls, diagnostics.cached_calls) == (3, 1, 1, 0)
    assert diagnostics.rejected_actions == {}
    assert diagnostics.max_prompt_bytes == max(r["input_bytes"] for r in stored["model_requests"])
    assert diagnostics.finish_reasons == ("unreported", "unreported", "unreported")
    lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("mcp_checkpoint ")]
    assert len(lines) == 1
    payload = json.loads(lines[0].removeprefix("mcp_checkpoint "))
    assert (payload["state"], payload["turns"], payload["candidate_revision"]) == ("complete", 3, root.revision + 1)
    assert "test-token" not in lines[0]
    assert "test-provider-key" not in lines[0]


async def test_rejections_are_counted_by_category(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    mcp_responses(httpx_mock, stored)
    httpx_mock.add_callback(
        lambda _request: httpx.Response(200, json={"choices": [{"message": {"content": "not json"}}]}),
        method="POST",
        url=AI_URL,
        is_reusable=True,
    )
    await service._poll(root)  # noqa: SLF001
    diagnostics = artifacts[0].mcp.diagnostics
    assert diagnostics.rejected_actions == {"invalid_json": 8}
    assert diagnostics.final_state == "invalid_response"


class FakeClock:
    """Monotonic stand-in shared by the worker and the agent; tests advance it explicitly."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


async def test_deadline_stops_with_retained_evidence_and_publishes(monkeypatch, httpx_mock):
    service, root, collection, artifacts, stored = mcp_runtime(monkeypatch)
    mcp_responses(httpx_mock, stored)
    clock = FakeClock()
    monkeypatch.setattr(worker, "monotonic", clock)
    monkeypatch.setattr(mcp_impact_agent, "monotonic", clock)

    def respond(request):
        context = read_context(request)
        if context["observations"]:
            clock.now += 200  # The worker budget is spent while the model reasons.
            return ai_response({"action": "describe", "tools": ["get_mist_stats"]})
        return investigator(request)

    httpx_mock.add_callback(respond, method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    mcp = artifacts[0].mcp
    assert mcp.state == "deadline_exceeded"
    assert [e.state for e in mcp.evidence] == ["complete"]
    assert len(mcp.request_ids) == 3
    assert mcp.diagnostics.final_state == "deadline_exceeded"
    publication = collection.update_one.await_args_list[-1].args[1]["$set"]
    assert publication["report_id"] == artifacts[0].id


async def test_safety_timeout_publishes_unavailable_checkpoint(monkeypatch):
    service, root, _, artifacts, _ = mcp_runtime(monkeypatch)

    async def stall(*_args, **_kwargs):
        await asyncio.sleep(5)

    monkeypatch.setattr(worker.McpImpactAgent, "run_mcp", stall)
    monkeypatch.setattr(worker, "MCP_SAFETY_TIMEOUT_SECONDS", 0.01)
    await service._poll(root)  # noqa: SLF001
    assert len(artifacts) == 1
    assert artifacts[0].mcp.state == "unavailable"
    assert "safety timeout" in artifacts[0].mcp.reason


SYSTEM = "system prompt"
bounded_context = mcp_impact_agent.McpImpactAgent._bounded_context  # noqa: SLF001


def prompt_data(*observations, attributes=None, previous=None):
    return {
        "configuration_changes": {
            "changes": [
                {
                    "attributes": attributes
                    or [{"stp_config": {"before": {"enabled": True}, "after": {"enabled": False}}}]
                }
            ],
            "gaps": [],
        },
        "configured_devices": {
            "state": "available",
            "groups": [
                {
                    "site_id": SITE,
                    "device_type": "ap",
                    "outcome": "configured",
                    "correlation": "audit_id",
                    "device_macs": [f"{n:012x}" for n in range(40)],
                }
            ],
        },
        "deterministic_context": {
            "id": str(uuid4()),
            "tool": "guardian_deterministic",
            "data": {"assessment": {"impact": "info"}, "evidence": ["d" * 2000]},
        },
        "previous_checkpoint": previous,
        "observations": list(observations),
    }


def observation(size, identity=None):
    return {
        "id": identity or str(uuid4()),
        "tool": "search_mist_data",
        "state": "complete",
        "data": {"results": ["r" * size]},
    }


def encoded_size(data):
    return len((SYSTEM + json.dumps(data, separators=(",", ":"), sort_keys=True)).encode())


def test_prompt_that_fits_is_unchanged():
    data = prompt_data(observation(100))
    result = bounded_context(data, SYSTEM, encoded_size(data))
    assert json.loads(result.body) == data
    assert (result.steps, result.hidden_observations) == (0, 0)


def test_trimming_rechecks_after_each_step_and_keeps_later_observations():
    data = prompt_data(observation(8000), observation(8000), observation(8000))
    result = bounded_context(data, SYSTEM, encoded_size(data) - 7000)
    context = json.loads(result.body)
    assert context["configured_devices"]["groups"][0]["device_count"] == 40
    assert context["deterministic_context"]["id"] == data["deterministic_context"]["id"]
    assert context["deterministic_context"]["data"]["assessment"] == {"impact": "info"}
    hidden = [row["data"] == mcp_impact_agent.HIDDEN_PAYLOAD for row in context["observations"]]
    assert hidden == [True, False, False]
    assert result.hidden_observations == 1
    assert context["configuration_changes"] == data["configuration_changes"]


def test_evidence_cited_by_previous_report_is_never_hidden():
    cited = observation(8000)
    previous = {"source_revision": 1, "state": "complete", "reason": "", "evidence": [cited, observation(8000)]}
    data = prompt_data(observation(8000), previous=previous)
    result = bounded_context(data, SYSTEM, encoded_size(data) - 7000, frozenset({cited["id"]}))
    context = json.loads(result.body)
    assert context["previous_checkpoint"]["evidence"][0]["data"] == cited["data"]
    assert context["previous_checkpoint"]["evidence"][1]["data"] == mcp_impact_agent.HIDDEN_PAYLOAD
    assert context["observations"][0]["data"] == data["observations"][0]["data"]


def test_long_changed_values_are_shortened_individually_as_last_resort():
    attributes = [{"port_config": {"before": {"ge-0/0/1": "v" * 5000}, "after": {"enabled": True}}}]
    newest = observation(3000)
    data = prompt_data(newest, attributes=attributes)
    result = bounded_context(data, SYSTEM, encoded_size(data) - 6000)
    context = json.loads(result.body)
    change = context["configuration_changes"]["changes"][0]["attributes"][0]["port_config"]
    assert change["after"] == {"enabled": True}
    assert change["before"].endswith("…[shortened]")
    assert len(change["before"]) <= 200 + len("…[shortened]")
    assert context["observations"][0]["data"] == newest["data"]
    assert bounded_context(data, SYSTEM, 1000) is None


async def test_mcp_prompts_use_their_own_input_bound(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    root.model_input_bytes_limit = MCP_MAX_INPUT_BYTES_TOTAL
    rows = [
        {
            "org_id": MIST_ORG,
            "site_id": SITE,
            "mac": MAC,
            "type": "SW_PORT_DOWN",
            "timestamp": int(LATER.timestamp()),
            "text": "e" * 200,
        }
        for _ in range(25)
    ]
    mcp_responses(httpx_mock, stored, result={"results": rows, "total": 25})
    contexts = []

    def respond(request):
        context = read_context(request)
        contexts.append(context)
        if len(context["observations"]) == 2:
            return ai_response(report(context))
        if not context["observations"] and not context["described_tools"]:
            return ai_response({"action": "describe", "tools": ["search_mist_data"]})
        return ai_response(
            {
                "action": "tool",
                "tool": "search_mist_data",
                "arguments": {
                    "search_type": "alarms" if context["observations"] else "device_events",
                    "site_id": SITE,
                },
                "purpose": "Collect operational events for the changed site.",
            }
        )

    httpx_mock.add_callback(respond, method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    assert artifacts[0].mcp.state == "complete", artifacts[0].mcp.reason
    assert all("results" in row["data"] for row in contexts[-1]["observations"])
    assert max(r["input_bytes"] for r in stored["model_requests"]) > 24_000
    assert artifacts[0].mcp.diagnostics.observations_hidden_in_prompt == 0


def test_compact_schema_keeps_types_enums_defaults_and_a_property_named_description():
    schema = {
        "type": "object",
        "title": "Tool",
        "description": "Long prose.",
        "properties": {
            "description": {
                "type": "string",
                "description": "A property literally named description.",
                "examples": ["x"],
            },
            "kind": {"type": "string", "enum": ["a", "b"], "default": "a", "title": "Kind"},
        },
        "required": ["kind"],
    }
    assert compact_schema(schema) == {
        "type": "object",
        "properties": {
            "description": {"type": "string"},
            "kind": {"type": "string", "enum": ["a", "b"], "default": "a"},
        },
        "required": ["kind"],
    }


def test_all_real_compact_schemas_fit_every_prompt():
    tools = catalog(CATALOG)
    compact = {t.name: compact_schema(t.input_schema) for t in tools}
    assert len(json.dumps(compact).encode()) < 8000  # measured at 5.6 KB with 300-char summaries
    assert "device_events" in compact["search_mist_data"]["properties"]["search_type"]["enum"]
    assert compact["get_mist_insights"]["required"] == ["insight_type"]


async def test_tool_can_be_called_without_describe(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    calls = mcp_responses(httpx_mock, stored)

    def respond(request):
        context = read_context(request)
        assert "known_tool_names" not in context
        assert {t["name"] for t in context["tools"]} == {t.name for t in catalog(CATALOG)}
        assert all(len(t["description"]) <= 300 for t in context["tools"])
        if context["observations"]:
            return ai_response(report(context))
        return ai_response(
            {
                "action": "tool",
                "tool": "search_mist_data",
                "arguments": {"search_type": "device_events", "site_id": SITE, "filters": {"mac": MAC}},
                "purpose": "Check for operational transitions after the change.",
            }
        )

    httpx_mock.add_callback(respond, method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    assert artifacts[0].mcp.state == "complete", artifacts[0].mcp.reason
    assert len(artifacts[0].mcp.request_ids) == 2
    assert len([c for c in calls if c["method"] == "tools/call"]) == 1


async def test_undiscovered_tool_is_rejected_with_its_category(monkeypatch, httpx_mock):
    service, root, _, _, stored = mcp_runtime(monkeypatch)
    mcp_responses(httpx_mock, stored, tools=[t for t in CATALOG if t["name"] != "get_mist_insights"])
    feedback = []

    def respond(request):
        context = read_context(request)
        feedback.append(context["feedback"])
        if len(feedback) == 1:
            return ai_response(
                {
                    "action": "tool",
                    "tool": "get_mist_insights",
                    "arguments": {"insight_type": "sle"},
                    "purpose": "Compare SLE before and after.",
                }
            )
        return investigator(request)

    httpx_mock.add_callback(respond, method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    first = ModelRequestRecord.model_validate(stored["model_requests"][0])
    assert first.response_error == ModelResponseError.TOOL_NOT_DISCOVERED
    assert feedback[1] == "Action rejected (tool_not_discovered): Only discovered read tools are available."


def test_scope_sites_include_configured_device_and_deployment_sites():
    deployed = "44444444-4444-4444-8444-444444444444"
    configured = "55555555-5555-4555-8555-555555555555"
    sites = mcp_impact_agent.McpImpactAgent._scope_sites(  # noqa: SLF001
        {"sites": [SITE], "devices": [{"site_id": configured, "device_mac": MAC}]},
        {"devices": [{"site_id": deployed, "device_mac": MAC}, {"site_id": "not-a-uuid"}]},
    )
    assert sites == {SITE, deployed, configured}


def agent_conclusion(summary="Agent summary.", evidence=()):
    return McpConclusion(
        summary=summary,
        scope="Changed switch.",
        impact="info",
        confidence="low",
        coverage="partial",
        evidence=evidence,
        gaps=("A coincident fault has not been excluded.",),
    )


@pytest.mark.parametrize(
    ("minutes", "last", "due"),
    [
        (1, None, False),
        (9, None, False),
        (10, None, True),
        (20, 10, False),
        (29, 10, False),
        (30, 10, True),
        (50, 30, False),
        (60, 30, True),
        (60, 60, False),
        (35, None, True),
        (60, 35, True),
    ],
)
def test_agent_runs_once_per_schedule_band(minutes, last, due):
    last_run = NOW + timedelta(minutes=last) if last is not None else None
    assert agent_due(NOW, NOW + timedelta(minutes=minutes), last_run) is due


def test_last_agent_run_reads_legacy_revisions():
    assert last_agent_run(McpCheckpoint(state="complete"), LATER) == LATER
    assert last_agent_run(McpCheckpoint(state="not_scheduled"), LATER) is None
    assert last_agent_run(McpCheckpoint(state="provider_error", agent_as_of=NOW), LATER) == NOW
    assert last_agent_run(None, LATER) is None


def test_prior_conclusion_keeps_only_cited_evidence_and_passes_carried_forward():
    cited, other = (
        McpEvidence(
            id=uuid4(),
            tool="get_mist_stats",
            arguments={},
            data={"v": n},
            state="complete",
            captured_at=LATER,
            schema_hash="t",
        )
        for n in range(2)
    )
    complete = McpCheckpoint(
        state="complete", conclusion=agent_conclusion(evidence=(cited.id,)), evidence=(cited, other)
    )
    carried = prior_conclusion(complete, 4)
    assert (carried.source_revision, carried.evidence) == (4, (cited,))
    assert prior_conclusion(McpCheckpoint(state="not_scheduled", carried=carried), 5) == carried
    assert prior_conclusion(McpCheckpoint(state="budget_exhausted"), 5) is None


def test_prior_conclusion_is_not_carried_without_every_cited_evidence_row():
    missing = McpCheckpoint(state="complete", conclusion=agent_conclusion(evidence=(uuid4(),)))
    assert prior_conclusion(missing, 4) is None


async def test_agent_runs_at_ten_thirty_and_sixty_minutes_and_carries_conclusion(monkeypatch):
    service, root, _, artifacts, _ = mcp_runtime(monkeypatch)
    runs = []

    async def fake_run(_self, _root, **kwargs):
        runs.append(kwargs["as_of"])
        return McpCheckpoint(state="complete", conclusion=agent_conclusion(f"Run {len(runs)}."))

    monkeypatch.setattr(worker.McpImpactAgent, "run_mcp", fake_run)
    for minutes in (1, 10, 20, 30, 40, 50, 60):
        now = NOW + timedelta(minutes=minutes)
        monkeypatch.setattr(worker, "utc_now", lambda now=now: now)
        await service._poll(root)  # noqa: SLF001
        root.report_id, root.revision = artifacts[-1].id, artifacts[-1].revision
    assert runs == [NOW + timedelta(minutes=m) for m in (10, 30, 60)]
    assert [a.mcp.state for a in artifacts] == [
        "not_scheduled",
        "complete",
        "not_scheduled",
        "complete",
        "not_scheduled",
        "not_scheduled",
        "complete",
    ]
    assert artifacts[0].mcp.carried is None
    assert artifacts[2].mcp.carried.source_revision == artifacts[1].revision
    assert artifacts[5].mcp.carried.conclusion.summary == "Run 2."
    assert artifacts[5].mcp.agent_as_of == NOW + timedelta(minutes=30)
    assert "Carried forward from revision" in artifacts[5].report.sections.summary.explanation
    assert artifacts[5].assessment.policy_version == "mcp-agent.v1"


async def poll_at(monkeypatch, service, root, artifacts, minutes):
    now = NOW + timedelta(minutes=minutes)
    monkeypatch.setattr(worker, "utc_now", lambda: now)
    await service._poll(root)  # noqa: SLF001
    root.report_id, root.revision = artifacts[-1].id, artifacts[-1].revision


def counting_agent(monkeypatch, runs, checkpoint=None):
    async def fake_run(_self, _root, **kwargs):
        runs.append(kwargs["as_of"])
        return checkpoint or McpCheckpoint(state="complete", conclusion=agent_conclusion(f"Run {len(runs)}."))

    monkeypatch.setattr(worker.McpImpactAgent, "run_mcp", fake_run)


async def test_late_and_skipped_checkpoints_still_run_each_band_once(monkeypatch):
    service, root, _, artifacts, _ = mcp_runtime(monkeypatch)
    runs = []
    counting_agent(monkeypatch, runs)
    for minutes in (1, 12, 25, 41, 52, 61):
        await poll_at(monkeypatch, service, root, artifacts, minutes)
    # The +61 checkpoint evaluates at the one-hour expiry, which is the third band.
    assert runs == [NOW + timedelta(minutes=m) for m in (12, 41, 60)]
    assert [a.mcp.state for a in artifacts] == [
        "not_scheduled",
        "complete",
        "not_scheduled",
        "complete",
        "not_scheduled",
        "complete",
    ]


async def test_unpublished_agent_attempt_spends_its_band(monkeypatch):
    service, root, _, artifacts, _ = mcp_runtime(monkeypatch)
    runs = []
    counting_agent(monkeypatch, runs)
    attempt = NOW + timedelta(minutes=10, seconds=5)
    # A worker reserved MCP discovery for this candidate, then lost its lease before publishing.
    root.mcp_dispatches = [
        McpDispatch(
            id=uuid4(),
            generation=root.generation - 1,
            candidate_revision=root.revision + 1,
            tool="tools/list",
            arguments_hash="h",
            reserved_at=attempt,
        )
    ]
    for minutes in (15, 20, 30):
        await poll_at(monkeypatch, service, root, artifacts, minutes)
    assert runs == [NOW + timedelta(minutes=30)]
    assert [a.mcp.state for a in artifacts] == ["not_scheduled", "not_scheduled", "complete"]
    assert artifacts[0].mcp.agent_as_of == attempt
    assert artifacts[1].mcp.agent_as_of == attempt


async def test_failed_agent_run_still_spends_its_band(monkeypatch):
    service, root, _, artifacts, _ = mcp_runtime(monkeypatch)
    runs = []
    counting_agent(monkeypatch, runs, McpCheckpoint(state="provider_error", reason="AI provider request failed."))
    for minutes in (10, 20):
        await poll_at(monkeypatch, service, root, artifacts, minutes)
    assert runs == [NOW + timedelta(minutes=10)]
    assert artifacts[0].mcp.agent_as_of == NOW + timedelta(minutes=10)
    assert (artifacts[1].mcp.state, artifacts[1].mcp.carried) == ("not_scheduled", None)
    assert "first runs" not in artifacts[1].mcp.reason


async def test_revision_without_agent_as_of_counts_as_a_run_at_its_evaluation(monkeypatch):
    service, root, _, artifacts, _ = mcp_runtime(monkeypatch)
    runs = []
    counting_agent(monkeypatch, runs)
    await poll_at(monkeypatch, service, root, artifacts, 10)
    # Simulate a revision stored before scheduling existed.
    artifacts[0].mcp = artifacts[0].mcp.model_copy(update={"agent_as_of": None})
    await poll_at(monkeypatch, service, root, artifacts, 20)
    assert runs == [NOW + timedelta(minutes=10)]
    assert artifacts[1].mcp.state == "not_scheduled"
    assert artifacts[1].mcp.agent_as_of == artifacts[0].assessment.evaluated_at
    assert artifacts[1].mcp.carried.source_revision == artifacts[0].revision


async def test_not_scheduled_checkpoint_spends_no_model_or_mcp_budget(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    await poll_at(monkeypatch, service, root, artifacts, 1)
    assert artifacts[0].mcp.state == "not_scheduled"
    assert artifacts[0].mcp.diagnostics is None
    assert (stored["model_calls_used"], stored["calls_used"], stored["mcp_dispatches"]) == (0, 0, [])
    assert not httpx_mock.get_requests()


@pytest.mark.parametrize("mode", ["legacy", "shadow"])
async def test_non_agent_modes_publish_no_mcp_checkpoint(monkeypatch, mode):
    service, root, _, artifacts, _ = mcp_runtime(monkeypatch)
    settings = SimpleNamespace(impact_engine_mode=mode, mist_mcp_url=MCP_URL)
    monkeypatch.setattr(worker, "get_settings", lambda: settings)
    runs = []
    counting_agent(monkeypatch, runs)
    for minutes in (1, 10, 20):
        await poll_at(monkeypatch, service, root, artifacts, minutes)
    assert runs == []
    assert all(a.mcp is None for a in artifacts)


def test_next_agent_run_sees_carried_conclusion_and_its_evidence():
    evidence = McpEvidence(
        id=uuid4(),
        tool="get_mist_stats",
        arguments={"site_id": SITE},
        data={"v": 1},
        state="complete",
        captured_at=LATER,
        schema_hash="t",
    )
    carried = prior_conclusion(
        McpCheckpoint(state="complete", conclusion=agent_conclusion(evidence=(evidence.id,)), evidence=(evidence,)),
        4,
    )
    previous = InvestigationRevision.model_construct(
        revision=5, mcp=McpCheckpoint(state="not_scheduled", carried=carried)
    )
    agent = mcp_impact_agent.McpImpactAgent
    protected = agent._protected_ids(prior_conclusion(previous.mcp, previous.revision))  # noqa: SLF001
    assert protected == frozenset({str(evidence.id)})
    summary = agent._checkpoint_summary(previous, protected, carried)  # noqa: SLF001
    assert (summary["source_revision"], summary["state"], summary["conclusion_source_revision"]) == (
        5,
        "not_scheduled",
        4,
    )
    assert [row["id"] for row in summary["evidence"]] == [str(evidence.id)]


def test_tool_action_accepts_single_or_batched_form_only():
    single = {"action": "tool", "tool": "search_mist_data", "arguments": {}, "purpose": "One call."}
    call = {"tool": "search_mist_data", "arguments": {}, "purpose": "Batched call."}
    assert len(McpToolAction.model_validate(single).requested_calls()) == 1
    assert len(McpToolAction.model_validate({"action": "tool", "calls": [call] * 3}).requested_calls()) == 3
    for invalid in (
        {"action": "tool", "calls": [call] * 4},
        {**single, "calls": [call]},
        {"action": "tool", "tool": "search_mist_data"},
        {"action": "tool"},
    ):
        with pytest.raises(ValidationError):
            McpToolAction.model_validate(invalid)


async def test_batched_calls_execute_valid_calls_and_reject_only_the_invalid_one(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    calls = mcp_responses(httpx_mock, stored)
    contexts = []

    def respond(request):
        context = read_context(request)
        contexts.append(context)
        if context["observations"]:
            return ai_response(report(context))
        return ai_response(
            {
                "action": "tool",
                "calls": [
                    {
                        "tool": "search_mist_data",
                        "arguments": {"search_type": "device_events", "site_id": SITE},
                        "purpose": "Events for the changed site.",
                    },
                    {
                        "tool": "search_mist_data",
                        "arguments": {"search_type": "device_events", "site_id": str(uuid4())},
                        "purpose": "An undiscovered site.",
                    },
                    {
                        "tool": "search_mist_data",
                        "arguments": {"search_type": "alarms", "site_id": SITE},
                        "purpose": "Alarms for the changed site.",
                    },
                ],
            }
        )

    httpx_mock.add_callback(respond, method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    assert len([c for c in calls if c["method"] == "tools/call"]) == 2
    assert len(stored["mcp_dispatches"]) == 3  # discovery plus two calls
    assert len(artifacts[0].mcp.evidence) == 2
    assert contexts[1]["feedback"].startswith("Call 2 rejected (argument_out_of_scope): ")
    assert ModelRequestRecord.model_validate(stored["model_requests"][0]).state == "complete"
    assert artifacts[0].mcp.diagnostics.rejected_actions == {"argument_out_of_scope": 1}
    assert artifacts[0].mcp.state == "complete", artifacts[0].mcp.reason


async def test_batched_calls_beyond_evidence_slots_are_rejected(monkeypatch, httpx_mock):
    service, root, _, _, stored = mcp_runtime(monkeypatch)
    calls = mcp_responses(httpx_mock, stored)
    monkeypatch.setattr(mcp_impact_agent, "MAX_MCP_CHECKPOINT_CALLS", 2)
    contexts = []

    def respond(request):
        context = read_context(request)
        contexts.append(context)
        if context["observations"]:
            return ai_response(report(context))
        return ai_response(
            {
                "action": "tool",
                "calls": [
                    {
                        "tool": "search_mist_data",
                        "arguments": {"search_type": kind, "site_id": SITE},
                        "purpose": f"Query {kind}.",
                    }
                    for kind in ("device_events", "alarms", "client_sessions")
                ],
            }
        )

    httpx_mock.add_callback(respond, method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    assert len([c for c in calls if c["method"] == "tools/call"]) == 2
    assert contexts[1]["feedback"].startswith("Call 3 rejected (tool_call_limit): ")


def batch_call(kind="device_events", site=SITE):
    return {
        "tool": "search_mist_data",
        "arguments": {"search_type": kind, "site_id": site},
        "purpose": f"Query {kind}.",
    }


async def test_duplicate_call_in_one_batch_is_cached_and_uses_no_evidence_slot(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    calls = mcp_responses(httpx_mock, stored)
    monkeypatch.setattr(mcp_impact_agent, "MAX_MCP_CHECKPOINT_CALLS", 1)
    contexts = []

    def respond(request):
        context = read_context(request)
        contexts.append(context)
        if context["observations"]:
            return ai_response(report(context))
        return ai_response({"action": "tool", "calls": [batch_call(), batch_call(), batch_call(site=str(uuid4()))]})

    httpx_mock.add_callback(respond, method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    mcp = artifacts[0].mcp
    assert len([c for c in calls if c["method"] == "tools/call"]) == 1
    assert len(stored["mcp_dispatches"]) == 2  # discovery plus one call
    assert len(mcp.evidence) == 1
    feedback = contexts[1]["feedback"]
    assert feedback.startswith("Call 3 rejected (argument_out_of_scope): ")
    assert f"Call 2: cached evidence ID {mcp.evidence[0].id}; repeated request issued no MCP call." in feedback
    diagnostics = mcp.diagnostics
    assert (diagnostics.tool_calls, diagnostics.cached_calls) == (1, 1)
    assert diagnostics.rejected_actions == {"argument_out_of_scope": 1}
    assert mcp.state == "complete", mcp.reason


async def test_batch_with_only_invalid_calls_is_one_rejected_action(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    calls = mcp_responses(httpx_mock, stored)
    contexts = []

    def respond(request):
        context = read_context(request)
        contexts.append(context)
        if len(contexts) == 1:
            foreign = [batch_call(site=str(uuid4())), batch_call("alarms", str(uuid4()))]
            return ai_response({"action": "tool", "calls": foreign})
        if context["observations"]:
            return ai_response(report(context))
        return ai_response({"action": "tool", **batch_call()})

    httpx_mock.add_callback(respond, method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    first = ModelRequestRecord.model_validate(stored["model_requests"][0])
    assert (first.state, first.response_error) == ("invalid_response", ModelResponseError.ARGUMENT_OUT_OF_SCOPE)
    assert contexts[1]["feedback"].startswith("Action rejected (argument_out_of_scope): ")
    assert len([c for c in calls if c["method"] == "tools/call"]) == 1
    assert artifacts[0].mcp.diagnostics.rejected_actions == {"argument_out_of_scope": 1}
    assert artifacts[0].mcp.state == "complete", artifacts[0].mcp.reason


async def test_deadline_mid_batch_finishes_the_call_in_flight_and_keeps_its_evidence(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    calls = mcp_responses(httpx_mock, stored)
    clock = FakeClock()
    monkeypatch.setattr(worker, "monotonic", clock)
    monkeypatch.setattr(mcp_impact_agent, "monotonic", clock)
    normalize = mcp_impact_agent.normalize_result_detail

    def slow_normalize(*args, **kwargs):
        clock.now += 200  # The first call of the batch consumes the checkpoint budget.
        return normalize(*args, **kwargs)

    monkeypatch.setattr(mcp_impact_agent, "normalize_result_detail", slow_normalize)
    httpx_mock.add_callback(
        lambda _request: ai_response({"action": "tool", "calls": [batch_call(), batch_call("alarms")]}),
        method="POST",
        url=AI_URL,
        is_reusable=True,
    )
    await service._poll(root)  # noqa: SLF001
    mcp = artifacts[0].mcp
    assert mcp.state == "deadline_exceeded"
    assert len([c for c in calls if c["method"] == "tools/call"]) == 1
    assert [e.state for e in mcp.evidence] == ["complete"]
    assert [d["state"] for d in stored["mcp_dispatches"]] == ["complete", "complete"]
    assert mcp.diagnostics.tool_calls == 1


async def test_dispatch_denial_mid_batch_keeps_earlier_evidence(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    calls = mcp_responses(httpx_mock, stored)
    normal = worker.Organization.get

    async def organization(identity):
        result = await normal(identity)
        if any(c["method"] == "tools/call" for c in calls):
            return SimpleNamespace(status=result.status, encrypted_service_token="rotated")
        return result

    monkeypatch.setattr(worker.Organization, "get", AsyncMock(side_effect=organization))
    httpx_mock.add_callback(
        lambda _request: ai_response({"action": "tool", "calls": [batch_call(), batch_call("alarms")]}),
        method="POST",
        url=AI_URL,
        is_reusable=True,
    )
    await service._poll(root)  # noqa: SLF001
    mcp = artifacts[0].mcp
    assert mcp.state == "dispatch_denied"
    assert "credential changed" in mcp.reason
    assert len([c for c in calls if c["method"] == "tools/call"]) == 1
    assert [e.state for e in mcp.evidence] == ["complete"]
    assert [d["state"] for d in stored["mcp_dispatches"]] == ["complete", "complete"]


async def test_prompt_leads_with_procedure_explicit_windows_and_playbooks(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    mcp_responses(httpx_mock, stored)
    monkeypatch.setattr(
        worker,
        "mcp_playbooks",
        lambda plan: skills.mcp_playbooks(
            plan.model_copy(update={"mcp_context": {"changes": [{"object_type": "wlans", "attributes": []}]}})
        ),
    )
    seen = []

    def respond(request):
        seen.append((json.loads(request.content)["messages"][0]["content"], read_context(request)))
        return investigator(request)

    httpx_mock.add_callback(respond, method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    system, context = seen[0]
    assert system.startswith("You investigate whether one recorded Mist configuration change")
    assert system.index("Procedure:") < system.index("Safety:")
    # At +10 min both windows span exactly ten minutes around the change.
    assert context["before_window"] == {
        "start_time": str(int((NOW - timedelta(minutes=10)).timestamp())),
        "end_time": str(int(NOW.timestamp())),
    }
    assert context["after_window"] == {"start_time": str(int(NOW.timestamp())), "end_time": str(int(LATER.timestamp()))}
    assert "before_window and after_window have equal duration" in system
    assert "compare rates per window duration" in system
    assert [p["id"] for p in context["playbooks"]] == ["wlan-lifecycle.v1"]
    assert context["playbooks"][0]["instructions"].startswith("Investigate removal/disable")
    assert {r["prompt_version"] for r in stored["model_requests"]} == {"impact-mcp.v2"}
    assert artifacts[0].mcp.state == "complete", artifacts[0].mcp.reason


@pytest.mark.parametrize(("minutes", "before_minutes"), [(10, 10), (30, 30), (60, 60), (90, 60)])
def test_before_window_matches_after_window_duration_capped_by_scope_start(minutes, before_minutes):
    as_of = NOW + timedelta(minutes=minutes)
    scope = McpScope(org_id=UUID(MIST_ORG), changed_at=NOW, as_of=as_of, sites=[SITE])
    windows = mcp_impact_agent.McpImpactAgent._windows(scope, NOW, as_of)  # noqa: SLF001
    before, after = windows["before_window"], windows["after_window"]
    assert before == {
        "start_time": str(int((NOW - timedelta(minutes=before_minutes)).timestamp())),
        "end_time": str(int(NOW.timestamp())),
    }
    assert after == {"start_time": str(int(NOW.timestamp())), "end_time": str(int(as_of.timestamp()))}
    assert int(before["start_time"]) >= int(scope.start.timestamp())
    assert int(before["end_time"]) - int(before["start_time"]) <= 3600
    # A model copying either window verbatim is accepted by the scope.
    tool = next(t for t in catalog(CATALOG) if t.name == "search_mist_data")
    for window in (before, after):
        args = scope.arguments(tool, {"search_type": "device_events", "site_id": SITE, **window})
        assert (args["start_time"], args["end_time"]) == (window["start_time"], window["end_time"])


def test_system_prompt_describes_batched_calls_digests_optional_describe_and_feedback():
    system = mcp_impact_agent._SYSTEM  # noqa: SLF001
    assert system.index("Procedure:") < system.index("Actions:") < system.index("Safety:")
    for phrase in (
        "before_window",
        "after_window",
        "calls:[{tool,arguments,purpose}]",
        "tool_call_limit",
        "describe is optional",
        "change_buckets",
        "before_change/after_change",
        "never none",
        "error_detail",
        "Action rejected (category): detail",
        "previous_report",
        "rule-derived",
    ):
        assert phrase in system, phrase
    # Safety stays a short list rather than the bulk of the prompt.
    assert len(system[system.index("Safety:") :]) * 4 < len(system)


def test_trimming_never_removes_explicit_windows_or_playbooks():
    windows = {
        "before_window": {"start_time": "1757670600", "end_time": "1757671200"},
        "after_window": {"start_time": "1757671200", "end_time": "1757671800"},
        "playbooks": [{"id": "wlan-lifecycle.v1", "instructions": "Investigate removal/disable only."}],
    }
    attributes = [{"port_config": {"before": {"ge-0/0/1": "v" * 5000}, "after": {"enabled": True}}}]
    data = {**prompt_data(observation(8000), observation(3000), attributes=attributes), **windows}
    result = bounded_context(data, SYSTEM, encoded_size(data) - 12_000)
    assert result is not None
    assert result.steps == 4  # Every degradation step ran, including the last-resort value shortening.
    context = json.loads(result.body)
    assert {key: context[key] for key in windows} == windows


@pytest.mark.parametrize("version", ["impact-mcp.v1", "impact-mcp.v2"])
async def test_stored_mcp_actions_stay_readable_for_every_mcp_prompt_version(monkeypatch, httpx_mock, version):
    service, root, collection, _, stored = mcp_runtime(monkeypatch)
    mcp_responses(httpx_mock, stored)
    httpx_mock.add_callback(investigator, method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    request_id = ModelRequestRecord.model_validate(stored["model_requests"][-1]).id
    raw = {**stored["model_requests"][-1], "prompt_version": version}

    async def selected(_query, *, projection):
        assert "model_requests" in projection
        return {"_id": root.id, "model_requests": [raw]}

    collection.find_one.side_effect = selected
    monkeypatch.setattr(
        ModelRequestArtifact,
        "find_one",
        AsyncMock(side_effect=lambda query: next((a for a in stored["model_artifacts"] if a.id == query["_id"]), None)),
    )
    result = await model_request_reads.model_request_details(root.organization_id, PydanticObjectId(), request_id)
    assert result.action_state == "available"
    assert result.action.action == "report"


@pytest.mark.parametrize(
    ("version", "counted"),
    [("impact-mcp.v1", True), ("impact-mcp.v2", True), ("impact-investigator.v8", False)],
)
def test_unpublished_mcp_model_request_of_any_mcp_prompt_version_spends_its_band(monkeypatch, version, counted):
    _, root, _, _, _ = mcp_runtime(monkeypatch)
    attempt = NOW + timedelta(minutes=10, seconds=5)
    root.mcp_dispatches = []
    root.model_requests = [
        ModelRequestRecord.model_validate(
            {
                "id": str(uuid4()),
                "generation": root.generation,
                "candidate_revision": root.revision + 1,
                "prompt_version": version,
                "reserved_at": attempt,
                "input_hash": "0" * 64,
                "model": "model",
                "input_bytes": 1,
                "output_token_limit": 1,
            }
        )
    ]
    expected = attempt if counted else None
    assert worker.ImpactInvestigationService._unpublished_agent_attempt(root) == expected  # noqa: SLF001


async def test_truncated_completion_is_rejected_with_shorter_action_feedback(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    configuration = AiRuntimeConfiguration(
        "https://ai.example.test/v1", "test-model", "test-provider-key", 8000, automatic_summaries=False
    )
    monkeypatch.setattr(
        impact_agent.ApplicationConfigurationService, "ai_runtime", AsyncMock(return_value=configuration)
    )
    mcp_responses(httpx_mock, stored)
    contexts = []

    def respond(request):
        contexts.append(read_context(request))
        assert json.loads(request.content)["max_tokens"] == MCP_MAX_OUTPUT_TOKENS
        if len(contexts) == 1:
            return httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {"content": '{"action":"report","report":{"summary":"cut'},
                            "finish_reason": "length",
                        }
                    ]
                },
            )
        return investigator(request)

    httpx_mock.add_callback(respond, method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    first = ModelRequestRecord.model_validate(stored["model_requests"][0])
    assert first.output_token_limit == MCP_MAX_OUTPUT_TOKENS
    assert first.response_error == ModelResponseError.TRUNCATED
    assert contexts[1]["feedback"].startswith("Action rejected (truncated): Response stopped at the output token limit")
    assert artifacts[0].mcp.diagnostics.finish_reasons[0] == "length"
    assert artifacts[0].mcp.diagnostics.rejected_actions == {"truncated": 1}
    assert artifacts[0].mcp.state == "complete", artifacts[0].mcp.reason


def test_request_record_accepts_the_mcp_output_token_bound():
    record = ModelRequestRecord(
        id=uuid4(),
        generation=1,
        candidate_revision=1,
        reserved_at=LATER,
        prompt_version="impact-mcp.v2",
        input_hash="0" * 64,
        model="test-model",
        input_bytes=1,
        output_token_limit=MCP_MAX_OUTPUT_TOKENS,
    )
    assert record.output_token_limit == MCP_MAX_OUTPUT_TOKENS
    with pytest.raises(ValidationError):
        ModelRequestRecord.model_validate({**record.model_dump(), "output_token_limit": MCP_MAX_OUTPUT_TOKENS + 1})
