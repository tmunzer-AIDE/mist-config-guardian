"""Production MCP loop with real advertised tool schemas, independent of rule coverage."""

import asyncio
import json
import logging
import subprocess
import sys
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

from mist_config_guardian_backend.impact.agent import ModelRequestRecord, ModelResponseError
from mist_config_guardian_backend.impact.mcp_context import configuration_context
from mist_config_guardian_backend.impact.mcp_contracts import (
    McpConclusion,
    McpDispatch,
    McpEvidence,
    McpReportAction,
    McpView,
)
from mist_config_guardian_backend.impact.mcp_scope import McpScope, McpScopeError, catalog, normalize_result
from mist_config_guardian_backend.impact.mcp_views import selected_rows
from mist_config_guardian_backend.integrations.mist_mcp import MistMcpClient, MistMcpError
from mist_config_guardian_backend.models.investigation import InvestigationRevision, ModelRequestArtifact
from mist_config_guardian_backend.services import impact_investigations as worker
from mist_config_guardian_backend.services import mcp_dispatch, mcp_impact_agent
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


def mcp_responses(httpx_mock, stored, *, result=None, error=False):
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
            payload = {"tools": CATALOG}
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
            assert "search_mist_data" in context["known_tool_names"]
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
