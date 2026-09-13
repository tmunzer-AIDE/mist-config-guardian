"""Agent-selected checks, durable model spending and fail-closed action execution."""

import asyncio
import json
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from beanie import PydanticObjectId
from bson import BSON
from bson.codec_options import CodecOptions
from pymongo.errors import ConnectionFailure

from mist_config_guardian_backend.impact.agent import MAX_INPUT_BYTES_TOTAL, MAX_MODEL_CALLS, ModelRequestRecord
from mist_config_guardian_backend.services import impact_agent as agent_module
from mist_config_guardian_backend.services import impact_investigations as runtime
from mist_config_guardian_backend.services import investigation_reads
from mist_config_guardian_backend.services.application_configuration import AiRuntimeConfiguration
from test_impact_dispatch_journal import empty_response, journal_runtime
from test_wlan_investigation import LATER, ORG

AI_URL = "https://ai.example.test/v1/chat/completions"


def agent_runtime(monkeypatch):
    service, root, collection, artifacts, stored = journal_runtime(monkeypatch)
    stored.update(model_requests=[], model_calls_used=0, model_input_bytes_reserved=0, model_artifacts=[])
    monkeypatch.setattr(agent_module.ModelRequestArtifact, "get_pymongo_collection", lambda *_: collection)

    async def insert(artifact, **_kwargs):
        stored["model_artifacts"].append(artifact)
        return artifact

    monkeypatch.setattr(agent_module.ModelRequestArtifact, "insert", insert)
    configuration = AiRuntimeConfiguration(
        "https://ai.example.test/v1", "test-model", "test-provider-key", 1500, automatic_summaries=False
    )
    monkeypatch.setattr(
        agent_module.ApplicationConfigurationService, "ai_runtime", AsyncMock(return_value=configuration)
    )
    monkeypatch.setattr(agent_module, "utc_now", lambda: LATER)
    monkeypatch.setattr(runtime, "get_settings", lambda: SimpleNamespace(impact_engine_mode="agent_shadow"))
    normal_update = collection.update_one.side_effect

    async def update(query, mutation):
        encoded_query = BSON(BSON.encode(query)).decode(codec_options=CodecOptions(tz_aware=True))
        encoded = BSON(BSON.encode(mutation)).decode(codec_options=CodecOptions(tz_aware=True))
        assert query["_id"] == root.id
        assert query["organization_id"] == ORG
        if "model_calls_used" in mutation.get("$inc", {}):
            assert query["model_requests.20"] == {"$exists": False}
            limits = query["$expr"]["$and"]
            assert limits[0] == {
                "$lt": [{"$ifNull": ["$model_calls_used", 0]}, min(root.model_calls_limit, MAX_MODEL_CALLS)]
            }
            byte_limit = limits[1]["$lte"][1]
            if (
                query["generation"] != stored["generation"]
                or root.lease_until <= agent_module.utc_now()
                or stored["model_calls_used"] >= limits[0]["$lt"][1]
                or stored["model_input_bytes_reserved"] > byte_limit
                or len(stored["model_requests"]) >= MAX_MODEL_CALLS
            ):
                return SimpleNamespace(matched_count=0)
            for key, value in mutation["$inc"].items():
                stored[key] += value
            stored["model_requests"].append(encoded["$push"]["model_requests"])
            return SimpleNamespace(matched_count=1)
        if "model_requests" in query:
            predicate = encoded_query["model_requests"]["$elemMatch"]
            matches = [
                record for record in stored["model_requests"] if all(record[k] == v for k, v in predicate.items())
            ]
            if not matches:
                return SimpleNamespace(matched_count=0)
            for key, value in encoded["$set"].items():
                matches[0][key.removeprefix("model_requests.$.")] = value
            return SimpleNamespace(matched_count=1)
        return await normal_update(query, mutation)

    collection.update_one.side_effect = update
    return service, root, collection, artifacts, stored


def ai_response(action):
    return httpx.Response(
        200,
        json={
            "choices": [{"message": {"content": json.dumps(action)}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 80},
        },
    )


def read_context(request):
    return json.loads(json.loads(request.content)["messages"][1]["content"])


def collect_all(context):
    return {"action": "collect", "checks": [check["ref"] for check in context["capabilities"]]}


def proposal(context):
    return {
        "action": "report",
        "report": {
            "summary": "No disconnects were found in the returned sample; failed joins remain untested.",
            "hypotheses": [
                {
                    "target_handle": context["changes"][0]["target_handle"],
                    "statement": "The WLAN change may have affected previously connected clients.",
                    "supporting_checks": [],
                    "counterevidence_checks": [row["ref"] for row in context["observations"]],
                    "limitations": ["Session history does not establish failed joins or AP failure."],
                }
            ],
            "open_questions": ["Failed-join evidence requires another capability."],
        },
    }


def investigating_response(request):
    context = read_context(request)
    return ai_response(proposal(context) if context["observations"] else collect_all(context))


def add_mist(httpx_mock):
    httpx_mock.add_callback(empty_response, method="GET", is_reusable=True)


async def test_agent_selects_checks_receives_results_and_publishes_one_audit_proposal(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = agent_runtime(monkeypatch)

    def respond(request):
        assert stored["model_requests"][-1]["state"] == "reserved"
        assert stored["model_calls_used"] == len(stored["model_requests"])
        assert "test-provider-key" not in next(
            a.content_json
            for a in stored["model_artifacts"]
            if a.id == stored["model_requests"][-1]["input_artifact_id"]
        )
        context = read_context(request)
        assert context["changes"][0]["change_kind"] == "removed"
        return investigating_response(request)

    httpx_mock.add_callback(respond, method="POST", url=AI_URL, is_reusable=True)
    add_mist(httpx_mock)
    await service._poll(root)  # noqa: SLF001
    assert [r.method for r in httpx_mock.get_requests()] == ["POST", "GET", "GET", "POST"]
    assert len(artifacts) == 1
    assert artifacts[0].agent.state == "complete"
    assert artifacts[0].agent.memory.source_revision == root.revision + 1
    assert len(artifacts[0].agent.observations) == 2
    assert artifacts[0].assessment.impact == "none"
    assert len(stored["dispatches"]) == 2
    assert stored["model_calls_used"] == 2
    for raw in stored["model_requests"]:
        record = ModelRequestRecord.model_validate(raw)
        assert record.state == "complete"
        assert record.request_tokens == 100
        assert record.model == "test-model"
        assert record.finished_at is not None
        context = next(a.content_json for a in stored["model_artifacts"] if a.id == record.input_artifact_id)
        assert "client_mac" not in context
        assert "site_id" not in context
        assert "input_json" not in raw
        assert "action" not in raw


@pytest.mark.parametrize("bad", ["foreign_ref", "extra_url", "write_tool", "severity", "unobserved_ref", "oversize"])
async def test_invalid_model_actions_cannot_dispatch_and_required_checks_still_run(monkeypatch, httpx_mock, bad):
    service, root, _, artifacts, stored = agent_runtime(monkeypatch)

    def respond(request):
        context = read_context(request)
        action = collect_all(context)
        if bad == "foreign_ref":
            action["checks"].append("b" * 64)
        elif bad == "extra_url":
            action["url"] = "https://attacker.invalid/collect"
        elif bad == "write_tool":
            action["action"] = "delete_wlan"
        else:
            action = proposal(context)
            if bad == "severity":
                action["report"]["severity"] = "critical"
            elif bad == "unobserved_ref":
                action["report"]["hypotheses"][0]["supporting_checks"] = [context["capabilities"][0]["ref"]]
            else:
                action["report"]["summary"] = "x" * 17_000
        return ai_response(action)

    httpx_mock.add_callback(respond, method="POST", url=AI_URL)
    add_mist(httpx_mock)
    await service._poll(root)  # noqa: SLF001
    assert artifacts[0].agent.state == "invalid_response"
    assert artifacts[0].agent.proposal is None
    assert artifacts[0].assessment.impact == "none"  # Required evidence, never the model's rating.
    assert stored["model_requests"][0]["action_artifact_id"] is None
    assert (
        stored["model_requests"][0]["response_error"]
        == {
            "foreign_ref": "unknown_or_repeated_check",
            "extra_url": "schema_mismatch",
            "write_tool": "schema_mismatch",
            "severity": "schema_mismatch",
            "unobserved_ref": "unobserved_or_foreign_evidence",
            "oversize": "output_too_large",
        }[bad]
    )
    assert len([r for r in httpx_mock.get_requests() if r.method == "GET"]) == 2
    assert all(r.url.host != "attacker.invalid" for r in httpx_mock.get_requests())


async def test_repeated_cached_checks_spend_model_budget_but_do_not_repeat_mist_reads(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = agent_runtime(monkeypatch)
    httpx_mock.add_callback(
        lambda r: ai_response(collect_all(read_context(r))), method="POST", url=AI_URL, is_reusable=True
    )
    add_mist(httpx_mock)
    await service._poll(root)  # noqa: SLF001
    assert artifacts[0].agent.state == "budget_exhausted"
    assert stored["model_calls_used"] == 3
    assert len(stored["dispatches"]) == 2
    assert artifacts[0].assessment.impact == "none"


@pytest.mark.parametrize("failure", ["http", "timeout", "malformed"])
async def test_provider_failure_preserves_journal_and_deterministic_fallback(monkeypatch, httpx_mock, failure):
    service, root, _, artifacts, stored = agent_runtime(monkeypatch)
    if failure == "timeout":
        httpx_mock.add_exception(httpx.ReadTimeout("secret-provider-error"), method="POST", url=AI_URL)
    else:
        httpx_mock.add_response(
            status_code=429 if failure == "http" else 200, text="secret-provider-error", method="POST", url=AI_URL
        )
    add_mist(httpx_mock)
    await service._poll(root)  # noqa: SLF001
    assert artifacts[0].agent.state == "provider_error"
    assert stored["model_requests"][0]["state"] == "provider_error"
    assert "secret-provider-error" not in json.dumps(stored["model_requests"], default=str)
    assert artifacts[0].assessment.impact == "none"


@pytest.mark.parametrize("committed", [False, True])
async def test_uncertain_model_reservation_never_calls_provider(monkeypatch, httpx_mock, committed):
    service, root, collection, artifacts, stored = agent_runtime(monkeypatch)
    normal = collection.update_one.side_effect

    async def fail(query, mutation):
        if committed:
            await normal(query, mutation)
        message = "acknowledgement lost"
        raise ConnectionFailure(message)

    collection.update_one.side_effect = fail
    with pytest.raises(ConnectionFailure):
        await service._poll(root)  # noqa: SLF001
    assert not httpx_mock.get_requests()
    assert not artifacts
    assert stored["model_calls_used"] == int(committed)
    if committed:
        assert stored["model_requests"][0]["state"] == "reserved"


@pytest.mark.parametrize("failure", ["completion_write", "cancelled"])
async def test_unfinished_model_call_stays_unknown_and_cannot_execute_actions(monkeypatch, httpx_mock, failure):
    service, root, collection, artifacts, stored = agent_runtime(monkeypatch)
    normal = collection.update_one.side_effect

    async def fail(query, mutation):
        if "model_requests" in query:
            message = "result write failed"
            raise ConnectionFailure(message)
        return await normal(query, mutation)

    def respond(request):
        if failure == "cancelled":
            raise asyncio.CancelledError
        return ai_response(collect_all(read_context(request)))

    collection.update_one.side_effect = fail
    httpx_mock.add_callback(respond, method="POST", url=AI_URL)
    with pytest.raises(asyncio.CancelledError if failure == "cancelled" else ConnectionFailure):
        await service._poll(root)  # noqa: SLF001
    assert [r.method for r in httpx_mock.get_requests()] == ["POST"]
    assert stored["model_requests"][0]["state"] == "reserved"
    assert not artifacts


@pytest.mark.parametrize("limit", ["calls", "bytes", "journal", "lease"])
async def test_audit_limits_and_lost_lease_prevent_provider_dispatch(monkeypatch, httpx_mock, limit):
    service, root, _, artifacts, stored = agent_runtime(monkeypatch)
    if limit == "calls":
        stored["model_calls_used"] = MAX_MODEL_CALLS
    elif limit == "bytes":
        stored["model_input_bytes_reserved"] = MAX_INPUT_BYTES_TOTAL
    elif limit == "journal":
        stored["model_requests"] = [{}] * MAX_MODEL_CALLS
    else:
        stored["generation"] += 1
    if limit != "lease":
        add_mist(httpx_mock)
    await service._poll(root)  # noqa: SLF001
    assert all(r.method == "GET" for r in httpx_mock.get_requests())
    assert artifacts[0].agent.state == "dispatch_denied"
    assert artifacts[0].agent.dispatch_denial == "reservation_rejected"


async def test_lost_lease_can_finish_own_model_record_but_not_dispatch_or_publish(monkeypatch, httpx_mock):
    service, root, collection, artifacts, stored = agent_runtime(monkeypatch)

    def respond(request):
        stored["generation"] += 1
        return ai_response(collect_all(read_context(request)))

    httpx_mock.add_callback(respond, method="POST", url=AI_URL)
    await service._poll(root)  # noqa: SLF001
    assert stored["model_requests"][0]["state"] == "complete"
    assert [r.method for r in httpx_mock.get_requests()] == ["POST"]
    assert artifacts[0].agent.state == "unavailable"
    assert artifacts[0].evidence[0].state == "dispatch_denied"
    assert collection.update_one.await_args.args[0]["generation"] == root.generation


async def test_checkpoint_resumes_exact_published_memory_and_refreshes_evidence(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = agent_runtime(monkeypatch)
    contexts = []

    def respond(request):
        contexts.append(read_context(request))
        return investigating_response(request)

    httpx_mock.add_callback(respond, method="POST", url=AI_URL, is_reusable=True)
    add_mist(httpx_mock)
    await service._poll(root)  # noqa: SLF001
    first = artifacts[0]
    root.report_id, root.revision = first.id, first.revision
    lookup = AsyncMock(return_value=first)
    monkeypatch.setattr(runtime.InvestigationRevision, "find_one", lookup)
    later = LATER + timedelta(minutes=10)
    root.lease_until = later + timedelta(minutes=3)
    monkeypatch.setattr(runtime, "utc_now", lambda: later)
    monkeypatch.setattr(agent_module, "utc_now", lambda: later)
    await service._poll(root)  # noqa: SLF001
    lookup.assert_awaited_once_with(
        {"_id": first.id, "organization_id": ORG, "investigation_id": root.id, "revision": first.revision}
    )
    assert contexts[2]["memory"]["source_revision"] == first.revision
    assert len(contexts[2]["previous_observations"]) == 2
    assert contexts[2]["observations"] == []
    assert len(stored["dispatches"]) == 4
    assert artifacts[1].agent.memory.source_revision == first.revision + 1
    assert artifacts[1].evidence[1].window.end == later


@pytest.mark.parametrize("missing", [True, False])
async def test_missing_or_foreign_published_context_never_reaches_model(monkeypatch, httpx_mock, missing):
    service, root, _, artifacts, stored = agent_runtime(monkeypatch)
    root.report_id = PydanticObjectId()
    wrong = SimpleNamespace(assessment=SimpleNamespace(audit_id="another-audit"))
    monkeypatch.setattr(runtime.InvestigationRevision, "find_one", AsyncMock(return_value=None if missing else wrong))
    add_mist(httpx_mock)
    await service._poll(root)  # noqa: SLF001
    assert stored["model_calls_used"] == 0
    assert artifacts[0].agent.state == "context_unavailable"
    assert artifacts[0].assessment.impact == "none"


@pytest.mark.parametrize("mode", ["legacy", "shadow"])
async def test_existing_modes_never_call_the_new_model_runtime(monkeypatch, httpx_mock, mode):
    service, root, _, artifacts, stored = agent_runtime(monkeypatch)
    monkeypatch.setattr(runtime, "get_settings", lambda: SimpleNamespace(impact_engine_mode=mode))
    add_mist(httpx_mock)
    await service._poll(root)  # noqa: SLF001
    agent_module.ApplicationConfigurationService.ai_runtime.assert_not_awaited()
    assert artifacts[0].agent is None
    assert stored["model_calls_used"] == 0


@pytest.mark.parametrize("change", ["provider", "credential", "disabled"])
async def test_configuration_revocation_stops_model_dispatch(monkeypatch, httpx_mock, change):
    service, root, _, artifacts, stored = agent_runtime(monkeypatch)
    if change == "provider":
        configured = await agent_module.ApplicationConfigurationService.ai_runtime()
        agent_module.ApplicationConfigurationService.ai_runtime.side_effect = [configured, None]
        add_mist(httpx_mock)
        expected = "provider_changed"
    else:
        organization = await runtime.Organization.get(ORG)
        replacement = SimpleNamespace(**vars(organization))
        if change == "credential":
            replacement.encrypted_service_token = "rotated-token"
        else:
            replacement.status = runtime.OrganizationStatus.DISABLED
        runtime.Organization.get.side_effect = [organization, replacement, replacement]
        expected = "credential_changed" if change == "credential" else "organization_unavailable"
    await service._poll(root)  # noqa: SLF001
    assert stored["model_calls_used"] == 0
    assert artifacts[0].agent.dispatch_denial == expected
    assert all(r.method == "GET" for r in httpx_mock.get_requests())


async def test_disabled_provider_is_visible_and_does_not_skip_required_checks(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = agent_runtime(monkeypatch)
    agent_module.ApplicationConfigurationService.ai_runtime.return_value = None
    add_mist(httpx_mock)
    await service._poll(root)  # noqa: SLF001
    assert artifacts[0].agent.state == "unavailable"
    assert artifacts[0].assessment.impact == "none"
    assert stored["model_calls_used"] == 0


async def test_no_model_conversation_before_audit_correlation(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = agent_runtime(monkeypatch)
    monkeypatch.setattr(runtime.AuditChangeGroup, "find_one", AsyncMock(return_value=None))
    await service._poll(root)  # noqa: SLF001
    agent_module.ApplicationConfigurationService.ai_runtime.assert_not_awaited()
    assert not httpx_mock.get_requests()
    assert stored["model_calls_used"] == 0
    assert artifacts[0].assessment.impact == "info"


async def test_completed_model_record_cannot_be_rewritten(monkeypatch, httpx_mock):
    service, root, _, _, stored = agent_runtime(monkeypatch)
    httpx_mock.add_callback(investigating_response, method="POST", url=AI_URL, is_reusable=True)
    add_mist(httpx_mock)
    await service._poll(root)  # noqa: SLF001
    record = ModelRequestRecord.model_validate(stored["model_requests"][0])
    with pytest.raises(RuntimeError, match="publication stopped"):
        await agent_module.ImpactAgent._finish(root, record, "provider_error")  # noqa: SLF001
    assert stored["model_requests"][0]["state"] == "complete"


async def test_input_admission_limit_stops_before_any_model_request(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = agent_runtime(monkeypatch)
    monkeypatch.setattr(agent_module, "MAX_INPUT_BYTES", 64)
    add_mist(httpx_mock)
    await service._poll(root)  # noqa: SLF001
    assert stored["model_calls_used"] == 0
    assert artifacts[0].agent.state == "budget_exhausted"
    assert artifacts[0].assessment.impact == "none"


async def test_missing_telemetry_cannot_become_clean_through_a_model_proposal(monkeypatch, httpx_mock):
    service, root, _, artifacts, _ = agent_runtime(monkeypatch)
    httpx_mock.add_callback(investigating_response, method="POST", url=AI_URL, is_reusable=True)
    httpx_mock.add_response(status_code=503, method="GET", is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    assert artifacts[0].agent.state == "complete"  # Only schema/reference validation, not factual acceptance.
    assert artifacts[0].assessment.impact == "info"
    assert artifacts[0].assessment.coverage == "partial"
    assert all(view.state == "error" for view in artifacts[0].agent.observations)


async def test_preview_separates_published_agent_proposal_from_live_model_activity(monkeypatch, httpx_mock):
    from mist_config_guardian_backend.services.investigation_reads import shadow_investigation  # noqa: PLC0415

    service, root, _, artifacts, stored = agent_runtime(monkeypatch)
    httpx_mock.add_callback(investigating_response, method="POST", url=AI_URL, is_reusable=True)
    add_mist(httpx_mock)
    await service._poll(root)  # noqa: SLF001
    artifact = artifacts[0]
    root.report_id, root.revision = artifact.id, artifact.revision
    root.model_calls_used = stored["model_calls_used"]
    root.model_input_bytes_reserved = stored["model_input_bytes_reserved"]
    root.model_requests = [ModelRequestRecord.model_validate(row) for row in stored["model_requests"]]
    monkeypatch.setattr(investigation_reads, "read_investigation_root", AsyncMock(return_value=root))
    monkeypatch.setattr(runtime.InvestigationRevision, "find_one", AsyncMock(return_value=artifact))
    result = await shadow_investigation(ORG, PydanticObjectId())
    assert result.agent == artifact.agent
    assert result.model_activity.source == "live_investigation_root"
    assert result.model_activity.calls_used == 2
    assert len(result.model_activity.records) == 2
    assert "test-provider-key" not in result.model_dump_json()


async def test_existing_lower_model_budget_is_preserved(monkeypatch, httpx_mock):
    service, root, collection, artifacts, stored = agent_runtime(monkeypatch)
    root.model_calls_limit = 1
    httpx_mock.add_callback(investigating_response, method="POST", url=AI_URL)
    add_mist(httpx_mock)
    await service._poll(root)  # noqa: SLF001
    assert stored["model_calls_used"] == 1
    assert artifacts[0].agent.state == "dispatch_denied"
    reservation = next(
        call for call in collection.update_one.await_args_list if "model_calls_used" in call.args[1].get("$inc", {})
    )
    assert reservation.args[1]["$set"]["model_calls_limit"] == 1
