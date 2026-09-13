"""Payloads are separate, journal-linked, digest-checked and loaded only on demand."""

import json
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from beanie import PydanticObjectId
from pymongo.errors import ConnectionFailure

from mist_config_guardian_backend.impact.agent import ModelRequestRecord
from mist_config_guardian_backend.models.investigation import ROOT_METADATA_PROJECTION
from mist_config_guardian_backend.services import impact_agent as agent_module
from mist_config_guardian_backend.services import investigation_reads, model_request_reads
from test_impact_agent import AI_URL, add_mist, agent_runtime, investigating_response
from test_wlan_investigation import ORG


async def prepared(monkeypatch, httpx_mock):
    service, root, collection, _, stored = agent_runtime(monkeypatch)
    httpx_mock.add_callback(investigating_response, method="POST", url=AI_URL, is_reusable=True)
    add_mist(httpx_mock)
    await service._poll(root)  # noqa: SLF001

    async def selected(query, *, projection):
        assert query == {"organization_id": ORG, "audit_id": root.audit_id}
        selected_id = projection["model_requests"]["$elemMatch"]["id"]
        assert set(projection) == {"_id", "model_requests"}
        return {"_id": root.id, "model_requests": [r for r in stored["model_requests"] if r["id"] == selected_id]}

    async def artifact(query):
        return next((a for a in stored["model_artifacts"] if a.id == query["_id"]), None)

    collection.find_one.side_effect = selected
    monkeypatch.setattr(agent_module.ModelRequestArtifact, "find_one", AsyncMock(side_effect=artifact))
    record = ModelRequestRecord.model_validate(stored["model_requests"][0])
    return service, root, collection, stored, record


async def test_request_details_follow_exact_scoped_pointers_and_verify_digests(monkeypatch, httpx_mock):
    _, root, _, stored, record = await prepared(monkeypatch, httpx_mock)
    result = await model_request_reads.model_request_details(ORG, PydanticObjectId(), record.id)
    assert result.input_state == result.action_state == "available"
    assert json.loads(result.input_json)["observations"] == []
    assert result.action.action == "collect"
    assert len(stored["model_artifacts"]) == 4  # Separate input and validated-action artifacts per request.
    for call in agent_module.ModelRequestArtifact.find_one.await_args_list:
        query = call.args[0]
        assert query["organization_id"] == ORG
        assert query["investigation_id"] == root.id
        assert query["request_id"] == record.id
        assert query["generation"] == record.generation
        assert query["candidate_revision"] == record.candidate_revision
        assert "content_hash" in query
    assert "input_json" not in record.model_dump()
    assert "action" not in record.model_dump()


@pytest.mark.parametrize("corruption", ["content", "organization", "request", "revision", "generation", "missing"])
async def test_foreign_missing_or_tampered_input_is_not_displayed(monkeypatch, httpx_mock, corruption):
    _, _, _, stored, record = await prepared(monkeypatch, httpx_mock)
    artifact = next(a for a in stored["model_artifacts"] if a.id == record.input_artifact_id)
    if corruption == "missing":
        stored["model_artifacts"].remove(artifact)
    else:
        changes = {
            "content": {"content_json": '{"forged":"context"}'},
            "organization": {"organization_id": PydanticObjectId()},
            "request": {"request_id": uuid4()},
            "revision": {"candidate_revision": record.candidate_revision + 1},
            "generation": {"generation": record.generation + 1},
        }
        stored["model_artifacts"][stored["model_artifacts"].index(artifact)] = artifact.model_copy(
            update=changes[corruption]
        )
    result = await model_request_reads.model_request_details(ORG, PydanticObjectId(), record.id)
    assert result.input_state == "unavailable"
    assert result.input_json is None
    assert result.action_state == "available"


async def test_action_digest_is_also_required(monkeypatch, httpx_mock):
    _, _, _, stored, record = await prepared(monkeypatch, httpx_mock)
    artifact = next(a for a in stored["model_artifacts"] if a.id == record.action_artifact_id)
    artifact.content_json = '{"action":"report","report":{"summary":"forged"}}'
    result = await model_request_reads.model_request_details(ORG, PydanticObjectId(), record.id)
    assert result.input_state == "available"
    assert result.action_state == "unavailable"
    assert result.action is None


async def test_unjournalled_request_cannot_read_even_same_organization_artifacts(monkeypatch, httpx_mock):
    _, _, _, _, _ = await prepared(monkeypatch, httpx_mock)
    assert await model_request_reads.model_request_details(ORG, PydanticObjectId(), uuid4()) is None
    agent_module.ModelRequestArtifact.find_one.assert_not_awaited()


async def test_foreign_change_group_cannot_access_request_context(monkeypatch, httpx_mock):
    _, _, collection, _, record = await prepared(monkeypatch, httpx_mock)
    monkeypatch.setattr(model_request_reads.AuditChangeGroup, "find_one", AsyncMock(return_value=None))
    assert await model_request_reads.model_request_details(ORG, PydanticObjectId(), record.id) is None
    collection.find_one.assert_not_awaited()
    agent_module.ModelRequestArtifact.find_one.assert_not_awaited()


async def test_database_failure_keeps_request_context_unavailable(monkeypatch, httpx_mock):
    _, _, _, _, record = await prepared(monkeypatch, httpx_mock)
    agent_module.ModelRequestArtifact.find_one.side_effect = ConnectionFailure("private database detail")
    result = await model_request_reads.model_request_details(ORG, PydanticObjectId(), record.id)
    assert result.input_state == result.action_state == "unavailable"
    assert "private database detail" not in result.model_dump_json()


async def test_legacy_embedded_payload_is_only_returned_on_explicit_request(monkeypatch, httpx_mock):
    _, _, _, stored, record = await prepared(monkeypatch, httpx_mock)
    raw = stored["model_requests"][0]
    raw["input_json"] = '{"legacy":"context"}'
    raw["action"] = {"action": "collect", "checks": ["a" * 64]}
    for key in ("input_artifact_id", "input_context_hash", "action_artifact_id", "action_hash"):
        raw.pop(key)
    result = await model_request_reads.model_request_details(ORG, PydanticObjectId(), record.id)
    assert result.input_state == result.action_state == "legacy"
    assert result.input_json == raw["input_json"]
    assert result.action.checks == ("a" * 64,)
    agent_module.ModelRequestArtifact.find_one.assert_not_awaited()


@pytest.mark.parametrize("committed", [False, True])
async def test_failed_or_uncertain_input_artifact_insert_cannot_reserve_or_dispatch(monkeypatch, httpx_mock, committed):
    service, root, _, artifacts, stored = agent_runtime(monkeypatch)
    normal = agent_module.ModelRequestArtifact.insert

    async def fail(artifact):
        if committed:
            await normal(artifact)
        message = "input insert acknowledgement lost"
        raise ConnectionFailure(message)

    monkeypatch.setattr(agent_module.ModelRequestArtifact, "insert", fail)
    with pytest.raises(ConnectionFailure):
        await service._poll(root)  # noqa: SLF001
    assert not httpx_mock.get_requests()
    assert stored["model_calls_used"] == 0
    assert not stored["model_requests"]
    assert len(stored["model_artifacts"]) == int(committed)
    assert not artifacts


async def test_action_artifact_failure_leaves_unknown_request_and_stops_tool_execution(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = agent_runtime(monkeypatch)
    normal = agent_module.ModelRequestArtifact.insert

    async def fail(artifact):
        if artifact.kind == "action":
            message = "action artifact insert failed"
            raise ConnectionFailure(message)
        return await normal(artifact)

    monkeypatch.setattr(agent_module.ModelRequestArtifact, "insert", fail)
    httpx_mock.add_callback(investigating_response, method="POST", url=AI_URL)
    with pytest.raises(ConnectionFailure):
        await service._poll(root)  # noqa: SLF001
    assert [r.method for r in httpx_mock.get_requests()] == ["POST"]
    assert stored["model_requests"][0]["state"] == "reserved"
    assert stored["model_requests"][0]["action_artifact_id"] is None
    assert not artifacts


async def test_compact_root_and_poll_claim_exclude_legacy_payloads(monkeypatch, httpx_mock):
    service, root, collection, stored, _ = await prepared(monkeypatch, httpx_mock)
    raw = {**root.model_dump(by_alias=True), "model_requests": stored["model_requests"]}
    for record in raw["model_requests"]:
        record["input_json"] = "legacy input must not load"
        record["action"] = {"legacy": "action must not load"}

    async def projected(*_args, projection, **_kwargs):
        assert projection == ROOT_METADATA_PROJECTION
        return {
            **raw,
            "model_requests": [
                {k: v for k, v in r.items() if k not in {"input_json", "action"}} for r in raw["model_requests"]
            ],
        }

    collection.find_one.side_effect = projected
    loaded = await investigation_reads.read_investigation_root({"organization_id": ORG, "audit_id": root.audit_id})
    assert "legacy input must not load" not in loaded.model_dump_json()
    documents = [await projected(projection=ROOT_METADATA_PROJECTION), None]
    collection.find_one_and_update = AsyncMock(side_effect=documents)
    monkeypatch.setattr(service, "_poll", AsyncMock())
    await service.poll_due()
    assert collection.find_one_and_update.await_args_list[0].kwargs["projection"] == ROOT_METADATA_PROJECTION
