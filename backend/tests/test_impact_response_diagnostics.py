"""Model formatting failures remain bounded diagnostics, never executable evidence."""

import json

import httpx
import pytest
from pydantic import ValidationError

from mist_config_guardian_backend.impact.agent import ModelRequestRecord, ModelResponseError
from mist_config_guardian_backend.services.impact_agent import ImpactAgent, InvalidModelActionError
from test_impact_agent import AI_URL, agent_runtime, ai_response, read_context
from test_impact_change_context import device_inputs, gap_report, use_data


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("```json\n{}\n```", ModelResponseError.INVALID_JSON),
        ('{"action":"collect","checks":[]}', ModelResponseError.EMPTY_COLLECTION),
        ('{"action":"report","private-value":"secret"}', ModelResponseError.SCHEMA_MISMATCH),
        ("x" * 17000, ModelResponseError.OUTPUT_TOO_LARGE),
    ],
)
def test_parse_classifies_without_retaining_model_text(text, reason):
    with pytest.raises(InvalidModelActionError) as caught:
        ImpactAgent._parse(text)  # noqa: SLF001
    assert caught.value.error == reason
    assert "secret" not in str(caught.value)


@pytest.mark.parametrize("invalid", [False, True])
async def test_unmapped_only_report_contract_and_journal(monkeypatch, httpx_mock, invalid):
    service, root, _, revisions, stored = agent_runtime(monkeypatch)
    use_data(service, device_inputs())

    def respond(request):
        context = read_context(request)
        assert context["capabilities"] == []
        system = json.loads(request.content)["messages"][0]["content"]
        schema = json.loads(system.split("JSON action schema:\n")[1].split("\nNo checks")[0])
        assert schema["properties"]["action"]["const"] == "report"
        assert '"hypotheses":[]' in system
        if invalid:
            return httpx.Response(200, json={"choices": [{"message": {"content": '{"action":"collect","checks":[]}'}}]})
        return ai_response(gap_report())

    httpx_mock.add_callback(respond, method="POST", url=AI_URL)
    await service._poll(root)  # noqa: SLF001
    assert len(httpx_mock.get_requests()) == 1
    assert stored["calls_used"] == 0
    assert revisions[0].assessment.impact == "info"
    record = ModelRequestRecord.model_validate(stored["model_requests"][0])
    if invalid:
        assert record.response_error == ModelResponseError.EMPTY_COLLECTION
        assert record.action_artifact_id is None
        assert "empty check collection" in revisions[0].agent.reason
        with pytest.raises(ValidationError, match="requires invalid_response"):
            ModelRequestRecord.model_validate({**record.model_dump(), "state": "complete"})
        assert all(a.kind == "input" for a in stored["model_artifacts"])
    else:
        assert record.state == "complete"
        assert record.response_error is None
        assert revisions[0].agent.proposal.hypotheses == ()
