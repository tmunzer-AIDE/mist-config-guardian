"""The largest legal required set must survive collection, storage and publication."""

import re
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from beanie import PydanticObjectId
from pydantic import ValidationError

from mist_config_guardian_backend.impact.agent import capabilities
from mist_config_guardian_backend.impact.wlan_removal import compile_wlan_removal
from mist_config_guardian_backend.models.investigation import InvestigationRevision
from mist_config_guardian_backend.services import impact_investigations as runtime
from mist_config_guardian_backend.snapshots.registry import SITE_OBJECTS, ObjectFamily
from test_impact_agent import AI_URL, agent_runtime, ai_response, read_context
from test_impact_change_context import gap_report, use_data
from test_impact_dispatch_journal import empty_response
from test_impact_port_scope import payload, port_inputs
from test_wlan_investigation import LATER, inputs


def mixed_inputs():
    data = port_inputs()
    data["after"][0].configuration["port_config_overwrite"]["ge-0/0/2"] = {"poe_disabled": True}
    for _ in range(4):
        wlan = inputs()
        identity = PydanticObjectId()
        wlan_id = str(uuid4())
        wlan["logicals"][0].id = identity
        wlan["logicals"][0].object_type = next(d.key for d in SITE_OBJECTS if d.family is ObjectFamily.WLAN)
        for version in [*wlan["before"], *wlan["after"]]:
            version.logical_object_id = identity
            version.configuration["id"] = wlan_id
        for key in ("logicals", "before", "after"):
            data[key].extend(wlan[key])
    return data


@pytest.mark.parametrize("mode", ["shadow", "agent_shadow"])
async def test_maximal_mixed_audit_publishes_all_ten_checks_once(monkeypatch, httpx_mock, mode):
    service, root, collection, artifacts, stored = agent_runtime(monkeypatch)
    monkeypatch.setattr(runtime, "get_settings", lambda: SimpleNamespace(impact_engine_mode=mode))
    data = mixed_inputs()
    use_data(service, data)
    menu = capabilities(compile_wlan_removal(**data), LATER)
    assert len(menu) == 10  # Independent regression boundary, not derived from the cap under test.
    if mode == "agent_shadow":

        def respond(request):
            context = read_context(request)
            observed = {item["ref"] for item in context["observations"]}
            missing = [item["ref"] for item in context["capabilities"] if item["ref"] not in observed]
            return ai_response({"action": "collect", "checks": missing[:8]} if missing else gap_report())

        httpx_mock.add_callback(respond, method="POST", url=AI_URL, is_reusable=True)
    httpx_mock.add_callback(
        empty_response, method="GET", url=re.compile(r".*/clients/sessions/search\?.*"), is_reusable=True
    )
    httpx_mock.add_callback(
        lambda request: httpx.Response(200, json=payload(port_id=request.url.params["port_id"])),
        method="GET",
        url=re.compile(r".*/stats/ports/search\?.*"),
        is_reusable=True,
    )
    await service._poll(root)  # noqa: SLF001
    assert stored["calls_used"] == 10
    assert len(stored["dispatches"]) == 10
    assert all(d["state"] == "complete" for d in stored["dispatches"])
    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert len(artifact.evidence) == 10
    assert len(artifact.assessment.findings) == 4
    assert all(finding.impact == "none" for finding in artifact.assessment.findings)
    assert artifact.assessment.impact == "info"  # Port impact still unmapped.
    persisted = InvestigationRevision.model_validate_json(artifact.model_dump_json())
    assert persisted.evidence == artifact.evidence
    if mode == "agent_shadow":
        assert artifact.agent.state == "complete"
        assert len(artifact.agent.observations) == 10
        assert stored["model_calls_used"] == 3
    publications = [
        call for call in collection.update_one.await_args_list if "report_id" in call.args[1].get("$set", {})
    ]
    assert len(publications) == 1
    query, mutation = publications[0].args
    assert query["revision"] == root.revision
    assert query["generation"] == root.generation
    assert query["lease_until"] == {"$gt": LATER}
    assert mutation["$set"]["report_id"] == artifact.id
    assert mutation["$set"]["revision"] == root.revision + 1
    assert mutation["$set"]["next_poll_at"] > LATER
    with pytest.raises(ValidationError, match="at most 10"):
        InvestigationRevision.model_validate(
            {**artifact.model_dump(), "evidence": [*artifact.evidence, artifact.evidence[0]]}
        )
