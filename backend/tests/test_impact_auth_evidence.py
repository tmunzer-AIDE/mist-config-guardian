"""Authentication uses immutable WLAN scope and paired clients, never aggregate failure counts."""

import re
from datetime import timedelta

import pytest
from pydantic import ValidationError

from mist_config_guardian_backend.impact.agent import capabilities
from mist_config_guardian_backend.impact.domain_evaluation import compose_domains
from mist_config_guardian_backend.impact.wlan_removal import compile_wlan_removal, evaluate_wlan_removal
from mist_config_guardian_backend.integrations.mist_auth_evidence import parse_auth
from mist_config_guardian_backend.models.investigation import InvestigationRevision
from test_impact_agent import AI_URL, ai_response, read_context
from test_impact_change_context import gap_report, use_data
from test_impact_dispatch_journal import empty_response
from test_impact_mixed_publication import mixed_inputs
from test_impact_neighbor_discovery import INVENTORY_URL, MIST_ORG, inventory_payload, neighbor_runtime, register_port
from test_wlan_investigation import LATER, NOW, inputs

AUTH_URL = re.compile(r".*/clients/events/search\?.*")


def auth_inputs():
    data = inputs()
    data["after"][0].is_deleted = False
    for v in [*data["before"], *data["after"]]:
        v.configuration["enabled"] = True
    data["before"][0].configuration["auth"] = {"psk": "secret-before", "type": "psk"}
    data["after"][0].configuration["auth"] = {"psk": "secret-after", "type": "psk"}
    data["after"][0].changed_fields = ["auth"]
    return data


def response_for(_plan, target, window, events):
    return {
        "start": int(window.start.timestamp()),
        "end": int(window.end.timestamp()),
        "total": len(events),
        "results": [
            {
                "type": kind,
                "timestamp": at.timestamp(),
                "mac": client,
                "ap": "aabbccddee01",
                "site_id": str(target.site_id),
                "wlan_id": str(target.wlan_id),
                "org_id": str(MIST_ORG),
                "text": "secret-provider-message",
                "ssid": "secret-injected-name",
            }
            for kind, at, client in events
        ],
    }


def test_auth_scope_collects_one_history_check_without_unrelated_sessions():
    plan = compile_wlan_removal(**auth_inputs())
    assert not plan.unmapped
    assert plan.targets[0].change_kind == "authentication"
    assert [c.check_id for c in capabilities(plan, LATER)] == ["wlan-auth-events.v1"]
    assert "secret" not in plan.model_dump_json()


def test_paired_client_failure_and_positive_recovery_do_not_mark_ap_failed():
    plan = compile_wlan_removal(**auth_inputs())
    target = plan.targets[0]
    check = capabilities(plan, LATER)[0]
    payload = response_for(
        plan,
        target,
        check.window,
        [
            ("CLIENT_AUTHENTICATED", NOW - timedelta(minutes=1), "001122334455"),
            ("MARVIS_EVENT_CLIENT_AUTH_FAILURE", NOW, "001122334455"),
            ("CLIENT_AUTHENTICATED", NOW + timedelta(seconds=1), "001122334455"),
            ("MARVIS_EVENT_CLIENT_AUTH_FAILURE", NOW, "001122334466"),
        ],
    )
    evidence = parse_auth(payload, plan, target, MIST_ORG, check.window)
    result = compose_domains(plan, [evidence], evaluate_wlan_removal(plan, [], evidence_as_of=LATER))
    finding = result.domain_findings[0]
    assert finding.impact == "warning"
    assert finding.state == "recovered"
    assert finding.affected_clients == 1
    assert finding.device_mac is None
    assert finding.serving_ap_macs == ("aabbccddee01",)
    assert "001122334455" not in evidence.model_dump_json()
    assert "secret" not in evidence.model_dump_json()


@pytest.mark.parametrize("change", ["wlan_id", "site_id", "org_id", "timestamp"])
def test_wrong_scope_and_timing_are_rejected(change):
    plan = compile_wlan_removal(**auth_inputs())
    target = plan.targets[0]
    check = capabilities(plan, LATER)[0]
    payload = response_for(plan, target, check.window, [("CLIENT_AUTHENTICATED", NOW, "001122334455")])
    payload["results"][0][change] = "invalid"
    with pytest.raises(ValueError, match=r"scope mismatch|invalid timing"):
        parse_auth(payload, plan, target, MIST_ORG, check.window)


def test_missing_clients_and_empty_attempts_never_mean_no_impact():
    plan = compile_wlan_removal(**auth_inputs())
    target = plan.targets[0]
    check = capabilities(plan, LATER)[0]
    for events in [[], [("MARVIS_EVENT_CLIENT_AUTH_FAILURE", NOW, None)]]:
        evidence = parse_auth(response_for(plan, target, check.window, events), plan, target, MIST_ORG, check.window)
        result = compose_domains(plan, [evidence], evaluate_wlan_removal(plan, [], evidence_as_of=LATER))
        assert result.impact == "info"
        assert result.domain_findings[0].state == "unknown"


@pytest.mark.parametrize("mode", ["shadow", "agent_shadow"])
async def test_all_four_domains_fit_eighteen_checks_and_publish_once(monkeypatch, httpx_mock, mode):
    service, root, _, artifacts, stored = neighbor_runtime(monkeypatch, mode)
    data = mixed_inputs()
    for v in data["after"]:
        if "enabled" in v.configuration:
            v.changed_fields = [*v.changed_fields, "auth"]
    use_data(service, data)
    register_port(httpx_mock)
    httpx_mock.add_response(url=INVENTORY_URL, json=inventory_payload(), is_reusable=True)
    httpx_mock.add_callback(
        empty_response, method="GET", url=re.compile(r".*/clients/sessions/search\?.*"), is_reusable=True
    )
    httpx_mock.add_callback(empty_response, method="GET", url=AUTH_URL, is_reusable=True)
    if mode == "agent_shadow":

        def respond(request):
            context = read_context(request)
            assert all(c["window_ref"] in context["windows"] for c in context["capabilities"])
            assert all(row["window_ref"] in context["windows"] for row in context["observations"])
            assert context["domain_skills"]
            observed = {row["ref"] for row in context["observations"]}
            missing = [c["ref"] for c in context["capabilities"] if c["ref"] not in observed]
            return ai_response({"action": "collect", "checks": missing} if missing else gap_report())

        httpx_mock.add_callback(respond, method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    assert stored["calls_used"] == len(artifacts[0].evidence) == 18
    assert len(artifacts) == 1
    assert all(record["state"] == "complete" for record in stored["dispatches"])
    assert InvestigationRevision.model_validate_json(artifacts[0].model_dump_json()).evidence == artifacts[0].evidence
    if mode == "agent_shadow":
        assert artifacts[0].agent.state == "complete"
        assert stored["model_calls_used"] == 2
        assert {s.id for s in artifacts[0].agent.skills} == {
            "wlan-lifecycle.v1",
            "wlan-authentication.v1",
            "switch-poe.v1",
        }
    with pytest.raises(ValidationError, match="at most 18"):
        InvestigationRevision.model_validate(
            {**artifacts[0].model_dump(), "evidence": [*artifacts[0].evidence, artifacts[0].evidence[0]]}
        )
