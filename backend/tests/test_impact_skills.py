"""Pinned skills guide reasoning without extending operational authority."""

from types import SimpleNamespace

import pytest

from mist_config_guardian_backend.impact import skills
from mist_config_guardian_backend.impact.agent import capabilities
from mist_config_guardian_backend.impact.contracts import WlanRemovalPlan
from mist_config_guardian_backend.impact.wlan_removal import compile_wlan_removal
from test_impact_agent import add_mist, agent_runtime
from test_impact_auth_evidence import auth_inputs
from test_impact_port_scope import port_inputs
from test_wlan_investigation import LATER, NOW, ORG, inputs


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (inputs, {"wlan-lifecycle.v1"}),
        (auth_inputs, {"wlan-authentication.v1"}),
        (port_inputs, {"switch-poe.v1"}),
    ],
)
def test_only_relevant_hash_verified_skills_are_selected(data, expected):
    plan = compile_wlan_removal(**data())
    menu = capabilities(plan, LATER)
    chosen = skills.selected_skills(plan)
    assert {s.id for s in chosen} == expected
    assert all(len(s.content_hash) == 64 for s in chosen)
    assert capabilities(plan, LATER) == menu


async def test_tampered_skill_stops_model_without_canceling_required_collection(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = agent_runtime(monkeypatch)
    monkeypatch.setattr(
        skills,
        "files",
        lambda *_: SimpleNamespace(
            joinpath=lambda *_: SimpleNamespace(read_bytes=lambda: b"arbitrary injected instructions")
        ),
    )
    add_mist(httpx_mock)
    await service._poll(root)  # noqa: SLF001
    assert artifacts[0].agent.state == "unavailable"
    assert "could not be verified" in artifacts[0].agent.reason
    assert stored["model_calls_used"] == 0
    assert stored["calls_used"] == 2


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        (
            [{"object_type": "wlans", "attributes": [{"auth": {"before": "psk", "after": "eap"}}]}],
            {"wlan-lifecycle.v1", "wlan-authentication.v1"},
        ),
        ([{"object_type": "devices", "attributes": [{"port_config": {}}]}], {"port-availability.v1"}),
        (
            [{"object_type": "networktemplates", "attributes": [{"port_usages": {}}, {"poe_disabled": {}}]}],
            {"port-availability.v1", "switch-poe.v1"},
        ),
        ([{"object_type": "sites", "attributes": [{"stp_config": {}}]}], set()),
    ],
)
def test_mcp_playbooks_follow_the_change_type_within_the_bound(changes, expected):
    plan = WlanRemovalPlan(
        organization_id=str(ORG), audit_id="audit-one", changed_at=NOW, mcp_context={"changes": changes}
    )
    chosen = skills.mcp_playbooks(plan)
    assert {s.id for s in chosen} == expected
    assert sum(len(s.instructions.encode()) for s in chosen) <= skills.MAX_PLAYBOOK_BYTES


def test_mcp_playbooks_stop_at_the_byte_bound(monkeypatch):
    changes = [{"object_type": "wlans", "attributes": [{"auth": {"before": "psk", "after": "eap"}}]}]
    plan = WlanRemovalPlan(
        organization_id=str(ORG), audit_id="audit-one", changed_at=NOW, mcp_context={"changes": changes}
    )
    monkeypatch.setattr(skills, "MAX_PLAYBOOK_BYTES", 500)
    # Sorted selection: authentication (470 B) fits, lifecycle (442 B) would exceed 500 B.
    assert [s.id for s in skills.mcp_playbooks(plan)] == ["wlan-authentication.v1"]


@pytest.mark.parametrize("data", [inputs, auth_inputs, port_inputs])
def test_mcp_playbooks_include_every_rule_selected_skill(data):
    plan = compile_wlan_removal(**data())
    assert {s.id for s in skills.selected_skills(plan)} <= {s.id for s in skills.mcp_playbooks(plan)}
