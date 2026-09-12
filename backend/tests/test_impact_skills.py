"""Pinned skills guide reasoning without extending operational authority."""

from types import SimpleNamespace

import pytest

from mist_config_guardian_backend.impact import skills
from mist_config_guardian_backend.impact.agent import capabilities
from mist_config_guardian_backend.impact.wlan_removal import compile_wlan_removal
from test_impact_agent import add_mist, agent_runtime
from test_impact_auth_evidence import auth_inputs
from test_impact_port_scope import port_inputs
from test_wlan_investigation import LATER, inputs


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
