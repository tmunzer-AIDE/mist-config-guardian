"""Typed domain evidence preserves service impact without aggregate attribution."""

from datetime import timedelta

import pytest

from mist_config_guardian_backend.impact.contracts import PortEvidence, PortRow, Window
from mist_config_guardian_backend.impact.domain_evaluation import compose_domains
from mist_config_guardian_backend.impact.wlan_removal import evaluate_wlan_removal
from mist_config_guardian_backend.integrations.mist_port_history import parse_port_history
from test_impact_neighbor_discovery import MIST_ORG
from test_impact_port_history import event_payload, history_inputs
from test_wlan_investigation import LATER, NOW


def assess(rule, events, *, power=None, at=None, partial=False):
    plan, target, window = history_inputs()
    target = target.model_copy(update={"domains": (rule,)})
    plan = plan.model_copy(update={"port_targets": (target,)})
    history = parse_port_history(event_payload(target, window, events), target, MIST_ORG, window)
    if partial:
        history = history.model_copy(update={"state": "partial"})
    evidence = [history]
    if power is not None:
        evidence.append(
            PortEvidence(
                target_handle=target.handle,
                window=Window(start=NOW, end=LATER),
                captured_at=LATER,
                state="complete",
                rows=(PortRow(up=True, poe_on=True, power_draw=power, observed_at=at),),
            )
        )
    return compose_domains(plan, evidence, evaluate_wlan_removal(plan, [], evidence_as_of=LATER))


def test_port_recovery_preserves_peak_and_does_not_claim_ap_failure():
    result = assess(
        "port-availability.v1",
        [
            ("SW_PORT_UP", NOW - timedelta(minutes=1)),
            ("SW_PORT_DOWN", NOW + timedelta(seconds=1)),
            ("SW_PORT_UP", NOW + timedelta(seconds=30)),
        ],
    )
    row = result.domain_findings[0]
    assert result.impact == row.impact == "warning"
    assert row.current_impact == "none"
    assert row.state == "recovered"
    assert row.service == "port_link"
    assert row.attribution == "plausible"


@pytest.mark.parametrize("partial", [False, True])
def test_empty_or_incomplete_history_never_proves_health(partial):
    result = assess("port-availability.v1", [], partial=partial)
    assert result.impact == "info"
    assert result.domain_findings[0].state == "unknown"


def test_poe_enabled_event_does_not_establish_prior_power_delivery():
    result = assess(
        "switch-poe.v1", [("SW_POE_PORT_ENABLED", NOW - timedelta(minutes=1)), ("SW_POE_PORT_DISABLED", NOW)]
    )
    assert result.impact == "info"


@pytest.mark.parametrize(
    ("power", "at", "expected"),
    [
        (0, NOW - timedelta(seconds=30), "info"),
        (12, NOW + timedelta(seconds=1), "info"),
        (12, NOW - timedelta(minutes=6), "info"),
        (12, None, "info"),
        (12, NOW - timedelta(seconds=30), "critical"),
    ],
)
def test_poe_loss_requires_recent_actual_prechange_delivery(power, at, expected):
    result = assess("switch-poe.v1", [("SW_POE_PORT_DISABLED", NOW)], power=power, at=at)
    assert result.impact == expected
    assert result.domain_findings[0].service == "port_power"
    assert result.domain_findings[0].device_mac is not None


def test_equal_timestamp_contradictions_do_not_sort_into_a_verdict():
    result = assess(
        "port-availability.v1", [("SW_PORT_UP", NOW - timedelta(minutes=1)), ("SW_PORT_DOWN", NOW), ("SW_PORT_UP", NOW)]
    )
    assert result.impact == "info"
    assert "Contradictory" in result.domain_findings[0].explanation
