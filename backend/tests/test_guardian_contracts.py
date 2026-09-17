"""Guardian's pure contracts enforce the spec's shapes and cross-field invariants without any database."""

import subprocess
import sys
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from mist_config_guardian_backend.guardian.contracts import (
    MAX_REASON_CHARS,
    AgentConclusion,
    CompactImpactedDevice,
    Conclusion,
    DeviceImpact,
    Evidence,
    Exclusion,
    ExpectedDevice,
    Finding,
    Gap,
    LedgerRow,
    Obligation,
    ObligationStatus,
    RuleConclusion,
    RulePlan,
    RunBudget,
    Target,
    Verdict,
    band_rank,
    bound_reason,
    recovery_for,
    validate_published_verdict,
)

NOW = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)
MAC = "5c5b35000001"
SITE = "978c48e6-6ef6-11e6-8bbf-02e208b2d34f"


def verdict(**overrides) -> Verdict:
    values = {
        "peak": "warning",
        "current": "info",
        "recovery": "recovered",
        "confidence": "low",
        "coverage": "partial",
        "sources": ("monitoring",),
        "summary": "Monitoring saw a warning that later recovered.",
    }
    return Verdict.model_validate(values | overrides)


def evidence(**overrides) -> Evidence:
    values = {
        "id": "E1",
        "source": "monitoring",
        "kind": "service_health",
        "title": "Monitoring sessions",
        "captured_at": NOW,
        "collection": "complete",
        "representation": "full",
    }
    return Evidence.model_validate(values | overrides)


def monitoring_obligation(**overrides) -> Obligation:
    values = {
        "id": "O1",
        "owner": "dns",
        "change_ref": "A1",
        "paths": (("dns_servers",),),
        "role": "observation",
        "kind": "monitoring",
        "target": Target(device_mac=MAC),
        "metric": "switch-health",
        "empty_policy": "incomplete",
    }
    return Obligation.model_validate(values | overrides)


def test_bands_are_ordered_and_recovery_follows_peak_and_current():
    assert [band_rank(band) for band in ("none", "info", "warning", "critical")] == [0, 1, 2, 3]
    assert recovery_for("critical", "info") == "recovered"
    assert recovery_for("warning", "none") == "recovered"
    assert recovery_for("warning", "warning") == "unrecovered"
    assert recovery_for("critical", "warning") == "unrecovered"
    assert recovery_for("info", "info") == "none"
    assert recovery_for("none", "none") == "none"


def test_a_valid_verdict_is_frozen_and_closed():
    published = verdict()
    with pytest.raises(ValidationError):
        published.peak = "critical"
    with pytest.raises(ValidationError):
        verdict(unexpected="field")


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"peak": "info", "current": "warning", "recovery": "unrecovered"}, "current"),
        ({"recovery": "none"}, "Recovery"),
        ({"peak": "info", "current": "info", "recovery": "recovered"}, "Recovery"),
        ({"peak": "info", "current": "none", "recovery": "none", "coverage": "partial"}, "complete"),
        ({"peak": "none", "current": "none", "recovery": "none", "coverage": "not_applicable"}, "complete"),
    ],
)
def test_verdict_rejects_inconsistent_bands(overrides, message):
    with pytest.raises(ValidationError, match=message):
        verdict(**overrides)


def test_only_complete_coverage_publishes_none_and_a_recovered_warning_may_end_at_none():
    assert verdict(peak="none", current="none", recovery="none", coverage="complete").peak == "none"
    assert verdict(current="none", coverage="complete").recovery == "recovered"
    validate_published_verdict("critical", "critical", "unrecovered", "insufficient")


def test_compact_impacted_devices_keep_current_within_peak():
    CompactImpactedDevice(mac=MAC, site_id=SITE, name="sw-1", peak="critical", current="info")
    with pytest.raises(ValidationError, match="current"):
        CompactImpactedDevice(mac=MAC, site_id=SITE, name="sw-1", peak="info", current="warning")
    with pytest.raises(ValidationError):
        CompactImpactedDevice(mac="5C:5B:35:00:00:01", site_id=SITE, peak="info", current="info")


def test_verdict_carries_capped_compact_devices_and_sourced_gaps():
    published = verdict(
        impacted_devices=(CompactImpactedDevice(mac=MAC, site_id=SITE, peak="warning", current="info"),),
        impacted_devices_omitted=3,
        gaps=(Gap(source="rule:switch-port", text="Port snapshot unavailable"),),
        sources=("monitoring", "rule:switch-port", "agent"),
    )
    assert published.impacted_devices_omitted == 3
    with pytest.raises(ValidationError):
        verdict(impacted_devices_omitted=-1)
    with pytest.raises(ValidationError):
        verdict(sources=("mcp:search_mist_data",))


def test_evidence_citability_and_server_owned_kinds():
    assert evidence().citable
    assert evidence(source="mcp:get_mist_config", kind="configuration", representation="digest").citable
    assert evidence(source="rule:wlan-auth", kind="service_health").citable
    assert not evidence(collection="error", detail="Mist returned 503").citable
    point = evidence(window={"start": NOW, "end": NOW}, scope={"site_ids": (SITE,), "device_macs": (MAC,)})
    assert point.window is not None
    assert point.scope.device_macs == (MAC,)


@pytest.mark.parametrize(
    "overrides",
    [
        {"source": "monitoring", "kind": "configuration"},
        {"source": "deployment", "kind": "service_health"},
        {"source": "mcp:search_mist_data", "kind": "deployment"},
        {"source": "rule:dns", "kind": "deployment"},
        {"collection": "error", "detail": ""},
        {"id": "E0"},
        {"source": "mcp:"},
        {"window": {"start": NOW, "end": NOW - timedelta(seconds=1)}},
        {"scope": {"device_macs": ("5C:5B:35:00:00:01",)}},
    ],
)
def test_evidence_rejects_invalid_kind_source_and_error_shapes(overrides):
    with pytest.raises(ValidationError):
        evidence(**overrides)


def test_obligations_separate_core_preconditions_from_plugin_observations():
    anchor = Obligation(id="O2", owner="core", role="precondition", kind="anchor", target=Target())
    deployment = Obligation(
        id="O3", owner="core", role="precondition", kind="deployment", target=Target(device_mac=MAC)
    )
    rule = Obligation(
        id="O4",
        owner="switch-port",
        change_ref="A2",
        paths=(("port_config", "ge-0/0/1", "disabled"),),
        role="observation",
        kind="rule",
        target=Target(device_mac=MAC, port_id="ge-0/0/1"),
    )
    assert {anchor.kind, deployment.kind, rule.kind, monitoring_obligation().kind} == {
        "anchor",
        "deployment",
        "rule",
        "monitoring",
    }


@pytest.mark.parametrize(
    "overrides",
    [
        {"kind": "deployment", "owner": "core", "role": "observation", "metric": None, "empty_policy": None},
        {"kind": "anchor", "owner": "dns", "role": "precondition", "metric": None, "empty_policy": None},
        {"role": "precondition"},
        {"change_ref": None},
        {"paths": ()},
        {"paths": ((),)},
        {"metric": None},
        {"empty_policy": None},
        {"kind": "rule", "metric": None},
        {"id": "E1"},
    ],
)
def test_obligations_reject_role_kind_and_policy_mismatches(overrides):
    with pytest.raises(ValidationError):
        monitoring_obligation(**overrides)


def test_statuses_carry_a_reason_only_when_unsatisfied():
    assert ObligationStatus(status="satisfied", evidence_ids=("E1",)).reason is None
    assert ObligationStatus(status="unsatisfied", reason="3 of 5 ports").reason == "3 of 5 ports"
    with pytest.raises(ValidationError, match="reason"):
        ObligationStatus(status="unsatisfied")
    with pytest.raises(ValidationError, match="reason"):
        ObligationStatus(status="not_exercised", reason="no attempts")


def test_rule_plans_hold_unique_plugin_observations_and_scoped_exclusions():
    exclusion = Exclusion(
        owner="dns",
        change_ref="A1",
        paths=(("dns_servers",),),
        target=Target(site_id=SITE),
        reason="Client resolution is not used by APs",
    )
    plan = RulePlan(
        obligations=(monitoring_obligation(),),
        exclusions=(exclusion,),
        incident_types=("dns_failure",),
        finding_kinds=("port_down",),
    )
    assert plan.exclusions[0].target.site_id == SITE
    with pytest.raises(ValidationError, match="unique"):
        RulePlan(obligations=(monitoring_obligation(), monitoring_obligation()))
    with pytest.raises(ValidationError, match="observation"):
        RulePlan(obligations=(Obligation(id="O9", owner="core", role="precondition", kind="anchor", target=Target()),))
    with pytest.raises(ValidationError):
        Exclusion(owner="dns", change_ref="A1", paths=(), target=Target(), reason="x")


def test_conclusions_keep_current_and_devices_within_peak():
    assert RuleConclusion is Conclusion
    conclusion = Conclusion(
        statuses={"O1": ObligationStatus(status="satisfied", evidence_ids=("E2",))},
        peak="warning",
        current="info",
        findings=(Finding(text="Port went down", severity="warning", evidence_ids=("E2",)),),
        impacted_devices=(DeviceImpact(mac=MAC, severity="warning", evidence_ids=("E2",)),),
        gaps=("Neighbor AP state unavailable",),
    )
    assert conclusion.statuses["O1"].status == "satisfied"
    assert Conclusion().peak == "none"
    with pytest.raises(ValidationError, match="current"):
        Conclusion(peak="info", current="warning")
    with pytest.raises(ValidationError, match="peak"):
        Conclusion(peak="info", current="info", impacted_devices=(DeviceImpact(mac=MAC, severity="critical"),))
    with pytest.raises(ValidationError):
        Conclusion(statuses={"A1": ObligationStatus(status="satisfied")})


def test_agent_conclusions_either_report_or_explain_why_not():
    report = AgentConclusion(
        concluded=True, peak="warning", current="warning", confidence="medium", evidence_ids=("E3",)
    )
    assert report.reason is None
    skipped = AgentConclusion(concluded=False, reason="No AI runtime is configured")
    assert skipped.peak is None
    with pytest.raises(ValidationError):
        AgentConclusion(concluded=True, peak="warning", current="warning")
    with pytest.raises(ValidationError):
        AgentConclusion(concluded=True, peak="info", current="info", confidence="low", reason="late")
    with pytest.raises(ValidationError):
        AgentConclusion(concluded=False)
    with pytest.raises(ValidationError):
        AgentConclusion(concluded=False, reason="Provider failed", peak="info")
    with pytest.raises(ValidationError, match="current"):
        AgentConclusion(concluded=True, peak="info", current="critical", confidence="low")


def test_ledger_rows_resolve_to_one_of_three_outcomes():
    target = Target(device_mac=MAC)
    LedgerRow(atom_id="A1", target=target, resolution="claimed", obligation_ids=("O1",))
    LedgerRow(atom_id="A1", target=target, resolution="excluded")
    LedgerRow(atom_id="A1", target=target, resolution="uncovered", uncovered_paths=(("dns_suffix",),))
    with pytest.raises(ValidationError):
        LedgerRow(atom_id="A1", target=target, resolution="claimed")
    with pytest.raises(ValidationError):
        LedgerRow(atom_id="A1", target=target, resolution="excluded", obligation_ids=("O1",))
    with pytest.raises(ValidationError):
        LedgerRow(
            atom_id="A1",
            target=target,
            resolution="claimed",
            obligation_ids=("O1",),
            uncovered_paths=(("dns_suffix",),),
        )


def test_an_expected_device_is_one_mac_at_one_site():
    device = ExpectedDevice(mac=MAC, site_id=SITE)
    assert (device.mac, device.site_id) == (MAC, SITE)
    for values in ({"mac": "5C:5B:35:00:00:01", "site_id": SITE}, {"mac": MAC, "site_id": ""}, {"mac": MAC}):
        with pytest.raises(ValidationError):
            ExpectedDevice.model_validate(values)


def test_run_budget_is_capped_by_the_per_attempt_limits():
    assert RunBudget(model_turns=10, mcp_calls=7, rule_reads=8).model_turns == 10
    for field, over in (("model_turns", 11), ("mcp_calls", 8), ("rule_reads", 9)):
        with pytest.raises(ValidationError):
            RunBudget.model_validate({field: over})
    with pytest.raises(ValidationError):
        RunBudget(mcp_calls=-1)


def test_bound_reason_produces_single_line_bounded_text():
    assert bound_reason("Provider\ntimed out\t after 20 s ") == "Provider timed out after 20 s"
    long = bound_reason("x" * 1000)
    assert len(long) == MAX_REASON_CHARS
    assert long.endswith("…")
    assert bound_reason(long) == long
    assert bound_reason("\x00\n ") == "Unspecified failure"


def test_contracts_import_no_database_or_transport_modules():
    probe = (
        "import sys; import mist_config_guardian_backend.guardian.contracts; "
        "loaded = {'beanie', 'bson', 'pymongo', 'motor', 'httpx', 'fastapi'} & set(sys.modules); "
        "sys.exit(f'loaded: {sorted(loaded)}' if loaded else 0)"
    )
    subprocess.run([sys.executable, "-c", probe], check=True)  # noqa: S603 - fixed interpreter and probe
