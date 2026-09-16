"""A published verdict never drops below rule-derived disruption, and agent conclusions survive failed runs."""

from datetime import timedelta
from uuid import UUID, uuid4

import pytest

from mist_config_guardian_backend.impact import mcp_report
from mist_config_guardian_backend.impact.contracts import WlanAssessment
from mist_config_guardian_backend.impact.mcp_contracts import (
    McpCarriedConclusion,
    McpCheckpoint,
    McpConclusion,
    McpDeviceImpact,
    McpDispatch,
    McpEvidence,
)
from mist_config_guardian_backend.impact.mcp_report import build_mcp_report, compose_assessment
from mist_config_guardian_backend.impact.report import (
    MAX_DEVICE_IMPACTS,
    DeviceImpact,
    ImpactReport,
    ReportSection,
    ReportSections,
)
from mist_config_guardian_backend.services import impact_investigations as worker
from test_impact_change_context import MAC
from test_mcp_investigation import mcp_runtime
from test_wlan_investigation import LATER, NOW, SITE


def rule(impact):
    return WlanAssessment(
        policy_version="impact-domains.v1",
        audit_id="audit-one",
        evaluated_at=LATER,
        impact=impact,
        confidence="medium",
        coverage="partial",
        findings=(),
        gaps=("Rule gap.",),
    )


def agent(impact):
    return McpConclusion(
        summary="Agent summary.",
        scope="Changed switch.",
        impact=impact,
        confidence="low",
        coverage="complete" if impact == "none" else "partial",
        evidence=(uuid4(),),
        gaps=("Agent gap.",),
    )


@pytest.mark.parametrize(
    ("agent_impact", "rule_impact", "published", "source"),
    [
        ("warning", "info", "warning", "mcp_agent"),
        ("none", "info", "none", "mcp_agent"),
        ("info", "none", "info", "mcp_agent"),
        ("critical", "warning", "critical", "mcp_agent"),
        ("info", "warning", "warning", "combined"),
        ("none", "warning", "warning", "combined"),
        ("warning", "critical", "critical", "combined"),
    ],
)
def test_published_verdict_is_never_below_a_rule_disruption(agent_impact, rule_impact, published, source):
    checkpoint = McpCheckpoint(state="complete", conclusion=agent(agent_impact))
    assessment, verdict = compose_assessment("audit-one", LATER, checkpoint, rule(rule_impact))
    assert (assessment.impact, verdict) == (published, source)
    assert assessment.policy_version == "mcp-agent.v1"
    if source == "combined":
        assert (assessment.coverage, assessment.confidence) == ("partial", "medium")
        assert "Rule-derived impact exceeds the agent conclusion; the more severe verdict is published." in (
            assessment.gaps
        )


def test_agent_failure_publishes_the_rule_verdict_with_a_limitation():
    checkpoint = McpCheckpoint(state="deadline_exceeded", reason="Checkpoint time budget reached.")
    assessment, verdict = compose_assessment("audit-one", LATER, checkpoint, rule("warning"))
    assert (assessment.impact, assessment.policy_version, verdict) == ("warning", "impact-domains.v1", "rule")
    assert assessment.gaps == (
        "Rule gap.",
        "Rule-derived verdict: the AI agent did not conclude (Checkpoint time budget reached.).",
    )


def test_failed_run_uses_the_carried_agent_conclusion():
    carried = McpCarriedConclusion(source_revision=3, conclusion=agent("warning"))
    checkpoint = McpCheckpoint(state="provider_error", reason="AI provider request failed.", carried=carried)
    assessment, verdict = compose_assessment("audit-one", LATER, checkpoint, rule("info"))
    assert (assessment.impact, verdict) == ("warning", "mcp_agent")
    assert any("carried forward from revision 3" in gap for gap in assessment.gaps)
    assert any("AI provider request failed." in gap for gap in assessment.gaps)


async def test_later_failed_run_keeps_the_last_agent_devices(monkeypatch):
    service, root, _, artifacts, _ = mcp_runtime(monkeypatch)
    evidence = McpEvidence(
        id=uuid4(),
        tool="search_mist_data",
        arguments={"search_type": "device_events", "site_id": SITE},
        data={"results": [{"site_id": SITE, "mac": MAC, "type": "SW_PORT_DOWN"}]},
        state="partial",
        captured_at=LATER,
        schema_hash="test",
    )
    warning = McpConclusion(
        summary="Port-down events followed the change.",
        scope="Changed switch.",
        impact="warning",
        confidence="low",
        coverage="partial",
        evidence=(evidence.id,),
        impacted_devices=(
            McpDeviceImpact(
                device_mac=MAC,
                site_id=UUID(SITE),
                service="forwarding",
                impact="warning",
                evidence=(evidence.id,),
                explanation="Port-down evidence for this switch.",
            ),
        ),
    )
    outcomes = iter(
        [
            McpCheckpoint(state="complete", conclusion=warning, evidence=(evidence,)),
            McpCheckpoint(state="provider_error", reason="AI provider request failed; prior evidence is retained."),
        ]
    )

    async def fake_run(_self, _root, **_kwargs):
        return next(outcomes)

    monkeypatch.setattr(worker.McpImpactAgent, "run_mcp", fake_run)
    for minutes in (10, 30):
        now = NOW + timedelta(minutes=minutes)
        monkeypatch.setattr(worker, "utc_now", lambda now=now: now)
        await service._poll(root)  # noqa: SLF001
        root.report_id, root.revision = artifacts[-1].id, artifacts[-1].revision
    latest = artifacts[-1]
    assert latest.mcp.state == "provider_error"
    assert latest.mcp.carried.conclusion == warning
    assert latest.mcp.carried.evidence == (evidence,)
    assert latest.assessment.impact == "warning"
    assert latest.report.verdict_source == "mcp_agent"
    assert latest.report.current_impact == "warning"
    assert [d.device_mac for d in latest.report.impacted_devices] == [MAC]
    assert str(evidence.id) in {d.target_handle for d in latest.report.datasets}


def port_row(port, impact):
    return DeviceImpact(
        device_mac=MAC,
        site_id=UUID(SITE),
        role="affected_switch_port",
        service="port_link",
        target_handle=f"port-handle-{port}",
        port_id=port,
        impact=impact,
        current_impact=impact,
        confidence="medium",
    )


def rule_report(devices):
    section = ReportSection(state="available", explanation="Recorded in this immutable revision.")
    return ImpactReport(
        investigation_id="investigation-one",
        audit_id="audit-one",
        revision=1,
        generated_at=LATER,
        evidence_as_of=LATER,
        peak_impact="critical",
        peak_revision=1,
        peak_confidence="medium",
        history_complete=True,
        current_impact="critical",
        confidence="medium",
        coverage="partial",
        attribution="plausible",
        sections=ReportSections(**dict.fromkeys(ReportSections.model_fields, section)),
        datasets=(),
        impacted_devices=devices,
        gaps=(),
    )


@pytest.mark.parametrize("source", ["rule", "combined"])
def test_every_rule_device_row_reaches_the_mcp_report(source):
    rows = (port_row("ge-0/0/1", "warning"), port_row("ge-0/0/2", "critical"))
    cited = uuid4()
    conclusion = McpConclusion(
        summary="Port flaps were returned.",
        scope="Changed switch.",
        impact="warning",
        confidence="low",
        coverage="partial",
        evidence=(cited,),
        impacted_devices=(
            McpDeviceImpact(
                device_mac=MAC,
                site_id=UUID(SITE),
                service="port_link",
                impact="warning",
                evidence=(cited,),
                explanation="Same switch and service as both rule rows.",
            ),
        ),
    )
    checkpoint = (
        McpCheckpoint(state="complete", conclusion=conclusion)
        if source == "combined"
        else McpCheckpoint(state="provider_error", reason="AI provider request failed.")
    )
    report = build_mcp_report(rule_report(rows), checkpoint, source)
    rule_rows = [(d.port_id, d.impact) for d in report.impacted_devices if d.role == "affected_switch_port"]
    assert rule_rows == [("ge-0/0/1", "warning"), ("ge-0/0/2", "critical")]
    agent_rows = [d.target_handle for d in report.impacted_devices if d.role == "agent_observed_service"]
    assert agent_rows == ([str(cited)] if source == "combined" else [])
    assert report.omitted_device_impacts == 0


def agent_conclusion_rows(count, cited, impact="warning"):
    """One agent row per device, all citing the same evidence, so every row is a distinct merge key."""
    return McpConclusion(
        summary="Agent summary.",
        scope="Changed switch.",
        impact=impact,
        confidence="low",
        coverage="partial",
        evidence=(cited,),
        impacted_devices=tuple(
            McpDeviceImpact(
                device_mac=f"aabbccdd{n:04x}",
                site_id=UUID(SITE),
                service="port_link",
                impact=impact,
                evidence=(cited,),
                explanation="Observed on the changed switch.",
            )
            for n in range(count)
        ),
    )


def capped_rule_rows():
    return tuple(port_row(f"ge-0/0/{n}", "critical") for n in range(MAX_DEVICE_IMPACTS))


@pytest.mark.parametrize("source", ["rule", "combined"])
def test_rule_rows_win_the_device_cap_and_dropped_agent_rows_are_counted(source):
    checkpoint = McpCheckpoint(state="complete", conclusion=agent_conclusion_rows(50, uuid4()))
    report = build_mcp_report(rule_report(capped_rule_rows()), checkpoint, source)
    # A rule-derived verdict is justified by its own rows; lower-severity agent rows never evict them.
    assert [d.port_id for d in report.impacted_devices] == [f"ge-0/0/{n}" for n in range(MAX_DEVICE_IMPACTS)]
    assert report.omitted_device_impacts == 50


def test_reported_omissions_include_the_base_report_count():
    base = rule_report(capped_rule_rows()).model_copy(update={"omitted_device_impacts": 7})
    checkpoint = McpCheckpoint(state="complete", conclusion=agent_conclusion_rows(50, uuid4()))
    report = build_mcp_report(base, checkpoint, "combined")
    assert report.omitted_device_impacts == 57
    assert build_mcp_report(base, checkpoint, "mcp_agent").omitted_device_impacts == 7


def test_agent_verdict_keeps_its_own_rows():
    checkpoint = McpCheckpoint(state="complete", conclusion=agent_conclusion_rows(50, uuid4()))
    report = build_mcp_report(rule_report(capped_rule_rows()), checkpoint, "mcp_agent")
    assert len(report.impacted_devices) == 50
    assert {d.role for d in report.impacted_devices} == {"agent_observed_service"}
    assert report.omitted_device_impacts == 0


def test_same_key_from_both_sources_yields_one_row_from_the_verdict_source():
    cited = uuid4()
    same_key = DeviceImpact(
        device_mac="aabbccdd0000",
        site_id=UUID(SITE),
        role="agent_observed_service",
        service="port_link",
        target_handle=str(cited),
        impact="critical",
        current_impact="critical",
        confidence="medium",
    )
    checkpoint = McpCheckpoint(state="complete", conclusion=agent_conclusion_rows(1, cited))
    report = build_mcp_report(rule_report((same_key,)), checkpoint, "combined")
    assert len(report.impacted_devices) == 1
    # The combined verdict publishes the rule-derived severity, so the rule row is the one kept.
    assert report.impacted_devices[0].impact == "critical"
    assert report.omitted_device_impacts == 0
    agent_only = build_mcp_report(rule_report((same_key,)), checkpoint, "mcp_agent")
    assert [d.impact for d in agent_only.impacted_devices] == ["warning"]


def complete_none_run():
    evidence = McpEvidence(
        id=uuid4(),
        tool="search_mist_data",
        arguments={"search_type": "device_events", "site_id": SITE},
        data={"results": []},
        state="complete",
        captured_at=LATER,
        schema_hash="test",
    )
    conclusion = McpConclusion(
        summary="No disruption was returned.",
        scope="Changed switch.",
        impact="none",
        confidence="low",
        coverage="complete",
        evidence=(evidence.id,),
    )
    return McpCheckpoint(state="complete", conclusion=conclusion, evidence=(evidence,))


@pytest.mark.parametrize("state", ["not_scheduled", "provider_error"])
def test_final_checkpoint_never_claims_complete_coverage_from_a_carried_conclusion(state):
    carried = McpCarriedConclusion(source_revision=2, conclusion=complete_none_run().conclusion)
    checkpoint = McpCheckpoint(state=state, reason="Guardian reason.", carried=carried)
    ongoing, _ = compose_assessment("audit-one", LATER, checkpoint, rule("info"))
    final, verdict = compose_assessment("audit-one", LATER, checkpoint, rule("info"), final=True)
    assert (ongoing.coverage, ongoing.impact) == ("complete", "none")
    # Partial coverage cannot publish a clean outcome.
    assert (final.coverage, final.impact, verdict) == ("partial", "info", "mcp_agent")
    assert any("carried from revision 2" in gap for gap in final.gaps)
    this_run, _ = compose_assessment("audit-one", LATER, complete_none_run(), rule("info"), final=True)
    assert this_run.coverage == "complete"


async def test_expiry_checkpoint_without_a_due_agent_run_finishes_incomplete(monkeypatch):
    service, root, collection, artifacts, _ = mcp_runtime(monkeypatch)
    runs = []

    async def fake_run(_self, _root, **kwargs):
        runs.append(kwargs["as_of"])
        return complete_none_run()

    monkeypatch.setattr(worker.McpImpactAgent, "run_mcp", fake_run)
    now = NOW + timedelta(minutes=30)
    monkeypatch.setattr(worker, "utc_now", lambda: now)
    await service._poll(root)  # noqa: SLF001
    root.report_id, root.revision = artifacts[-1].id, artifacts[-1].revision
    # A worker spent the +60 band, then lost its lease before publishing (crash guard).
    root.mcp_dispatches = [
        McpDispatch(
            id=uuid4(),
            generation=root.generation - 1,
            candidate_revision=root.revision + 1,
            tool="tools/list",
            arguments_hash="h",
            reserved_at=NOW + timedelta(minutes=60, seconds=5),
        )
    ]
    now = NOW + timedelta(minutes=61)
    monkeypatch.setattr(worker, "utc_now", lambda: now)
    await service._poll(root)  # noqa: SLF001
    assert runs == [NOW + timedelta(minutes=30)]
    final = artifacts[-1]
    assert (final.mcp.state, final.mcp.carried.source_revision) == ("not_scheduled", artifacts[0].revision)
    assert (final.assessment.impact, final.assessment.coverage) == ("info", "partial")
    assert (final.report.coverage, final.report.current_impact, final.report.peak_impact) == ("partial", "info", "info")
    assert any(f"carried from revision {artifacts[0].revision}" in gap for gap in final.assessment.gaps)
    assert collection.update_one.await_args_list[-1].args[1]["$set"]["status"] == "incomplete"


@pytest.mark.parametrize("rule_impact", ["none", "info"])
async def test_final_rule_derived_checkpoint_never_completes_the_investigation(monkeypatch, rule_impact):
    checkpoint = McpCheckpoint(state="provider_error", reason="AI provider request failed.")
    complete_rule = rule(rule_impact).model_copy(update={"coverage": "complete"})
    ongoing, _ = compose_assessment("audit-one", LATER, checkpoint, complete_rule)
    assert (ongoing.coverage, ongoing.impact) == ("complete", rule_impact)
    final_rule, _ = compose_assessment("audit-one", LATER, checkpoint, complete_rule, final=True)
    # Forced partial coverage cannot publish a clean outcome.
    assert (final_rule.coverage, final_rule.impact) == ("partial", "info")
    service, root, collection, artifacts, _ = mcp_runtime(monkeypatch)
    compose_domains = worker.compose_domains
    monkeypatch.setattr(
        worker,
        "compose_domains",
        lambda *args: compose_domains(*args).model_copy(update={"coverage": "complete", "impact": rule_impact}),
    )

    async def fake_run(_self, _root, **_kwargs):
        return McpCheckpoint(state="provider_error", reason="AI provider request failed; prior evidence is retained.")

    monkeypatch.setattr(worker.McpImpactAgent, "run_mcp", fake_run)
    now = NOW + timedelta(minutes=61)
    monkeypatch.setattr(worker, "utc_now", lambda: now)
    await service._poll(root)  # noqa: SLF001
    final = artifacts[-1]
    assert (final.mcp.state, final.mcp.carried) == ("provider_error", None)
    assert final.deterministic_assessment.coverage == "complete"
    assert (final.assessment.coverage, final.report.coverage, final.report.verdict_source) == (
        "partial",
        "partial",
        "rule",
    )
    assert (final.assessment.impact, final.report.current_impact, final.report.peak_impact) == ("info", "info", "info")
    assert (
        "Rule-derived verdict: the AI agent did not conclude (AI provider request failed; prior evidence is retained.)."
        in final.assessment.gaps
    )
    assert collection.update_one.await_args_list[-1].args[1]["$set"]["status"] == "incomplete"


@pytest.mark.parametrize("rule_impact", ["none", "info"])
async def test_final_carried_none_is_published_as_info_with_partial_coverage(monkeypatch, rule_impact):
    """+10 concludes none/complete; the +30 and +60 runs fail, so the final checkpoint only carries it."""
    service, root, collection, artifacts, _ = mcp_runtime(monkeypatch)
    compose_domains = worker.compose_domains
    monkeypatch.setattr(
        worker, "compose_domains", lambda *args: compose_domains(*args).model_copy(update={"impact": rule_impact})
    )
    failed = McpCheckpoint(state="provider_error", reason="AI provider request failed; prior evidence is retained.")
    outcomes = iter([complete_none_run(), failed, failed])

    async def fake_run(_self, _root, **_kwargs):
        return next(outcomes)

    monkeypatch.setattr(worker.McpImpactAgent, "run_mcp", fake_run)
    for minutes in (10, 30, 61):
        now = NOW + timedelta(minutes=minutes)
        monkeypatch.setattr(worker, "utc_now", lambda now=now: now)
        await service._poll(root)  # noqa: SLF001
        root.report_id, root.revision = artifacts[-1].id, artifacts[-1].revision
    ran, ongoing, final = artifacts
    # Non-final checkpoints with a complete none conclusion (own or carried) still publish none.
    for artifact in (ran, ongoing):
        assert (artifact.assessment.impact, artifact.assessment.coverage) == ("none", "complete")
        assert (artifact.report.current_impact, artifact.report.verdict_source) == ("none", "mcp_agent")
    assert (final.mcp.state, final.mcp.carried.source_revision) == ("provider_error", ran.revision)
    assert (final.assessment.impact, final.assessment.coverage) == ("info", "partial")
    assert (final.report.current_impact, final.report.peak_impact, final.report.coverage) == ("info", "info", "partial")
    assert final.report.verdict_source == "mcp_agent"
    assert any(f"carried from revision {ran.revision}" in gap for gap in final.assessment.gaps)
    assert collection.update_one.await_args_list[-1].args[1]["$set"]["status"] == "incomplete"


@pytest.mark.parametrize("rule_impact", ["none", "info"])
def test_non_final_complete_none_is_published_as_none(rule_impact):
    checkpoint = complete_none_run()
    assessment, verdict = compose_assessment("audit-one", LATER, checkpoint, rule(rule_impact))
    assert (assessment.impact, assessment.coverage, verdict) == ("none", "complete", "mcp_agent")
    assert not any("clean outcome" in gap for gap in assessment.gaps)
    base = rule_report(()).model_copy(
        update={"coverage": "complete", "current_impact": "info", "peak_impact": "none", "attribution": "undetermined"}
    )
    assert build_mcp_report(base, checkpoint, verdict).current_impact == "none"


def test_rule_none_with_partial_coverage_is_published_as_info_with_a_limitation():
    checkpoint = McpCheckpoint(state="provider_error", reason="AI provider request failed.")
    assessment, verdict = compose_assessment("audit-one", LATER, checkpoint, rule("none"))
    assert (assessment.impact, assessment.coverage, verdict) == ("info", "partial", "rule")
    assert mcp_report.CLEAN_OUTCOME_GAP in assessment.gaps
    base = rule_report(()).model_copy(update={"current_impact": "none", "peak_impact": "none"})
    assert build_mcp_report(base, checkpoint, verdict).current_impact == "info"


async def test_expiry_checkpoint_with_a_due_complete_agent_run_still_completes(monkeypatch):
    service, root, collection, artifacts, _ = mcp_runtime(monkeypatch)

    async def fake_run(_self, _root, **_kwargs):
        return complete_none_run()

    monkeypatch.setattr(worker.McpImpactAgent, "run_mcp", fake_run)
    for minutes in (30, 61):
        now = NOW + timedelta(minutes=minutes)
        monkeypatch.setattr(worker, "utc_now", lambda now=now: now)
        await service._poll(root)  # noqa: SLF001
        root.report_id, root.revision = artifacts[-1].id, artifacts[-1].revision
    assert (artifacts[-1].mcp.state, artifacts[-1].assessment.coverage) == ("complete", "complete")
    assert artifacts[-1].report.verdict_source == "mcp_agent"
    assert collection.update_one.await_args_list[-1].args[1]["$set"]["status"] == "completed"
