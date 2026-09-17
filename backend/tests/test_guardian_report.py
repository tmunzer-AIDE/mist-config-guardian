"""Guardian's report: one pure builder that renders a run, and nothing else.

Every section comes from the immutable run document. An empty section explains itself from that same state, so no
sentence here is a fixed string that could outlive the facts behind it. The last test builds the worst-case run
every budget allows and checks it against the 256 KB run-document bound.
"""

from datetime import UTC, datetime, timedelta

import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.guardian.contracts import (
    RUN_DOCUMENT_MAX_BYTES,
    AgentConclusion,
    ChangeAtom,
    CompactImpactedDevice,
    Conclusion,
    DeviceImpact,
    Evidence,
    Finding,
    Gap,
    LedgerRow,
    Obligation,
    ObligationOutcome,
    ObligationStatus,
    RunAnchor,
    RunBudget,
    Target,
    Verdict,
)
from mist_config_guardian_backend.guardian.evidence import (
    CONCLUSIONS_BUDGET,
    IMPACTED_DEVICES_BUDGET,
    LEDGER_VIEW_BUDGET,
    MODEL_OUTPUT_BUDGET,
    json_size,
)
from mist_config_guardian_backend.guardian.monitoring import ComponentSeverity, DeviceMonitoring
from mist_config_guardian_backend.guardian.report import DISPLAY_ROWS, render_report
from mist_config_guardian_backend.models.guardian import GuardianRun, check_run_document_size


@pytest.fixture(autouse=True)
def _validate_without_mongo(monkeypatch):
    # Beanie refuses to build a document before init_beanie; the report builder only reads one.
    monkeypatch.setattr(GuardianRun, "get_pymongo_collection", lambda *_: None)


NOW = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)
TOKEN = PydanticObjectId()
ORG = PydanticObjectId()
ROOT = PydanticObjectId()
SITE = "978c48e6-6ef6-11e6-8bbf-02e208b2d34f"
MAC = "5c5b35000001"
# Monitoring, deployment, eight rule reads and seven MCP calls, each at its own aggregate budget.
EVIDENCE_BUDGET = 18_000 + 4_000 + 8 * 4_000 + 7 * 4_000


def atom(identity: str = "A1") -> ChangeAtom:
    return ChangeAtom(
        id=identity,
        logical_object_id="networktemplate:1",
        version=3,
        attribute="dns_servers",
        paths=(("dns_servers", "0"),),
        paths_complete=True,
    )


def monitoring_item(identity: str = "E1", mac: str = MAC, **device) -> Evidence:
    values = {
        "mac": mac,
        "site_id": SITE,
        "name": "ap-1",
        "status": "unsatisfied",
        "exclusive": True,
        "terminal": True,
        "peak": "warning",
        "current": "none",
        "deployment": "configured",
        "deployment_precondition": "satisfied",
        "metrics": ComponentSeverity(peak="warning", current="none"),
    }
    row = DeviceMonitoring.model_validate(values | device)
    return Evidence(
        id=identity,
        source="monitoring",
        kind="service_health",
        title=f"Monitoring {row.name}",
        captured_at=NOW,
        scope={"site_ids": (SITE,), "device_macs": (mac,)},
        collection="complete",
        representation="full",
        payload=row.model_dump(mode="json"),
    )


def digest_item(identity: str = "E2", **counts) -> Evidence:
    return Evidence(
        id=identity,
        source="monitoring",
        kind="service_health",
        title="Monitoring digest",
        captured_at=NOW,
        collection="complete",
        representation="digest",
        payload={"devices": counts or {"satisfied:none": 4}},
        detail="Devices beyond the monitoring evidence budget",
    )


def verdict(**overrides) -> Verdict:
    values = {
        "peak": "warning",
        "current": "none",
        "recovery": "recovered",
        "confidence": "low",
        "coverage": "complete",
        "sources": ("monitoring",),
        "summary": "Peak impact warning (coverage complete); current none; 1 impacted device.",
        "impacted_devices": (
            CompactImpactedDevice(mac=MAC, site_id=SITE, name="ap-1", peak="warning", current="none"),
        ),
    }
    return Verdict.model_validate(values | overrides)


def run(**overrides) -> GuardianRun:
    values = {
        "id": TOKEN,
        "organization_id": ORG,
        "investigation_id": ROOT,
        "audit_id": "audit-1",
        "kind": "final",
        "attempt": 1,
        "state": "succeeded",
        "started_at": NOW,
        "finished_at": NOW + timedelta(seconds=90),
        "anchor": RunAnchor(changed_at=NOW, source="audit"),
        "as_of": NOW + timedelta(minutes=60),
        "change": (atom(),),
        "evidence": (monitoring_item(),),
        "ledger": (
            LedgerRow(
                atom_id="A1", target=Target(device_mac=MAC, site_id=SITE), resolution="claimed", obligation_ids=("O1",)
            ),
        ),
        "obligations": (
            ObligationOutcome(
                obligation=Obligation(
                    id="O1",
                    owner="dns",
                    change_ref="A1",
                    paths=(("dns_servers",),),
                    role="observation",
                    kind="monitoring",
                    target=Target(device_mac=MAC, site_id=SITE),
                    metric="time-to-connect",
                    empty_policy="incomplete",
                ),
                status=ObligationStatus(status="unsatisfied", reason="No data in either window", evidence_ids=("E1",)),
            ),
        ),
        "monitoring": Conclusion(peak="warning", current="none", gaps=("shared session",)),
        "deployment": Conclusion(),
        "rules": {},
        "agent": None,
        "verdict": verdict(),
        "budget": RunBudget(model_turns=3, mcp_calls=2, rule_reads=1),
    }
    return GuardianRun.model_validate(values | overrides)


# --- header, summary and the run itself -------------------------------------------------------------------------


def test_the_header_is_the_composed_verdict() -> None:
    report = render_report(run())

    assert report.header is not None
    assert (report.header.peak, report.header.current, report.header.recovery) == ("warning", "none", "recovered")
    assert (report.header.confidence, report.header.coverage) == ("low", "complete")
    assert report.header.sources == ("monitoring",)
    assert report.header_note is None


def test_a_failed_run_renders_without_a_header_and_says_why() -> None:
    failed = run(state="failed", verdict=None, failure_reason="Provider timed out")

    report = render_report(failed)

    assert report.header is None
    assert report.header_note is not None
    assert "Provider timed out" in report.header_note
    assert (report.run.state, report.run.failure_reason) == ("failed", "Provider timed out")


def test_the_summary_pairs_the_deterministic_sentence_with_the_ai_one() -> None:
    concluded = AgentConclusion(
        concluded=True, peak="warning", current="none", confidence="low", summary="Clients reconnected."
    )

    report = render_report(run(agent=concluded))

    assert report.summary.deterministic == verdict().summary
    assert report.summary.ai == "Clients reconnected."
    assert report.summary.ai_note is None


def test_an_agent_that_did_not_conclude_leaves_its_reason_instead_of_a_summary() -> None:
    report = render_report(run(agent=AgentConclusion(concluded=False, reason="No MCP endpoint is configured")))

    assert report.summary.ai is None
    assert report.summary.ai_note is not None
    assert "No MCP endpoint is configured" in report.summary.ai_note


def test_no_agent_record_is_explained_as_one() -> None:
    report = render_report(run(agent=None))

    assert report.summary.ai is None
    assert report.summary.ai_note is not None


# --- the sections -----------------------------------------------------------------------------------------------


def test_the_change_section_lists_the_atoms_with_their_paths() -> None:
    report = render_report(run())

    assert [row.id for row in report.change.items] == ["A1"]
    assert report.change.items[0].paths == (("dns_servers", "0"),)
    assert report.change.explanation is None


def test_the_coverage_section_lists_rows_and_obligation_statuses() -> None:
    report = render_report(run())

    assert report.coverage.coverage == "complete"
    assert [row.atom_id for row in report.coverage.rows.items] == ["A1"]
    assert [row.status.status for row in report.coverage.obligations.items] == ["unsatisfied"]


def test_the_devices_section_reads_the_monitoring_items_and_counts_the_digest() -> None:
    report = render_report(run(evidence=(monitoring_item(), digest_item(**{"satisfied:none": 7}))))

    assert [device.mac for device in report.devices.items] == [MAC]
    assert (report.devices.items[0].deployment, report.devices.items[0].peak) == ("configured", "warning")
    assert report.devices.omitted == 7


def test_the_findings_section_names_the_source_of_every_finding() -> None:
    rules = {
        "switch-port": Conclusion(
            peak="warning",
            current="warning",
            findings=(Finding(text="Port 5 went down", severity="warning", evidence_ids=("E1",)),),
        )
    }
    agent = AgentConclusion(
        concluded=True,
        peak="warning",
        current="none",
        confidence="low",
        findings=(Finding(text="Clients roamed away", severity="info", evidence_ids=("E1",)),),
    )

    report = render_report(run(rules=rules, agent=agent))

    assert [(row.source, row.severity) for row in report.findings.items] == [
        ("rule:switch-port", "warning"),
        ("agent", "info"),
    ]


def test_the_evidence_section_tabulates_kind_collection_and_representation() -> None:
    failed = Evidence(
        id="E2",
        source="mcp:search_mist_data",
        kind="service_health",
        title="search_mist_data device_events",
        captured_at=NOW,
        collection="error",
        representation="full",
        detail="The tool reported an error.",
    )

    report = render_report(run(evidence=(monitoring_item(), failed)))

    assert [(row.id, row.kind, row.collection, row.citable) for row in report.evidence.items] == [
        ("E1", "service_health", "complete", True),
        ("E2", "service_health", "error", False),
    ]


def test_the_gaps_section_keeps_every_gap_with_its_source() -> None:
    report = render_report(run(verdict=verdict(gaps=(Gap(source="monitoring", text="shared session"),))))

    assert [(gap.source, gap.text) for gap in report.gaps.items] == [("monitoring", "shared session")]


def test_a_run_without_a_verdict_still_shows_the_gaps_its_conclusions_recorded() -> None:
    failed = run(state="failed", verdict=None, failure_reason="Provider timed out")

    report = render_report(failed)

    assert [(gap.source, gap.text) for gap in report.gaps.items] == [("monitoring", "shared session")]


def test_the_impacted_devices_of_the_verdict_are_shown_with_their_omitted_count() -> None:
    report = render_report(run(verdict=verdict(impacted_devices_omitted=4)))

    assert [row.mac for row in report.impacted.items] == [MAC]
    assert report.impacted.omitted == 4


# --- empty sections explain themselves from state -----------------------------------------------------------------


@pytest.mark.parametrize(
    "section",
    ["change", "devices", "findings", "evidence", "gaps", "impacted"],
)
def test_every_empty_section_explains_itself(section) -> None:
    empty = run(
        change=(),
        evidence=(),
        ledger=(),
        obligations=(),
        monitoring=None,
        deployment=None,
        verdict=verdict(gaps=(), impacted_devices=()),
    )

    report = render_report(empty)
    rendered = getattr(report, section)

    assert rendered.items == ()
    assert rendered.explanation is not None
    assert rendered.explanation.endswith(".")


def test_an_empty_section_explains_the_state_behind_it_rather_than_a_fixed_sentence() -> None:
    without_agent = render_report(run(rules={}, agent=None, monitoring=Conclusion()))
    without_conclusion = render_report(
        run(
            rules={},
            agent=AgentConclusion(concluded=False, reason="No MCP endpoint is configured"),
            monitoring=Conclusion(),
        )
    )

    assert without_agent.findings.explanation != without_conclusion.findings.explanation
    assert "No MCP endpoint is configured" in (without_conclusion.findings.explanation or "")


def test_the_evidence_explanation_counts_the_reads_the_attempt_made() -> None:
    report = render_report(run(evidence=(), budget=RunBudget(rule_reads=3, mcp_calls=2)))

    assert "3" in (report.evidence.explanation or "")
    assert "2" in (report.evidence.explanation or "")


def test_the_devices_explanation_distinguishes_a_missing_replay_from_an_empty_one() -> None:
    missing = render_report(run(evidence=(), monitoring=None))
    empty = render_report(run(evidence=(), monitoring=Conclusion()))

    assert missing.devices.explanation != empty.devices.explanation


# --- display limits ------------------------------------------------------------------------------------------------


def test_every_section_stops_at_its_display_limit_and_counts_the_rest() -> None:
    atoms = tuple(atom(f"A{index + 1}") for index in range(DISPLAY_ROWS + 7))

    report = render_report(run(change=atoms))

    assert len(report.change.items) == DISPLAY_ROWS
    assert report.change.omitted == 7


# --- the run-document bound ------------------------------------------------------------------------------------------


def worst_case_run() -> GuardianRun:
    """Every stored source at its budget, as the design's limits table allows one attempt to fill them.

    The conclusions here are deliberately well above their own 8 KB budget, so the bound is checked against more
    than any attempt can actually store.
    """
    evidence = (
        *(_padded(f"E{index + 1}", "monitoring", 1_800) for index in range(10)),
        _padded("E11", "deployment", 4_000, kind="deployment"),
        *(_padded(f"E{12 + index}", "rule:switch-port", 4_000) for index in range(8)),
        *(_padded(f"E{20 + index}", "mcp:search_mist_data", 4_000) for index in range(7)),
    )
    rows: list[LedgerRow] = []
    outcomes: list[ObligationOutcome] = []
    while json_size(tuple(rows)) + json_size(tuple(outcomes)) < LEDGER_VIEW_BUDGET:
        index = len(rows) + 1
        target = Target(device_mac=f"5c5b35{index:06d}", site_id=SITE)
        rows.append(LedgerRow(atom_id="A1", target=target, resolution="claimed", obligation_ids=(f"O{index}",)))
        outcomes.append(
            ObligationOutcome(
                obligation=Obligation(
                    id=f"O{index}",
                    owner="dns",
                    change_ref="A1",
                    paths=(("dns_servers",),),
                    role="observation",
                    kind="monitoring",
                    target=target,
                    metric="time-to-connect",
                    empty_policy="incomplete",
                ),
                status=ObligationStatus(status="unsatisfied", reason="No data in either window", evidence_ids=("E1",)),
            )
        )
    devices: list[CompactImpactedDevice] = []
    while json_size(tuple(devices)) < IMPACTED_DEVICES_BUDGET:
        devices.append(
            CompactImpactedDevice(
                mac=f"5c5b35{len(devices):06d}", site_id=SITE, name="n" * 40, peak="warning", current="warning"
            )
        )
    conclusion = Conclusion(
        peak="warning",
        current="warning",
        findings=tuple(Finding(text="f" * 400, severity="warning", evidence_ids=("E1",)) for _ in range(4)),
        impacted_devices=tuple(
            DeviceImpact(mac=device.mac, severity="warning", evidence_ids=("E1",)) for device in devices[:20]
        ),
    )
    rules = dict.fromkeys(("dns", "switch-port", "wlan-auth", "wlan-removal"), conclusion)
    steps = tuple(
        {
            "turn": index + 1,
            "action": "call",
            "output": "y" * MODEL_OUTPUT_BUDGET,
            "prompt_hash": "0" * 64,
            "prompt_size": 95_000,
            "visible_evidence_ids": [f"E{number + 1}" for number in range(26)],
            "withheld_evidence_ids": ["E25", "E26"],
        }
        for index in range(10)
    )
    return run(
        change=tuple(atom(f"A{index + 1}") for index in range(40)),
        evidence=evidence,
        ledger=tuple(rows),
        obligations=tuple(outcomes),
        monitoring=conclusion,
        deployment=conclusion,
        rules=rules,
        agent=AgentConclusion(
            concluded=True,
            peak="warning",
            current="warning",
            confidence="low",
            summary="s" * 2_000,
            evidence_ids=tuple(f"E{index + 1}" for index in range(20)),
            findings=conclusion.findings,
            impacted_devices=conclusion.impacted_devices,
        ),
        verdict=verdict(
            peak="warning",
            current="warning",
            recovery="unrecovered",
            impacted_devices=tuple(devices),
            impacted_devices_omitted=900,
            gaps=tuple(Gap(source="core", text="g" * 400) for _ in range(40)),
        ),
        steps=steps,
        budget=RunBudget(model_turns=10, mcp_calls=7, rule_reads=8),
    )


def _padded(identity: str, source: str, size: int, kind: str = "service_health") -> Evidence:
    item = Evidence(
        id=identity,
        source=source,
        kind=kind,
        title="t" * 100,
        captured_at=NOW,
        scope={"site_ids": (SITE,), "device_macs": (MAC,)},
        collection="complete",
        representation="full",
        payload={"rows": "x"},
    )
    return item.model_copy(update={"payload": {"rows": "x" * max(size - json_size(item), 0)}})


def test_a_worst_case_run_stays_within_the_run_document_bound() -> None:
    worst = worst_case_run()
    conclusions = json_size((worst.monitoring, worst.deployment, worst.rules, worst.agent))

    assert json_size(worst.evidence) >= EVIDENCE_BUDGET
    assert json_size(worst.ledger) + json_size(worst.obligations) >= LEDGER_VIEW_BUDGET
    assert worst.verdict is not None
    assert json_size(worst.verdict.impacted_devices) >= IMPACTED_DEVICES_BUDGET
    assert json_size(worst.steps) >= 10 * MODEL_OUTPUT_BUDGET
    assert conclusions > CONCLUSIONS_BUDGET
    assert check_run_document_size(worst) <= RUN_DOCUMENT_MAX_BYTES


def test_a_worst_case_run_renders_a_bounded_report() -> None:
    report = render_report(worst_case_run())

    assert len(report.evidence.items) == 26
    assert 0 < len(report.coverage.rows.items) <= DISPLAY_ROWS
    assert len(report.gaps.items) > 1
    assert report.header is not None
