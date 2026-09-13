"""Presentation retains uncertainty, exact publication identity and evidence counts."""

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from beanie import PydanticObjectId
from pydantic import ValidationError

from mist_config_guardian_backend.impact.contracts import (
    AuthEventRow,
    AuthEvidence,
    SessionEvidence,
    SessionRow,
    Window,
)
from mist_config_guardian_backend.impact.report import ImpactReport, build_report
from mist_config_guardian_backend.impact.wlan_removal import compile_wlan_removal, evaluate_wlan_removal
from mist_config_guardian_backend.models.investigation import InvestigationRevision
from mist_config_guardian_backend.services import investigation_reads
from test_impact_investigation_runtime import setup_runtime
from test_wlan_investigation import LATER, NOW, ORG, inputs


def report_inputs():
    plan = compile_wlan_removal(**inputs())
    baseline = SessionEvidence(
        target_handle=plan.targets[0].handle,
        window=Window(start=NOW - timedelta(hours=1), end=NOW),
        captured_at=LATER,
        state="complete",
    )
    follow = baseline.model_copy(update={"window": Window(start=NOW, end=LATER)})
    evidence = [baseline, follow]
    return {
        "investigation_id": str(PydanticObjectId()),
        "revision": 1,
        "generated_at": LATER,
        "plan": plan,
        "assessment": evaluate_wlan_removal(plan, evidence, evidence_as_of=LATER),
        "evidence": evidence,
    }


def test_fixed_contract_empty_sample_is_not_a_fleet_denominator():
    report = build_report(**report_inputs())
    assert report.current_impact == "none"
    assert len(report.sections.model_dump()) == 8
    assert report.datasets[0].rows == ()
    assert report.impacted_devices == ()
    assert report.device_coverage == "observed_only"
    assert "client_mac" not in report.model_dump_json()
    assert ImpactReport.model_validate_json(report.model_dump_json()) == report


def test_client_bars_dedup_sessions_and_never_claim_ap_failure():
    data = report_inputs()
    row = SessionRow(
        client_mac="001122334455",
        ap_mac="aabbccddeeff",
        connected_at=NOW - timedelta(minutes=10),
        disconnected_at=NOW + timedelta(minutes=1),
    )
    data["evidence"] = [e.model_copy(update={"rows": (row, row)}) for e in data["evidence"]]
    data["assessment"] = evaluate_wlan_removal(data["plan"], data["evidence"], evidence_as_of=LATER)
    report = build_report(**data)
    assert report.datasets[0].rows == ((row.ap_mac, 1),)
    assert len(report.impacted_devices) == 1
    assert report.impacted_devices[0].role == "serving_affected_clients"
    assert report.impacted_devices[0].device_failure == "not_established"
    assert row.client_mac not in report.model_dump_json()


def test_peak_survives_missing_current_evidence_with_original_confidence():
    data = report_inputs()
    data["assessment"] = data["assessment"].model_copy(update={"impact": "critical", "confidence": "medium"})
    previous = build_report(**data)
    data.update(revision=2, previous=previous)
    data["assessment"] = data["assessment"].model_copy(
        update={"impact": "info", "coverage": "partial", "confidence": "low"}
    )
    report = build_report(**data)
    assert (report.peak_impact, report.peak_revision, report.peak_confidence) == ("critical", 1, "medium")
    assert (report.current_impact, report.confidence) == ("info", "low")
    data["investigation_id"] = str(PydanticObjectId())
    with pytest.raises(ValueError, match="publication chain"):
        build_report(**data)


def test_histogram_counts_events_not_clients_and_preserves_partial_state():
    data = report_inputs()
    history = AuthEvidence(
        target_handle=data["plan"].targets[0].handle,
        window=Window(start=NOW - timedelta(hours=1), end=LATER),
        captured_at=LATER,
        state="partial",
        rows=tuple(
            AuthEventRow(client_handle="a" * 64, occurred_at=NOW + timedelta(seconds=n), outcome="failure")
            for n in (1, 2)
        ),
    )
    data["evidence"] = [history]
    report = build_report(**data)
    assert report.datasets[0].rows[0][-1] == 2
    assert report.datasets[0].state == "partial"
    assert report.datasets[0].window == history.window
    assert "not unique clients" in report.datasets[0].explanation
    with pytest.raises(ValidationError):
        report.datasets[0].model_validate({**report.datasets[0].model_dump(), "rows": [("wrong-width",)]})


async def test_history_follows_published_parents_and_rejects_foreign_artifacts(monkeypatch):
    _, root, _, artifacts, _ = setup_runtime(monkeypatch)
    data = report_inputs()
    data["investigation_id"] = str(root.id)
    first = InvestigationRevision.model_construct(
        id=PydanticObjectId(),
        organization_id=ORG,
        investigation_id=root.id,
        revision=1,
        generated_at=LATER,
        plan=data["plan"],
        assessment=data["assessment"],
        report=build_report(**data),
    )
    data.update(revision=2, previous=first.report)
    second = first.model_copy(
        update={"id": PydanticObjectId(), "revision": 2, "previous_report_id": first.id, "report": build_report(**data)}
    )
    artifacts.extend([first, second, second.model_copy(update={"id": PydanticObjectId()})])
    root.report_id, root.revision = second.id, 2
    monkeypatch.setattr(
        investigation_reads.AuditChangeGroup,
        "find_one",
        AsyncMock(return_value=SimpleNamespace(audit_id=root.audit_id)),
    )
    monkeypatch.setattr(investigation_reads, "read_investigation_root", AsyncMock(return_value=root))
    history = await investigation_reads.report_history(ORG, PydanticObjectId())
    assert history.complete
    assert [r.revision for r in history.reports] == [2, 1]
    first.organization_id = PydanticObjectId()
    history = await investigation_reads.report_history(ORG, PydanticObjectId())
    assert not history.complete
    assert [r.revision for r in history.reports] == [2]


def test_resolved_earlier_uncertainty_does_not_become_a_permanent_peak():
    data = report_inputs()
    clean = data["assessment"]
    data["assessment"] = clean.model_copy(update={"impact": "info", "coverage": "partial"})
    previous = build_report(**data)
    data.update(revision=2, previous=previous, assessment=clean)
    assert build_report(**data).peak_impact == "none"
