"""Common report layout for validated MCP-agent findings; charts contain returned values only."""

import json
from datetime import UTC, datetime

from mist_config_guardian_backend.impact.contracts import Window, WlanAssessment
from mist_config_guardian_backend.impact.mcp_contracts import McpCheckpoint, McpConclusion, McpEvidence
from mist_config_guardian_backend.impact.mcp_views import selected_rows
from mist_config_guardian_backend.impact.report import (
    MAX_DEVICE_IMPACTS,
    DeviceImpact,
    EvidenceDataset,
    ImpactReport,
    ReportSection,
    VerdictSource,
)

_SEVERITY = {"none": 0, "info": 1, "warning": 2, "critical": 3}
RULE_RAISED_GAP = "Rule-derived impact exceeds the agent conclusion; the more severe verdict is published."
CLEAN_OUTCOME_GAP = "Partial coverage cannot establish a clean outcome; info is published instead of none."


def _no_clean_outcome_without_coverage(assessment: WlanAssessment, *, explained: bool) -> WlanAssessment:
    """Missing or partial coverage never publishes none; `explained` means a gap already states why it is partial."""
    if assessment.coverage == "complete" or assessment.impact != "none":
        return assessment
    gaps = assessment.gaps if explained else tuple(dict.fromkeys((*assessment.gaps, CLEAN_OUTCOME_GAP)))
    return assessment.model_copy(update={"impact": "info", "gaps": gaps})


def effective_conclusion(
    checkpoint: McpCheckpoint,
) -> tuple[McpConclusion, tuple[McpEvidence, ...], int | None] | None:
    """This run's validated conclusion, else the carried one with its source revision."""
    if checkpoint.state == "complete" and checkpoint.conclusion is not None:
        pool = (
            *([checkpoint.deterministic_evidence] if checkpoint.deterministic_evidence else []),
            *checkpoint.evidence,
        )
        return checkpoint.conclusion, pool, None
    if checkpoint.carried is not None:
        return checkpoint.carried.conclusion, checkpoint.carried.evidence, checkpoint.carried.source_revision
    return None


def compose_assessment(
    audit_id: str,
    as_of: datetime,
    checkpoint: McpCheckpoint,
    deterministic: WlanAssessment,
    *,
    final: bool = False,
) -> tuple[WlanAssessment, VerdictSource]:
    """Never publish below rule-derived disruption; never let rule-only info/none override an agent conclusion."""
    effective = effective_conclusion(checkpoint)
    if effective is None:
        # Checkpoint reasons are Guardian-authored fixed texts, never provider or MCP output.
        reason = (checkpoint.reason or "Agent investigation is incomplete.")[:300]
        gap = f"Rule-derived verdict: the AI agent did not conclude ({reason})."
        update: dict[str, object] = {"gaps": tuple(dict.fromkeys((*deterministic.gaps, gap)))}
        forced = final and deterministic.coverage == "complete"
        if forced:
            # Agent failure stays explicit: the final checkpoint cannot complete the investigation on rules alone.
            update["coverage"] = "partial"
        # When coverage is forced partial, the agent-did-not-conclude gap already explains it.
        return _no_clean_outcome_without_coverage(deterministic.model_copy(update=update), explained=forced), "rule"
    conclusion, _, carried_from = effective
    raised = (
        deterministic.impact in {"warning", "critical"}
        and _SEVERITY[deterministic.impact] > _SEVERITY[conclusion.impact]
    )
    gaps = list(conclusion.gaps)
    coverage = "partial" if raised else conclusion.coverage
    if carried_from is not None:
        gaps.append(
            f"Agent conclusion carried forward from revision {carried_from}; no newer agent conclusion is available."
        )
        if checkpoint.state != "not_scheduled":
            gaps.append(
                f"Latest agent run stopped without a conclusion: {(checkpoint.reason or checkpoint.state)[:300]}"
            )
        if final:
            # The investigation's last checkpoint cannot complete on an earlier run's coverage.
            coverage = "partial"
            gaps.append(
                f"Final checkpoint has no new agent conclusion; the conclusion carried from revision {carried_from} "
                "cannot establish complete coverage."
            )
    if raised:
        gaps.append(RULE_RAISED_GAP)
    assessment = WlanAssessment(
        policy_version="mcp-agent.v1",
        audit_id=audit_id,
        evaluated_at=as_of,
        impact=deterministic.impact if raised else conclusion.impact,
        confidence=deterministic.confidence if raised else conclusion.confidence,
        coverage=coverage,
        findings=deterministic.findings if raised else (),
        domain_findings=deterministic.domain_findings if raised else (),
        gaps=tuple(dict.fromkeys(gaps)),
    )
    # A carried conclusion forced partial on the final checkpoint already carries its final-checkpoint gap.
    explained = final and carried_from is not None
    return _no_clean_outcome_without_coverage(assessment, explained=explained), "combined" if raised else "mcp_agent"


def _merge_key(device: DeviceImpact) -> tuple[str, str, str, str, str]:
    """Role and target handle keep distinct ports/WLAN targets and agent rows from collapsing into one row."""
    return (device.role, str(device.site_id), device.device_mac, device.service, device.target_handle)


def build_mcp_report(base: ImpactReport, checkpoint: McpCheckpoint, source: VerdictSource) -> ImpactReport:
    effective = effective_conclusion(checkpoint)
    conclusion = effective[0] if effective else None
    carried_from = effective[2] if effective else None
    datasets = []
    own = (*([checkpoint.deterministic_evidence] if checkpoint.deterministic_evidence else []), *checkpoint.evidence)
    carried_rows = tuple(e for e in (effective[1] if effective else ()) if e.id not in {o.id for o in own})
    for index, evidence in enumerate((*own, *carried_rows)):
        view = next((v for v in conclusion.views if v.evidence_id == evidence.id), None) if conclusion else None
        rows = selected_rows(evidence, view) if view else _flatten(evidence.data)
        datasets.append(
            EvidenceDataset(
                id=f"evidence-{index}",
                check_id=evidence.tool,
                target_handle=str(evidence.id),
                window=Window(
                    start=datetime.fromtimestamp(float(str(evidence.arguments["start_time"])), UTC),
                    end=datetime.fromtimestamp(float(str(evidence.arguments["end_time"])), UTC),
                )
                if "start_time" in evidence.arguments and "end_time" in evidence.arguments
                else None,
                captured_at=evidence.captured_at,
                state=evidence.state,
                title=evidence.tool,
                kind=view.kind if view else "table",
                columns=(
                    view.value_key if view.kind == "histogram" else view.label_key,
                    "Count" if view.kind == "histogram" else view.value_key,
                )
                if view
                else ("Field", "Observed value"),
                rows=tuple(rows[:200]),
                explanation=f"Evidence {evidence.id}. Query: "
                f"{json.dumps(evidence.arguments, separators=(',', ':'))[:300]}",
                omitted_rows=max(0, len(rows) - 200),
            )
        )
    if conclusion:
        summary = conclusion.summary + (f" (Carried forward from revision {carried_from}.)" if carried_from else "")
        if source == "combined":
            summary += " Rule-derived impact is higher and is published."
    else:
        summary = f"Rule-derived verdict; the AI agent did not conclude: {checkpoint.reason or checkpoint.state}"
    sections = base.sections.model_copy(
        update={
            "summary": ReportSection(state="available" if conclusion else "partial", explanation=summary[:500]),
            "scope": ReportSection(
                state="partial",
                explanation=conclusion.scope if conclusion else "Investigated scope is unavailable.",
            ),
            "findings": ReportSection(
                state="available" if conclusion else "unavailable",
                explanation="Agent findings cite retained operational evidence and remain provisional.",
            ),
        }
    )
    agent_devices = (
        tuple(
            DeviceImpact(
                device_mac=d.device_mac,
                site_id=d.site_id,
                role="agent_observed_service",
                service=d.service,
                target_handle=str(d.evidence[0]),
                impact=d.impact,
                current_impact=d.impact,
                confidence=conclusion.confidence,
            )
            for d in conclusion.impacted_devices
            if d.impact in {"warning", "critical"}
        )
        if conclusion
        else ()
    )
    # Every verdict source publishes both sets of rows; only the seeding order differs. The source the
    # published verdict rests on comes first (the agent conclusion for mcp_agent, the deterministic devices
    # for rule and combined), so the device bound drops the other source's rows instead of the rows that
    # justify the verdict, and a key both sources claim keeps the row of that same source.
    leading, trailing = (
        (agent_devices, base.impacted_devices) if source == "mcp_agent" else (base.impacted_devices, agent_devices)
    )
    merged = {_merge_key(d): d for d in leading}
    for device in trailing:
        merged.setdefault(_merge_key(device), device)
    devices = tuple(merged.values())
    current = conclusion.impact if source == "mcp_agent" and conclusion else base.current_impact
    if base.coverage != "complete" and current == "none":
        # As build_report: non-complete coverage never publishes a clean current outcome. The peak follows the
        # published assessment, which compose_assessment already clamps the same way.
        current = "info"
    return base.model_copy(
        update={
            "source": "mcp_agent",
            "verdict_source": source,
            "current_impact": current,
            "sections": sections,
            "datasets": tuple(datasets),
            "gaps": tuple(
                dict.fromkeys(
                    (*base.gaps, "Only investigated scope is covered; absent devices are not presumed healthy.")
                )
            ),
            "impacted_devices": devices[:MAX_DEVICE_IMPACTS],
            # Rows the base report already omitted stay omitted; this merge's own cut is added to them.
            "omitted_device_impacts": base.omitted_device_impacts + max(0, len(devices) - MAX_DEVICE_IMPACTS),
        }
    )


def _flatten(value: object, path: str = "") -> list[tuple[str, str | int | float | None]]:
    rows = []
    if isinstance(value, dict):
        for key, child in value.items():
            rows.extend(_flatten(child, f"{path}.{key}" if path else str(key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            rows.extend(_flatten(child, f"{path}[{index}]"))
    else:
        if isinstance(value, bool):
            cell = str(value).lower()
        else:
            cell = value if value is None or isinstance(value, (int, float)) else str(value)[:500]
        rows.append((path[:200], cell))
    return rows
