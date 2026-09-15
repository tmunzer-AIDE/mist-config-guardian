"""Common report layout for validated MCP-agent findings; charts contain returned values only."""

import json
from datetime import UTC, datetime

from mist_config_guardian_backend.impact.contracts import Window, WlanAssessment
from mist_config_guardian_backend.impact.mcp_contracts import McpCheckpoint, McpConclusion, McpEvidence
from mist_config_guardian_backend.impact.mcp_views import selected_rows
from mist_config_guardian_backend.impact.report import DeviceImpact, EvidenceDataset, ImpactReport, ReportSection


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


def mcp_assessment(audit_id: str, as_of: datetime, checkpoint: McpCheckpoint) -> WlanAssessment:
    effective = effective_conclusion(checkpoint)
    conclusion = effective[0] if effective else None
    return WlanAssessment(
        policy_version="mcp-agent.v1",
        audit_id=audit_id,
        evaluated_at=as_of,
        impact=conclusion.impact if conclusion else "info",
        confidence=conclusion.confidence if conclusion else "low",
        coverage=conclusion.coverage if conclusion else "partial",
        findings=(),
        gaps=conclusion.gaps if conclusion else (checkpoint.reason or "Agent investigation is incomplete.",),
    )


def build_mcp_report(base: ImpactReport, checkpoint: McpCheckpoint) -> ImpactReport:
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
    sections = base.sections.model_copy(
        update={
            "summary": ReportSection(
                state="available" if conclusion else "unavailable",
                explanation=(
                    conclusion.summary + (f" (Carried forward from revision {carried_from}.)" if carried_from else "")
                )[:500]
                if conclusion
                else checkpoint.reason or "No validated agent conclusion.",
            ),
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
    devices = (
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
    return base.model_copy(
        update={
            "source": "mcp_agent",
            "current_impact": conclusion.impact if conclusion else "info",
            "confidence": conclusion.confidence if conclusion else "low",
            "coverage": conclusion.coverage if conclusion else "partial",
            "sections": sections,
            "datasets": tuple(datasets),
            "gaps": (
                *(conclusion.gaps if conclusion else (checkpoint.reason,)),
                "Only investigated scope is covered; absent devices are not presumed healthy.",
            ),
            "impacted_devices": devices,
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
