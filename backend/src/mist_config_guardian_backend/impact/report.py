"""Fixed report contract and deterministic evidence views; no model-authored data."""

from collections import Counter
from collections.abc import Sequence
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, model_validator

from mist_config_guardian_backend.impact.contracts import (
    AuthEvidence,
    Contract,
    InvestigationEvidence,
    PortEvidence,
    PortHistoryEvidence,
    SessionEvidence,
    Window,
    WlanAssessment,
    WlanRemovalPlan,
)
from mist_config_guardian_backend.impact.limits import MAX_CHECKPOINT_EVIDENCE

Band = Literal["none", "info", "warning", "critical"]
_ORDER = {"none": 0, "info": 1, "warning": 2, "critical": 3}
Text = Annotated[str, Field(max_length=500)]
Cell = str | int | float | None
MAX_DEVICE_IMPACTS = 200


class ReportSection(Contract):
    state: Literal["available", "partial", "unavailable"]
    explanation: Text


class ReportSections(Contract):
    summary: ReportSection
    change: ReportSection
    scope: ReportSection
    findings: ReportSection
    evidence: ReportSection
    timeline: ReportSection
    context: ReportSection
    gaps_and_next_checks: ReportSection


class EvidenceDataset(Contract):
    """Rows are normalized server values; missing values remain null, never zero."""

    id: str = Field(pattern=r"^evidence-[0-9]+$")
    check_id: str
    target_handle: str
    window: Window
    captured_at: datetime
    state: str
    title: Text
    kind: Literal["table", "bar", "histogram", "timeline"]
    columns: tuple[str, ...] = Field(min_length=2, max_length=4)
    rows: tuple[tuple[Cell, ...], ...] = Field(max_length=200)
    omitted_rows: int = Field(default=0, ge=0)
    explanation: Text

    @model_validator(mode="after")
    def rectangular(self) -> "EvidenceDataset":
        if any(len(row) != len(self.columns) for row in self.rows):
            msg = "Evidence rows must match the declared columns"
            raise ValueError(msg)
        return self


class DeviceImpact(Contract):
    """A service association, not a claim that the entire device is down."""

    device_mac: str = Field(pattern=r"^[0-9a-f]{12}$")
    site_id: UUID
    role: Literal["affected_switch_port", "serving_affected_clients"]
    service: Literal["port_link", "port_power", "wlan_sessions", "wlan_authentication"]
    target_handle: str
    port_id: str | None = None
    impact: Band
    current_impact: Band
    confidence: Literal["low", "medium"]
    attribution: Literal["plausible"] = "plausible"
    device_failure: Literal["not_established"] = "not_established"


class ImpactReport(Contract):
    schema_version: Literal[1] = 1
    investigation_id: str
    audit_id: str
    revision: int = Field(ge=1)
    generated_at: datetime
    evidence_as_of: datetime
    peak_impact: Band
    peak_revision: int = Field(ge=1)
    peak_confidence: Literal["low", "medium"]
    history_complete: bool
    current_impact: Band
    confidence: Literal["low", "medium"]
    coverage: Literal["complete", "partial", "unmapped"]
    attribution: Literal["plausible", "undetermined"]
    sections: ReportSections
    datasets: tuple[EvidenceDataset, ...] = Field(max_length=MAX_CHECKPOINT_EVIDENCE)
    impacted_devices: tuple[DeviceImpact, ...] = Field(max_length=MAX_DEVICE_IMPACTS)
    device_coverage: Literal["observed_only"] = "observed_only"
    omitted_device_impacts: int = Field(default=0, ge=0)
    gaps: tuple[str, ...]


def build_report(  # noqa: PLR0913 - immutable publication identity and source data
    *,
    investigation_id: str,
    revision: int,
    generated_at: datetime,
    plan: WlanRemovalPlan,
    assessment: WlanAssessment,
    evidence: Sequence[InvestigationEvidence],
    previous: ImpactReport | None = None,
    history_available: bool = True,
) -> ImpactReport:
    """Build exclusively from one revision. Historical peak is handled by the chain reader."""
    current: Band = max(
        [*(f.impact for f in assessment.findings), *(f.current_impact for f in assessment.domain_findings)],
        default="info",
        key=_ORDER.__getitem__,
    )
    if assessment.coverage != "complete" and current == "none":
        current = "info"
    devices = _devices(plan, assessment)
    if previous and (
        previous.investigation_id != investigation_id
        or previous.audit_id != plan.audit_id
        or previous.revision != revision - 1
    ):
        msg = "Previous report does not match the publication chain"
        raise ValueError(msg)
    retain_peak = previous is not None and _ORDER[previous.peak_impact] > _ORDER[assessment.impact]
    available = ReportSection(state="available", explanation="Recorded in this immutable revision.")
    gaps = tuple(dict.fromkeys((*assessment.gaps, *plan.gaps)))
    return ImpactReport(
        investigation_id=investigation_id,
        audit_id=plan.audit_id,
        revision=revision,
        generated_at=generated_at,
        evidence_as_of=assessment.evaluated_at,
        peak_impact=previous.peak_impact if retain_peak and previous else assessment.impact,
        peak_revision=previous.peak_revision if retain_peak and previous else revision,
        peak_confidence=previous.peak_confidence if retain_peak and previous else assessment.confidence,
        history_complete=history_available and (previous.history_complete if previous else True),
        current_impact=current,
        confidence=assessment.confidence,
        coverage=assessment.coverage,
        attribution="plausible" if assessment.impact in {"warning", "critical"} else "undetermined",
        sections=ReportSections(
            summary=available,
            change=available,
            scope=ReportSection(
                state="partial" if plan.unmapped or plan.gaps else "available",
                explanation="Only resolved change targets are monitored; unmatched attributes remain unmapped.",
            ),
            findings=available,
            evidence=ReportSection(
                state="available" if assessment.coverage == "complete" else "partial",
                explanation="Counts describe returned evidence, not the expected fleet or a success rate.",
            ),
            timeline=ReportSection(
                state="available"
                if any(isinstance(e, (PortHistoryEvidence, AuthEvidence)) for e in evidence)
                else "unavailable",
                explanation="Only recorded event times are plotted; collection time is separate.",
            ),
            context=ReportSection(
                state="partial",
                explanation="Membership and deployment receipts cannot establish past dependency or device failure.",
            ),
            gaps_and_next_checks=ReportSection(
                state="partial" if gaps or plan.unmapped else "available",
                explanation="Unresolved coverage cannot establish a clean outcome.",
            ),
        ),
        datasets=tuple(_dataset(index, reading) for index, reading in enumerate(evidence)),
        impacted_devices=tuple(devices[:MAX_DEVICE_IMPACTS]),
        omitted_device_impacts=max(0, len(devices) - MAX_DEVICE_IMPACTS),
        gaps=(
            *(
                ()
                if history_available
                else ("Earlier published report is unavailable; historical peak may be incomplete.",)
            ),
            *gaps,
            "Device list covers observed service associations only; absence does not establish health.",
        ),
    )


def _devices(plan: WlanRemovalPlan, assessment: WlanAssessment) -> list[DeviceImpact]:
    records = {}
    sites = {t.handle: t.site_id for t in (*plan.targets, *plan.port_targets)}
    ports = {t.handle: t for t in plan.port_targets}
    for finding in assessment.domain_findings:
        if finding.impact not in {"warning", "critical"} or finding.target_handle not in sites:
            continue
        port = ports.get(finding.target_handle)
        # Identity comes from the immutable resolver, never a model or arbitrary finding.
        if port and finding.device_mac == port.device_mac and finding.port_id == port.port_id:
            device = DeviceImpact(
                device_mac=port.device_mac,
                site_id=port.site_id,
                role="affected_switch_port",
                service=finding.service,
                target_handle=port.handle,
                port_id=port.port_id,
                impact=finding.impact,
                current_impact=finding.current_impact,
                confidence=finding.confidence,
            )
            records[(device.site_id, device.device_mac, device.service, device.target_handle)] = device
        if finding.service == "wlan_authentication":
            for mac in finding.serving_ap_macs:
                device = DeviceImpact(
                    device_mac=mac,
                    site_id=sites[finding.target_handle],
                    role="serving_affected_clients",
                    service="wlan_authentication",
                    target_handle=finding.target_handle,
                    impact=finding.impact,
                    current_impact=finding.current_impact,
                    confidence=finding.confidence,
                )
                records[(device.site_id, mac, device.service, device.target_handle)] = device
    for finding in assessment.findings:
        if finding.impact != "warning" or finding.target_handle not in sites:
            continue
        for mac in finding.serving_ap_macs:
            device = DeviceImpact(
                device_mac=mac,
                site_id=sites[finding.target_handle],
                role="serving_affected_clients",
                service="wlan_sessions",
                target_handle=finding.target_handle,
                impact=finding.impact,
                current_impact=finding.impact,
                confidence=finding.confidence,
            )
            records[(device.site_id, mac, device.service, device.target_handle)] = device
    return sorted(records.values(), key=lambda d: (str(d.site_id), d.device_mac, d.service, d.target_handle))


def _dataset(index: int, reading: InvestigationEvidence) -> EvidenceDataset:
    rows: list[tuple[Cell, ...]] = []
    kind: Literal["table", "bar", "histogram", "timeline"] = "table"
    columns = ("Measure", "Value")
    explanation = reading.reason or "Normalized observations; missing values are unknown."
    if isinstance(reading, SessionEvidence):
        counts = Counter(row.ap_mac for row in reading.rows)
        # Unique clients per serving AP, not session-row counts or a fleet denominator.
        rows = [(mac, len({r.client_mac for r in reading.rows if r.ap_mac == mac})) for mac in sorted(counts)]
        columns = ("Serving AP", "Observed clients")
        kind = "bar"
    elif isinstance(reading, AuthEvidence):
        counts = Counter(
            (r.occurred_at.replace(minute=r.occurred_at.minute // 10 * 10, second=0, microsecond=0), r.outcome)
            for r in reading.rows
        )
        rows = [(at.isoformat(), outcome, count) for (at, outcome), count in sorted(counts.items())]
        columns = ("10-minute interval start", "Outcome", "Events")
        kind = "histogram"
        explanation = (
            "Event counts in UTC-aligned 10-minute bins; repeated attempts are not unique clients or a failure rate."
        )
    elif isinstance(reading, PortHistoryEvidence):
        rows = [(r.occurred_at.isoformat(), r.event_type) for r in sorted(reading.rows, key=lambda r: r.occurred_at)]
        columns = ("Occurred at", "Event")
        kind = "timeline"
    elif isinstance(reading, PortEvidence) and reading.rows:
        row = reading.rows[0]
        rows = [
            ("Link up", None if row.up is None else str(row.up)),
            ("PoE enabled", None if row.poe_on is None else str(row.poe_on)),
            ("Power draw (W)", row.power_draw),
            ("Observed at", row.observed_at.isoformat() if row.observed_at else None),
        ]
    else:
        rows = [("Inventory membership", "Verified" if reading.rows else None)]
    return EvidenceDataset(
        id=f"evidence-{index}",
        check_id=reading.check_id,
        target_handle=reading.target_handle,
        window=reading.window,
        captured_at=reading.captured_at,
        state=reading.state,
        title=reading.check_id,
        kind=kind,
        columns=columns,
        rows=tuple(rows[:200]),
        omitted_rows=max(0, len(rows) - 200),
        explanation=explanation,
    )
