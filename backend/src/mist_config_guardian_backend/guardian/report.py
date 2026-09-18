"""Guardian's report: one pure builder that renders a stored run, and stores nothing of its own.

A run document is immutable once terminal, so the report is derived on read rather than persisted. Every section
comes from that document alone: this module measures nothing, re-derives nothing and invents nothing.

An empty section carries an explanation built from the same state — how many obligations were raised, how many
reads the attempt made, why the agent has no summary — so a section can never claim something the run does not
say. There are no fixed boilerplate sentences that could outlive the facts behind them.
"""

from collections.abc import Sequence

from pydantic import AwareDatetime, Field, ValidationError

from mist_config_guardian_backend.guardian.contracts import (
    MAX_TEXT_CHARS,
    AgentConclusion,
    Band,
    ChangeAtom,
    CompactImpactedDevice,
    Conclusion,
    Confidence,
    Contract,
    Coverage,
    Evidence,
    EvidenceCollection,
    EvidenceId,
    EvidenceKind,
    EvidenceRepresentation,
    EvidenceScope,
    EvidenceWindow,
    Gap,
    GapSource,
    LedgerRow,
    ObligationOutcome,
    Recovery,
    RunAnchor,
    RunBudget,
    RunKind,
    RunState,
    SafeReason,
    Summary,
    Text,
    VerdictSource,
)
from mist_config_guardian_backend.guardian.monitoring import DeviceMonitoring
from mist_config_guardian_backend.models.guardian import GuardianRun

# What one section shows before it counts the rest. The run document is already bounded; this bounds the view.
DISPLAY_ROWS = 50


class Section[T](Contract):
    """One report section: the rows it shows, how many it left out, and, when it shows none, why."""

    items: tuple[T, ...] = ()
    omitted: int = Field(default=0, ge=0)
    explanation: Text | None = None


class ReportRun(Contract):
    """The attempt itself, as the panel's collapsed summary shows it."""

    kind: RunKind
    attempt: int
    state: RunState
    failure_reason: SafeReason | None = None
    started_at: AwareDatetime
    finished_at: AwareDatetime | None = None
    anchor: RunAnchor | None = None
    as_of: AwareDatetime | None = None
    budget: RunBudget


class ReportHeader(Contract):
    peak: Band
    current: Band
    recovery: Recovery
    confidence: Confidence
    coverage: Coverage
    sources: tuple[VerdictSource, ...] = ()


class ReportSummary(Contract):
    """The deterministic sentence, and the agent's own summary labelled as such, or why there is none."""

    deterministic: Summary = ""
    ai: Summary | None = None
    ai_note: Text | None = None


class CoverageSection(Contract):
    coverage: Coverage | None = None
    rows: Section[LedgerRow] = Section[LedgerRow]()
    obligations: Section[ObligationOutcome] = Section[ObligationOutcome]()


class FindingRow(Contract):
    source: GapSource
    text: Text
    severity: Band
    evidence_ids: tuple[EvidenceId, ...] = ()


class EvidenceRow(Contract):
    """One E-id as the evidence table shows it; payloads stay in the run document."""

    id: EvidenceId
    source: str
    kind: EvidenceKind
    title: Text
    captured_at: AwareDatetime
    window: EvidenceWindow | None = None
    scope: EvidenceScope = EvidenceScope()
    collection: EvidenceCollection
    representation: EvidenceRepresentation
    citable: bool
    detail: str = ""


class Report(Contract):
    """One rendered run. Nothing here is stored: it is built from the run document on every read."""

    run: ReportRun
    header: ReportHeader | None = None
    header_note: Text | None = None
    summary: ReportSummary = ReportSummary()
    change: Section[ChangeAtom] = Section[ChangeAtom]()
    coverage: CoverageSection = CoverageSection()
    devices: Section[DeviceMonitoring] = Section[DeviceMonitoring]()
    impacted: Section[CompactImpactedDevice] = Section[CompactImpactedDevice]()
    findings: Section[FindingRow] = Section[FindingRow]()
    evidence: Section[EvidenceRow] = Section[EvidenceRow]()
    gaps: Section[Gap] = Section[Gap]()


def render_report(run: GuardianRun) -> Report:
    """Render one run. A run that never composed a verdict renders every section it did reach."""
    devices, digested = _devices(run)
    return Report(
        run=ReportRun(
            kind=run.kind,
            attempt=run.attempt,
            state=run.state,
            failure_reason=run.failure_reason,
            started_at=run.started_at,
            finished_at=run.finished_at,
            anchor=run.anchor,
            as_of=run.as_of,
            budget=run.budget,
        ),
        header=None
        if run.verdict is None
        else ReportHeader(**run.verdict.model_dump(include=set(ReportHeader.model_fields))),
        header_note=None if run.verdict is not None else _no_verdict(run),
        summary=_summary(run),
        change=_section(run.change, _no_change(run), omitted=run.change_omitted),
        coverage=CoverageSection(
            coverage=None if run.verdict is None else run.verdict.coverage,
            rows=_section(run.ledger, _no_rows(run), omitted=run.ledger_omitted),
            obligations=_section(run.obligations, _no_obligations(run), omitted=run.obligations_omitted),
        ),
        devices=_section(devices, _no_devices(run, digested), omitted=digested),
        impacted=_section(
            () if run.verdict is None else run.verdict.impacted_devices,
            _no_impacted(run),
            omitted=0 if run.verdict is None else run.verdict.impacted_devices_omitted,
        ),
        findings=_section(_findings(run), _no_findings(run)),
        evidence=_section(
            [_evidence_row(item) for item in run.evidence],
            f"No read is recorded on this run, which used {run.budget.rule_reads} rule read(s) "
            f"and {run.budget.mcp_calls} MCP call(s).",
        ),
        gaps=_section(_gaps(run), f"No gap is recorded over {_obligation_total(run)} obligation(s)."),
    )


def _section[T](items: Sequence[T], explanation: str, *, omitted: int = 0) -> Section[T]:
    """The first rows within the display limit, the count of the rest, and an explanation only when empty.

    ``omitted`` is what the run itself left out before this view saw anything: a budget that capped a stored list,
    or a digest that counted rather than kept. It is added to what the display limit cuts, so the count is the
    whole of what the section does not show rather than only the part this module could measure.
    """
    kept = tuple(items[:DISPLAY_ROWS])
    return Section[T](
        items=kept,
        omitted=omitted + max(len(items) - DISPLAY_ROWS, 0),
        explanation=None if kept else _text(explanation),
    )


def _atom_total(run: GuardianRun) -> int:
    """Every atom the attempt compiled, stored or not: what its ledger and its coverage were evaluated over."""
    return len(run.change) + run.change_omitted


def _row_total(run: GuardianRun) -> int:
    return len(run.ledger) + run.ledger_omitted


def _obligation_total(run: GuardianRun) -> int:
    return len(run.obligations) + run.obligations_omitted


def _no_change(run: GuardianRun) -> str:
    if run.change_omitted:
        return f"None of the {run.change_omitted} changed attribute(s) this run compiled fit its stored change view."
    return f"No changed attribute is recorded on this run for audit {run.audit_id}."


def _no_rows(run: GuardianRun) -> str:
    if run.ledger_omitted:
        return f"None of the {run.ledger_omitted} ledger row(s) this run resolved fit its stored ledger view."
    return f"No applicable target was found for {_atom_total(run)} change atom(s)."


def _no_obligations(run: GuardianRun) -> str:
    if run.obligations_omitted:
        return f"None of the {run.obligations_omitted} obligation(s) this run raised fit its stored ledger view."
    return f"No obligation was raised over {_row_total(run)} ledger row(s)."


def _devices(run: GuardianRun) -> tuple[list[DeviceMonitoring], int]:
    """The per-device monitoring rows the run recorded as evidence, and how many its digest counted."""
    rows: list[DeviceMonitoring] = []
    digested = 0
    for item in run.evidence:
        if item.source != "monitoring":
            continue
        if item.representation == "digest":
            counted = item.payload.get("devices")
            counts = counted.values() if isinstance(counted, dict) else ()
            digested += sum(value for value in counts if isinstance(value, int))
            continue
        try:
            rows.append(DeviceMonitoring.model_validate(item.payload))
        except ValidationError:  # pragma: no cover - a monitoring item is written from this model
            digested += 1
    return rows, digested


def _findings(run: GuardianRun) -> list[FindingRow]:
    """Every finding a conclusion recorded, under the source that recorded it, deterministic sources first."""
    sources: list[tuple[GapSource, Conclusion | AgentConclusion | None]] = [
        ("monitoring", run.monitoring),
        ("deployment", run.deployment),
        *((f"rule:{plugin}", conclusion) for plugin, conclusion in sorted(run.rules.items())),
        ("agent", run.agent if run.agent is not None and run.agent.concluded else None),
    ]
    return [
        FindingRow(source=name, text=finding.text, severity=finding.severity, evidence_ids=finding.evidence_ids)
        for name, conclusion in sources
        if conclusion is not None
        for finding in conclusion.findings
    ]


def _gaps(run: GuardianRun) -> list[Gap]:
    """The composed gaps, or, for a run that never composed a verdict, the gaps its conclusions recorded."""
    if run.verdict is not None:
        return list(run.verdict.gaps)
    collected = [
        Gap(source=name, text=text)
        for name, conclusion in (
            ("monitoring", run.monitoring),
            ("deployment", run.deployment),
            *((f"rule:{plugin}", conclusion) for plugin, conclusion in sorted(run.rules.items())),
            ("agent", run.agent),
        )
        if conclusion is not None
        for text in conclusion.gaps
    ]
    return list(dict.fromkeys(collected))


def _summary(run: GuardianRun) -> ReportSummary:
    """The deterministic sentence beside the agent's own, or the reason the agent left none."""
    agent = run.agent
    if agent is not None and agent.concluded and agent.summary:
        return ReportSummary(deterministic=_deterministic(run), ai=agent.summary)
    if agent is None:
        note = "No agent conclusion is recorded on this run."
    elif not agent.concluded:
        note = f"The AI agent did not conclude: {agent.reason}"
    else:
        note = f"The AI agent reported {agent.peak} without a summary."
    return ReportSummary(deterministic=_deterministic(run), ai_note=_text(note))


def _deterministic(run: GuardianRun) -> str:
    return run.verdict.summary if run.verdict is not None else ""


def _no_verdict(run: GuardianRun) -> Text:
    reason = run.failure_reason or f"it is still {run.state}"
    return _text(f"This attempt composed no verdict: {reason}")


def _no_devices(run: GuardianRun, digested: int) -> str:
    if run.monitoring is None:
        return "No monitoring replay is recorded on this run."
    if digested:
        return f"Monitoring counted {digested} device(s) in a digest and recorded none in full."
    return f"Monitoring recorded no device item while resolving {len(run.monitoring.statuses)} obligation(s)."


def _no_impacted(run: GuardianRun) -> str:
    if run.verdict is None:
        return "This attempt composed no verdict, so it named no impacted device."
    return (
        f"No device reached warning: the verdict is {run.verdict.peak} "
        f"with {run.verdict.coverage} deterministic coverage."
    )


def _no_findings(run: GuardianRun) -> str:
    """Why nothing was found, naming each source's own state rather than one sentence for all of them."""
    rules = sorted(run.rules)
    parts = [f"{len(rules)} rule plug-in(s) reported no finding" if rules else "No rule plug-in applied"]
    if run.agent is None:
        parts.append("no agent conclusion is recorded")
    elif not run.agent.concluded:
        parts.append(f"the AI agent did not conclude: {run.agent.reason}")
    else:
        parts.append(f"the AI agent reported {run.agent.peak} with no finding")
    return f"{'; '.join(parts)}."


def _evidence_row(item: Evidence) -> EvidenceRow:
    return EvidenceRow(
        id=item.id,
        source=item.source,
        kind=item.kind,
        title=item.title,
        captured_at=item.captured_at,
        window=item.window,
        scope=item.scope,
        collection=item.collection,
        representation=item.representation,
        citable=item.citable,
        detail=item.detail,
    )


def _text(value: str) -> Text:
    """One bounded, single-line explanation. Every input here is already bounded by a contract."""
    collapsed = " ".join(value.split())
    return collapsed if len(collapsed) <= MAX_TEXT_CHARS else f"{collapsed[: MAX_TEXT_CHARS - 1]}…"
