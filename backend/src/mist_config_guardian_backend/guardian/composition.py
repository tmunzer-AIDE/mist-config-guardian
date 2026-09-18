"""Guardian's verdict composition: the one pure function that turns separate conclusions into one verdict.

Monitoring replay, deployment pairing, the rule plug-ins and the agent each conclude on their own and are stored
that way. This module never re-derives any of them: it applies the spec's numbered rules over what they said.

The base comes from deterministic coverage, the floor from the deterministic sources counting warning and above
alone, and the agent contributes only when its report cites service-health evidence. Nothing here reads a network,
a database or a clock, so every rule is table-testable.
"""

from collections.abc import Iterable, Mapping, Sequence

from pydantic import model_validator

from mist_config_guardian_backend.guardian.contracts import (
    MAX_TEXT_CHARS,
    AgentConclusion,
    Band,
    CompactImpactedDevice,
    Conclusion,
    Confidence,
    Contract,
    Coverage,
    DeviceMac,
    Evidence,
    EvidenceId,
    Gap,
    GapSource,
    Identifier,
    Text,
    Verdict,
    VerdictSource,
    band_rank,
    recovery_for,
)
from mist_config_guardian_backend.guardian.evidence import IMPACTED_DEVICES_BUDGET, Bounded, bounded

# The spec's own sentence for a change nothing exercised; every other summary is built from the composed state.
NOT_EXERCISED_SUMMARY = "The change was not exercised during the window"
NO_CONCLUSION_GAP = "AI agent did not conclude: {reason}"
BELOW_VERDICT_GAP = "AI assessment ({agent}) was below the published verdict ({peak})"
UNIDENTIFIED_GAP = "{count} impacted device{plural} named by a conclusion could not be listed: no site identifies them"
TRUNCATED_GAP = "{count} further gap{plural} were recorded and not listed"

MAX_VERDICT_GAPS = 24
# A device is listed on the verdict when it reached the floor bands, which is what the root and the site overlay show.
LISTED_FLOOR: Band = "warning"

_WARNING = band_rank(LISTED_FLOOR)


class DeviceSeverity(Contract):
    """One targeted device as a deterministic replay measured it: its identity and its own peak and current.

    Monitoring replay is the only source that measures both bands per device. Rule and agent conclusions name a
    device with one severity, which is a peak claim; :func:`compose` pairs it with its source's current.
    """

    mac: DeviceMac
    site_id: Identifier
    name: str = ""
    peak: Band = "none"
    current: Band = "none"

    @model_validator(mode="after")
    def current_within_peak(self) -> "DeviceSeverity":
        if band_rank(self.current) > band_rank(self.peak):
            msg = f"A device's current ({self.current}) cannot exceed peak ({self.peak})"
            raise ValueError(msg)
        return self


def compose(  # noqa: PLR0913 - one conclusion, or one of its inputs, per argument
    *,
    coverage: Coverage,
    monitoring: Conclusion | None = None,
    deployment: Conclusion | None = None,
    rules: Mapping[str, Conclusion] | None = None,
    agent: AgentConclusion | None = None,
    evidence: Iterable[Evidence] = (),
    devices: Iterable[DeviceSeverity] = (),
    core_gaps: Iterable[str] = (),
) -> Verdict:
    """Compose one attempt's verdict from its stored conclusions, in the spec's numbered order.

    ``devices`` are the deterministic per-device bands, and they also identify a device a rule or the agent names.
    ``evidence`` decides one thing only: whether the agent cited a service-health item, which is what lets its
    assessment contribute at all. ``core_gaps`` are what the attempt itself could not see or could not finish,
    such as an input its read caps truncated or an isolated phase that failed. Coverage already reflects each one:
    an input carries its own unsatisfied core obligation, and a failed phase reports no status for the obligations
    it would have resolved, which leaves them unsatisfied too.
    """
    plugins = dict(sorted((rules or {}).items()))
    base: Band = "none" if coverage == "complete" else "info"
    rows = tuple(devices)
    floor = _Floor(monitoring, deployment, plugins, rows)
    contribution = _Contribution.of(agent, evidence)

    peak = _worst(base, floor.peak, contribution.peak)
    current = _worst(base, floor.current, contribution.current)
    # Rule 5: only a contributing report that concurs with the published peak raises confidence above low.
    confidence: Confidence = "medium" if contribution.contributes and contribution.peak == peak else "low"

    listed, unidentified = _impacted(rows, monitoring, deployment, plugins, contribution)
    gaps = _gaps(
        monitoring, deployment, plugins, agent, contribution, peak=peak, unidentified=unidentified, core=core_gaps
    )
    return Verdict(
        peak=peak,
        current=current,
        recovery=recovery_for(peak, current),
        confidence=confidence,
        coverage=coverage,
        sources=_sources(base, floor, contribution, peak=peak, current=current),
        summary=_summary(peak=peak, current=current, coverage=coverage, base=base, listed=listed),
        gaps=gaps,
        impacted_devices=listed.items,
        impacted_devices_omitted=listed.omitted_count,
    )


class _Floor:
    """Rule 2: the maximum over the deterministic sources, counting warning and critical alone.

    The per-device rows belong to this floor too: they are the exclusive monitoring replay, which rule 2 names,
    measured device by device rather than folded into one band. Folding them back in changes nothing for a
    consistent replay, whose conclusion already carries the maximum over its own devices, and it keeps composition
    total: a verdict can never list a device it did not account for (controller ruling R36).
    """

    def __init__(
        self,
        monitoring: Conclusion | None,
        deployment: Conclusion | None,
        rules: Mapping[str, Conclusion],
        devices: Sequence[DeviceSeverity] = (),
    ) -> None:
        measured = (_worst(*(row.peak for row in devices)), _worst(*(row.current for row in devices)))
        if monitoring is not None and devices:
            monitoring = monitoring.model_copy(
                update={
                    "peak": _worst(monitoring.peak, measured[0]),
                    "current": _worst(monitoring.current, measured[1]),
                }
            )
        self.inputs: dict[VerdictSource, Conclusion] = {
            **({"monitoring": monitoring} if monitoring is not None else {}),
            **({"deployment": deployment} if deployment is not None else {}),
            **{f"rule:{plugin}": conclusion for plugin, conclusion in rules.items()},
        }
        self.peak = _worst(*(_above_info(item.peak) for item in self.inputs.values()), _above_info(measured[0]))
        self.current = _worst(*(_above_info(item.current) for item in self.inputs.values()), _above_info(measured[1]))

    def setting(self, band: Band) -> list[VerdictSource]:
        """The floor inputs whose own contribution is exactly ``band``."""
        return [
            name
            for name, item in self.inputs.items()
            if band in (_above_info(item.peak), _above_info(item.current)) and band != "none"
        ]


class _Contribution:
    """Rule 3: what an accepted agent report adds, which is nothing unless it cited a service-health item."""

    def __init__(self, agent: AgentConclusion | None, *, contributes: bool) -> None:
        self.agent = agent
        self.contributes = contributes
        self.peak: Band = agent.peak if contributes and agent is not None and agent.peak else "none"
        self.current: Band = agent.current if contributes and agent is not None and agent.current else "none"

    @classmethod
    def of(cls, agent: AgentConclusion | None, evidence: Iterable[Evidence]) -> "_Contribution":
        if agent is None or not agent.concluded:
            return cls(agent, contributes=False)
        health = {item.id for item in evidence if item.kind == "service_health" and item.citable}
        return cls(agent, contributes=bool(cited(agent) & health))


def cited(agent: AgentConclusion) -> set[EvidenceId]:
    """Every evidence id an agent report cites, from the report itself, its findings and its devices."""
    return {
        identity
        for source in ((agent,), agent.findings, agent.impacted_devices)
        for item in source
        for identity in item.evidence_ids
    }


def _impacted(
    devices: Iterable[DeviceSeverity],
    monitoring: Conclusion | None,
    deployment: Conclusion | None,
    rules: Mapping[str, Conclusion],
    contribution: _Contribution,
) -> tuple[Bounded[CompactImpactedDevice], int]:
    """The devices at or above the listed floor, worst first, within the impacted-devices budget.

    A device a conclusion names but no replay identifies has no site, so it cannot be one of these rows; it is
    counted instead, and :func:`_gaps` says so.
    """
    known = {row.mac: row for row in devices}
    bands: dict[str, tuple[Band, Band]] = {mac: (row.peak, row.current) for mac, row in known.items()}
    unidentified: set[str] = set()
    sources = [monitoring, deployment, *rules.values()]
    if contribution.contributes and contribution.agent is not None:
        sources.append(contribution.agent)
    for source in sources:
        if source is None:
            continue
        # A conclusion's device severity is that device's peak; it cannot be worse now than its source's current.
        source_current: Band = source.current or "none"
        for impacted in source.impacted_devices:
            if impacted.mac not in known:
                unidentified.add(impacted.mac)
                continue
            peak, current = bands[impacted.mac]
            bands[impacted.mac] = (
                _worst(peak, impacted.severity),
                _worst(current, _at_most(impacted.severity, source_current)),
            )
    rows = [
        CompactImpactedDevice(mac=mac, site_id=known[mac].site_id, name=known[mac].name, peak=peak, current=current)
        for mac, (peak, current) in bands.items()
        if band_rank(peak) >= _WARNING
    ]
    listed = bounded(
        rows,
        budget=IMPACTED_DEVICES_BUDGET,
        priority=lambda row: (-band_rank(row.peak), -band_rank(row.current), row.mac),
        category=lambda row: row.peak,
        build=lambda kept, omitted: Bounded[CompactImpactedDevice](items=kept, omitted=omitted),
    )
    return listed, len(unidentified)


def _sources(
    base: Band, floor: _Floor, contribution: _Contribution, *, peak: Band, current: Band
) -> tuple[VerdictSource, ...]:
    """Rule 7: the inputs that set the published bands, in a fixed order.

    When the base decides a band, every coverage input decided it, because coverage is resolved over all of them
    together. Otherwise it was the floor inputs that reached that band, or the agent.
    """
    names: list[VerdictSource] = []
    for band in (peak, current):
        if band == base:
            names.extend(floor.inputs)
        else:
            names.extend(floor.setting(band))
            if band in (contribution.peak, contribution.current) and contribution.contributes:
                names.append("agent")
    order = [*floor.inputs, "agent"]
    return tuple(sorted(set(names), key=order.index))


def _gaps(  # noqa: PLR0913 - one gap source per argument
    monitoring: Conclusion | None,
    deployment: Conclusion | None,
    rules: Mapping[str, Conclusion],
    agent: AgentConclusion | None,
    contribution: _Contribution,
    *,
    peak: Band,
    unidentified: int,
    core: Iterable[str] = (),
) -> tuple[Gap, ...]:
    """Every source's gaps under its own name, then what composition itself found, deduplicated and bounded."""
    collected: list[tuple[GapSource, str]] = [("core", text) for text in core]
    for name, conclusion in (("monitoring", monitoring), ("deployment", deployment)):
        collected.extend((name, text) for text in (conclusion.gaps if conclusion is not None else ()))
    collected.extend((f"rule:{plugin}", text) for plugin, item in rules.items() for text in item.gaps)
    if agent is not None:
        collected.extend(("agent", text) for text in agent.gaps)
        if not agent.concluded and agent.reason is not None:
            collected.append(("agent", NO_CONCLUSION_GAP.format(reason=agent.reason)))
        elif contribution.contributes and band_rank(contribution.peak) < band_rank(peak):
            collected.append(("agent", BELOW_VERDICT_GAP.format(agent=contribution.peak, peak=peak)))
    if unidentified:
        collected.append(("core", UNIDENTIFIED_GAP.format(count=unidentified, plural=_plural(unidentified))))
    unique = list(dict.fromkeys(collected))
    kept = [Gap(source=name, text=_text(value)) for name, value in unique[:MAX_VERDICT_GAPS]]
    if len(unique) > MAX_VERDICT_GAPS:
        rest = len(unique) - MAX_VERDICT_GAPS
        kept.append(Gap(source="core", text=TRUNCATED_GAP.format(count=rest, plural=_plural(rest))))
    return tuple(kept)


def _summary(
    *, peak: Band, current: Band, coverage: Coverage, base: Band, listed: Bounded[CompactImpactedDevice]
) -> str:
    """One deterministic sentence, built from the composed state alone.

    The spec's own wording is used for a change nothing exercised, and only while nothing raised the verdict above
    that base; a floor or an agent assessment describes what it found instead.
    """
    if coverage == "not_applicable" and peak == base:
        return NOT_EXERCISED_SUMMARY
    observed = {"none": "No service impact was observed", "info": "No service impact was established"}
    parts = [f"{observed.get(peak, f'Peak impact {peak}')} (coverage {coverage})"]
    if band_rank(peak) >= _WARNING:
        parts.append(f"current {current}")
    count = len(listed.items) + listed.omitted_count
    if count:
        parts.append(f"{count} impacted device{_plural(count)}")
    return "; ".join(parts) + "."


def _worst(*bands: Band) -> Band:
    return max(bands, key=band_rank, default="none")


def _above_info(band: Band) -> Band:
    """A floor counts warning and critical alone; anything below them sets no floor."""
    return band if band_rank(band) >= _WARNING else "none"


def _at_most(band: Band, ceiling: Band) -> Band:
    return band if band_rank(band) <= band_rank(ceiling) else ceiling


def _plural(count: int) -> str:
    return "" if count == 1 else "s"


def _text(value: str) -> Text:
    """One gap line within the stored bound; every input here is already a bounded contract field."""
    return value if len(value) <= MAX_TEXT_CHARS else f"{value[: MAX_TEXT_CHARS - 1]}…"
