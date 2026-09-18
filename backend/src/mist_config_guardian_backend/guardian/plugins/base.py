"""The rule plug-in boundary: what a plug-in is, what it may plan, and how one failing plug-in stays one gap.

A plug-in turns a change into obligations it can answer, reads what it needs through the Reader, and reports what it
found. It never reaches a network itself, keeps no state between attempts and holds no configuration values: its
inputs are the change model, the expected devices and the evidence the Reader recorded.

Planning, collection and evaluation are each isolated here. A plug-in that raises, plans something it does not own,
or claims a path of an atom that never changed becomes one bounded gap for that plug-in, and every other plug-in
still runs (controller ruling R22).
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from mist_config_guardian_backend.guardian.change import ChangedObject, ChangeSet, covers
from mist_config_guardian_backend.guardian.contracts import (
    MAX_IDENTIFIER_CHARS,
    MAX_RULE_READS,
    MAX_TEXT_CHARS,
    ChangeAtom,
    Conclusion,
    Evidence,
    EvidenceWindow,
    ExpectedDevice,
    Identifier,
    Obligation,
    RuleConclusion,
    RulePlan,
    Text,
    bound_reason,
)
from mist_config_guardian_backend.guardian.evidence import mentions_device, normalized_mac
from mist_config_guardian_backend.guardian.reader import Reader, RuleRead, RuleReading

MAX_PLUGIN_GAPS = 8
PLAN_FAILED = "planning failed"
COLLECTION_FAILED = "collection failed"
EVALUATION_FAILED = "evaluation failed"
PAIRED_READS = 2
NOT_READ_REASON = "The read this observation needs was not made"
PARTIAL_REASON = "The result was incomplete, so absence of a row establishes nothing"


class PluginError(ValueError):
    """A plug-in broke the plug-in contract. It becomes that plug-in's gap, never an aborted attempt."""


class RulePlugin(Protocol):
    """One deterministic rule. ``plan`` returns ``None`` when the change is outside what the plug-in addresses."""

    id: str
    version: str
    max_reads: int
    agent_hint: str

    def plan(self, change: ChangeSet, devices: Sequence[ExpectedDevice]) -> RulePlan | None:
        """The obligations and exclusions this plug-in takes on, or ``None`` when it does not apply."""
        ...

    async def collect(self, plan: RulePlan, reader: Reader) -> list[RuleReading]:
        """Everything the plan needs read, in a fixed order, through the Reader alone."""
        ...

    def evaluate(self, plan: RulePlan, readings: Sequence[RuleReading]) -> RuleConclusion:
        """A status for every rule obligation of the plan, with the severity and findings the reads show.

        A reading's full result is what the judgement is made from; only counts, judgements and identities that
        already pass the privacy rules leave this method, and the evidence it cites is the bounded stored one.
        """
        ...


class PluginPlan(RulePlan):
    """A plan that also carries what planning could not address, so evaluation reports it as this plug-in's gaps."""

    gaps: tuple[Text, ...] = ()


@dataclass(frozen=True, slots=True)
class ReadResult:
    """The rows of one read, or the single bounded reason the read cannot be relied on."""

    rows: tuple[Mapping[str, Any], ...] = ()
    reason: str = ""

    @property
    def complete(self) -> bool:
        return not self.reason


@dataclass(frozen=True, slots=True)
class RuleRun:
    """What the rule phase produced: the plans the ledger numbers, the evidence recorded, and each conclusion.

    ``conclusions`` is keyed by plug-in id and holds an entry for every plug-in that planned or failed. Statuses are
    keyed by the plug-in's own obligation ids, which only a plug-in present in ``plans`` can have mapped onto ledger
    ids. ``evidence`` holds the bounded, citable items alone: the full results the plug-ins judged from stay inside
    the attempt's Reader and are never handed on to be stored.
    """

    plans: dict[str, RulePlan] = field(default_factory=dict)
    evidence: dict[str, tuple[Evidence, ...]] = field(default_factory=dict)
    conclusions: dict[str, RuleConclusion] = field(default_factory=dict)


def rule_allowances(plugins: Iterable[RulePlugin]) -> dict[str, int]:
    """Each plug-in's declared read allowance, as the Reader charges it. Their sum stays within the attempt's own."""
    allowances = {plugin.id: plugin.max_reads for plugin in plugins}
    if sum(allowances.values()) > MAX_RULE_READS:
        msg = f"The plug-ins declare {sum(allowances.values())} reads, above the attempt's {MAX_RULE_READS}"
        raise PluginError(msg)
    return allowances


async def run_rules(
    plugins: Sequence[RulePlugin], change: ChangeSet, devices: Sequence[ExpectedDevice], reader: Reader
) -> RuleRun:
    """Plan, collect and evaluate every plug-in in id order, isolating each phase of each plug-in.

    A plug-in whose planning fails contributes no plan, so it claims no ledger row. One whose collection fails is
    still evaluated, but with no readings: :meth:`RulePlugin.collect` returns its readings only when it returns at
    all, so what it had already read cannot be recovered here. The evidence those reads recorded is still on the
    attempt — the Reader writes each one into the shared registry as it goes — but this plug-in cites none of it,
    and its obligations carry their own reasons beside the gap.
    """
    run = RuleRun()
    for plugin in sorted(plugins, key=lambda item: item.id):
        gaps: list[str] = []
        plan = _planned(plugin, change, devices, gaps)
        if plan is None:
            _record_gaps(run, plugin, gaps)
            continue
        run.plans[plugin.id] = plan
        readings = await _collected(plugin, plan, reader, gaps)
        run.evidence[plugin.id] = tuple(reading.evidence for reading in readings)
        run.conclusions[plugin.id] = _evaluated(plugin, plan, readings, gaps)
    return run


def validate_plan(plugin: RulePlugin, plan: RulePlan, change: ChangeSet) -> None:
    """Every item is the plug-in's own, names an atom of this change, and claims paths that atom really changed."""
    atoms = {atom.id: atom for atom in change.atoms}
    for item in (*plan.obligations, *plan.exclusions):
        if item.owner != plugin.id:
            msg = f"{plugin.id} planned an item owned by {item.owner}"
            raise PluginError(msg)
        if item.change_ref is None or item.change_ref not in atoms:
            msg = f"{plugin.id} refers to {item.change_ref}, which is not an atom of this change"
            raise PluginError(msg)
        changed = atoms[item.change_ref].paths
        for prefix in item.paths:
            if not any(covers(prefix, path) for path in changed):
                msg = f"{plugin.id} claims {'.'.join(prefix)}, which {item.change_ref} did not change"
                raise PluginError(msg)


def validate_conclusion(
    plugin: RulePlugin, plan: RulePlan, conclusion: RuleConclusion, readings: Sequence[RuleReading]
) -> None:
    """A plug-in reports on its own rule obligations and cites only citable evidence it collected."""
    own = {obligation.id for obligation in plan.obligations if obligation.kind == "rule"}
    if not set(conclusion.statuses) <= own:
        msg = f"{plugin.id} reported a status for an obligation it does not own"
        raise PluginError(msg)
    citable = {reading.id for reading in readings if reading.evidence.citable}
    cited = {
        identity
        for source in (*conclusion.statuses.values(), *conclusion.findings, *conclusion.impacted_devices)
        for identity in source.evidence_ids
    }
    if not cited <= citable:
        msg = f"{plugin.id} cited evidence it did not collect, or evidence that failed to collect"
        raise PluginError(msg)
    items = {reading.id: reading.evidence for reading in readings}
    for device in conclusion.impacted_devices:
        # The same rule an agent report is held to, and digest-aware for the same reason: a plug-in derives an
        # identity from the whole validated result while the stored item may be a digest of it (ruling R34).
        if not any(mentions_device(items[identity], device.mac) for identity in device.evidence_ids):
            msg = f"{plugin.id} reported {device.mac}, which the evidence it cites does not name"
            raise PluginError(msg)


# -- shared planning vocabulary ---------------------------------------------------------------------------------


def objects_of(change: ChangeSet, object_type: str, *, scope: str | None = None) -> list[ChangedObject]:
    """The changed objects of one registry type, in change-set order."""
    return [
        item for item in change.objects if item.object_type == object_type and (scope is None or item.scope == scope)
    ]


def atoms_of(change: ChangeSet, changed: ChangedObject) -> list[ChangeAtom]:
    """The atoms of one changed object version, in id order."""
    return [
        atom
        for atom in change.atoms
        if (atom.logical_object_id, atom.version) == (changed.logical_object_id, changed.version)
    ]


def cohort(devices: Sequence[ExpectedDevice], *, device_type: str, site_id: str | None = None) -> tuple[str, ...]:
    """The expected devices of one family, by MAC, optionally at one site.

    A device whose family no trigger established is not in any cohort: a mapping that applies to one family leaves
    such a device's rows uncovered instead of claiming them.
    """
    return tuple(
        sorted(
            device.mac for device in devices if device.device_type == device_type and site_id in (None, device.site_id)
        )
    )


def read_rows(reading: RuleReading | None, *, key: str = "results") -> ReadResult:
    """The rows of a read that can be relied on, or why it cannot be.

    The rows are the read's full validated result, not the bounded copy that will be stored: a result too large to
    store is still an answer. A partial collection is not, because rows are missing from the result itself — the
    provider said it was one page of more, or a row named a site this investigation may not read — and the ported
    clients treated anything but a complete response the same way.
    """
    if reading is None:
        return ReadResult(reason=NOT_READ_REASON)
    if reading.evidence.collection == "error":
        return ReadResult(reason=bound_reason(f"The read failed: {reading.evidence.detail}"))
    if reading.evidence.collection == "partial":
        return ReadResult(reason=PARTIAL_REASON)
    rows = reading.result.get(key)
    if not isinstance(rows, list):
        return ReadResult(reason=f"The result held no {key}")
    return ReadResult(rows=tuple(row for row in rows if isinstance(row, Mapping)))


async def read(reader: Reader, request: RuleRead) -> RuleReading:
    """One read, as a plug-in makes it: the bounded evidence to cite and the whole result to judge from."""
    evidence = await reader.read(request)
    return RuleReading(evidence=evidence, result=reader.full_result(evidence))


def window_start(reading: RuleReading) -> datetime:
    """When a read's window opens, for ordering a pair of reads; a read without one sorts first."""
    window = reading.evidence.window
    return window.start if window else datetime.min.replace(tzinfo=UTC)


def changed_at(window: EvidenceWindow) -> datetime:
    """The change a combined window is centred on: the Reader gives it equal halves on each side of the change."""
    return window.start + (window.end - window.start) / 2


def text(value: str) -> Text:
    """One finding or gap line, within the stored bound."""
    return value if len(value) <= MAX_TEXT_CHARS else f"{value[: MAX_TEXT_CHARS - 1]}…"


def string(value: object) -> str | None:
    """A payload field that must be a non-empty string to be used at all."""
    return value if isinstance(value, str) and value else None


def mac(value: object) -> str | None:
    """A device identity a payload names, normalized, or nothing when it is not one."""
    return normalized_mac(value)


def number(value: object) -> float | None:
    """A payload field that must be a real number, never a bool, to be used at all."""
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def gaps_within(gaps: Sequence[str]) -> tuple[Text, ...]:
    """The first few gaps, bounded, in the order they were found."""
    return tuple(text(gap) for gap in gaps[:MAX_PLUGIN_GAPS])


def obligation_ids(plan: RulePlan) -> tuple[str, ...]:
    """The plan's own rule obligation ids, in plan order."""
    return tuple(item.id for item in plan.obligations if item.kind == "rule")


def numbered(obligations: Sequence[Obligation]) -> tuple[Obligation, ...]:
    """The obligations under plan-local ids ``O1..On``, in the order the plug-in built them."""
    return tuple(item.model_copy(update={"id": f"O{index}"}) for index, item in enumerate(obligations, start=1))


def identifier(value: str) -> Identifier:
    """An identifier bounded to what a contract stores."""
    return value[:MAX_IDENTIFIER_CHARS]


# -- isolation ---------------------------------------------------------------------------------------------------


def _planned(
    plugin: RulePlugin, change: ChangeSet, devices: Sequence[ExpectedDevice], gaps: list[str]
) -> RulePlan | None:
    try:
        plan = plugin.plan(change, devices)
        if plan is not None:
            validate_plan(plugin, plan, change)
    except Exception as exc:  # noqa: BLE001 - one plug-in's planning failure is one gap, never an aborted attempt
        gaps.append(f"{plugin.id} {PLAN_FAILED}: {bound_reason(str(exc))}")
        return None
    return plan


async def _collected(plugin: RulePlugin, plan: RulePlan, reader: Reader, gaps: list[str]) -> tuple[RuleReading, ...]:
    try:
        return tuple(await plugin.collect(plan, reader))
    except Exception as exc:  # noqa: BLE001 - a refused or failed read leaves this plug-in's obligations unanswered
        # Whatever it read before it raised stays in the attempt's evidence registry, where the Reader put it; it
        # is only unavailable to this plug-in, because ``collect`` yields its readings only as a returned list.
        gaps.append(f"{plugin.id} {COLLECTION_FAILED}: {bound_reason(str(exc))}")
        return ()


def _evaluated(
    plugin: RulePlugin, plan: RulePlan, readings: tuple[RuleReading, ...], gaps: list[str]
) -> RuleConclusion:
    try:
        conclusion = plugin.evaluate(plan, readings)
        validate_conclusion(plugin, plan, conclusion, readings)
    except Exception as exc:  # noqa: BLE001 - an unevaluated plug-in reports nothing rather than failing the attempt
        gaps.append(f"{plugin.id} {EVALUATION_FAILED}: {bound_reason(str(exc))}")
        return Conclusion(gaps=gaps_within(gaps))
    return conclusion.model_copy(update={"gaps": gaps_within([*gaps, *conclusion.gaps])})


def _record_gaps(run: RuleRun, plugin: RulePlugin, gaps: list[str]) -> None:
    if gaps:
        run.conclusions[plugin.id] = Conclusion(gaps=gaps_within(gaps))
