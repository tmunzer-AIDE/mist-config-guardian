"""Guardian's coverage ledger: every change atom on every applicable target, and what addresses it.

The ledger takes the plug-ins' plans as they are and adds what only the core may add: the anchor precondition, the
deployment preconditions and an unsatisfied observation for every uncovered row. It numbers every obligation
``O<n>`` once, in a deterministic order, and maps each plug-in's own ids onto those numbers. Coverage is always
evaluated over the full ledger; the views only decide what is shown within their budgets.
"""

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence

from pydantic import Field

from mist_config_guardian_backend.guardian.change import ChangeSet, covers
from mist_config_guardian_backend.guardian.contracts import (
    CORE_OWNER,
    INPUT_OBLIGATION_KIND,
    MAX_TEXT_CHARS,
    AnchorSource,
    AtomId,
    ChangeAtom,
    ConfigPath,
    Contract,
    Coverage,
    DeviceMac,
    EmptyPolicy,
    EvidenceId,
    Exclusion,
    ExpectedDevice,
    Identifier,
    LedgerResolution,
    LedgerRow,
    Obligation,
    ObligationId,
    ObligationKind,
    ObligationRole,
    ObligationStatus,
    PluginId,
    RulePlan,
    StatusValue,
    Target,
    Text,
)
from mist_config_guardian_backend.guardian.evidence import (
    DETERMINISTIC_VIEW_BUDGET,
    LEDGER_VIEW_BUDGET,
    Bounded,
    bounded,
)

ANCHOR_REASON = "change time is unknown"
NO_STATUS_REASON = "No status was reported"
# An atom whose applicable targets are the expected devices, of which this audit has none, resolves to no row at
# all. They are recorded here rather than left to the coverage that happens to remain, so an audit that also
# changed a device object cannot publish complete coverage while they went unexamined. One reason covers them all:
# they are one condition, and repeating it per atom would crowd every other gap out of the lists that show them.
UNTARGETED_REASON = (
    "{count} change{plural} ({named}) apply to this audit's expected devices, of which it linked none; no ledger "
    "row covers {pronoun}"
)
VIEW_REFERENCES = 3

_RESOLUTION_ORDER: tuple[LedgerResolution, ...] = ("uncovered", "claimed", "excluded")
_STATUS_ORDER: tuple[StatusValue, ...] = ("unsatisfied", "not_exercised", "satisfied")
_LABEL_ORDER = ("anchor", "input", "uncovered", "rule", "monitoring", "deployment")
_STRICTNESS: tuple[EmptyPolicy, ...] = ("not_exercised", "incomplete")


class LedgerError(ValueError):
    """The plans or devices given to the ledger break its contract: a programming error, never a data condition."""


class Ledger(Contract):
    """Rows, every obligation numbered once, the statuses the core already knows, and each plug-in's id map.

    ``gaps`` are the core gaps this ledger raised, each one paired with an unsatisfied core observation above, so
    the caller composes exactly the gaps whose obligations already hold coverage down.
    """

    rows: tuple[LedgerRow, ...] = ()
    obligations: tuple[Obligation, ...] = ()
    statuses: dict[ObligationId, ObligationStatus] = Field(default_factory=dict)
    plan_ids: dict[PluginId, dict[ObligationId, ObligationId]] = Field(default_factory=dict)
    gaps: tuple[Text, ...] = ()

    def with_gaps(self, reasons: Iterable[str]) -> "Ledger":
        """This ledger plus one unsatisfied core observation per gap found after it was built.

        A phase that fails owns no obligation of its own unless a plug-in happened to plan one, so without this a
        failed monitoring or deployment phase could leave every planned obligation satisfied and publish complete
        coverage over evidence nobody collected. These reasons lead ``gaps``, because a phase that did not run
        tells a reader more than the per-change detail behind it; the obligations keep ledger numbering order.
        """
        late = tuple(_bounded(reason) for reason in reasons)
        if not late:
            return self
        obligations = list(self.obligations)
        statuses = dict(self.statuses)
        _append_gaps(obligations, statuses, late)
        return self.model_copy(
            update={"obligations": tuple(obligations), "statuses": statuses, "gaps": (*late, *self.gaps)}
        )

    def rule_statuses(
        self, plugin: str, statuses: Mapping[str, ObligationStatus]
    ) -> dict[ObligationId, ObligationStatus]:
        """A plug-in's statuses, keyed by its own ids, re-keyed to ledger ids. Only its rule obligations qualify."""
        ids = self.plan_ids.get(plugin)
        if ids is None:
            msg = f"{plugin} has no plan in this ledger"
            raise LedgerError(msg)
        own_rules = {o.id for o in self.obligations if o.owner == plugin and o.kind == "rule"}
        mapped: dict[ObligationId, ObligationStatus] = {}
        for local, value in statuses.items():
            if ids.get(local) not in own_rules:
                msg = f"{local} is not a rule obligation {plugin} planned"
                raise LedgerError(msg)
            mapped[ids[local]] = value
        return mapped


def build_ledger(
    change: ChangeSet,
    devices: Iterable[ExpectedDevice],
    plans: Mapping[str, RulePlan],
    anchor: AnchorSource,
    inputs: Sequence[str] = (),
) -> Ledger:
    """Resolve every atom-target row and number every obligation.

    Ids follow one order: the anchor precondition, plug-in obligations (plug-ins by id, each in plan order, a
    duplicate monitoring obligation folded into the first), deployment preconditions by MAC, one unsatisfied
    observation per uncovered row in row order, and last one unsatisfied ``input`` observation per input the
    attempt could not see in full and one for the atoms that resolved to no row at all.

    ``inputs`` are those inputs, each already a bounded reason. They claim no atom, because the atom is exactly
    what could not be built, and they are always unsatisfied, so a run that silently dropped part of what it was
    asked to judge can never publish complete coverage. Every atom with no applicable target joins them under one
    shared reason, for the same purpose: they are changes this attempt was asked to judge and placed on nothing,
    and without an obligation the only thing between them and complete coverage would be whatever other rows
    happen to be uncovered.
    """
    expected = _expected_devices(devices)
    atoms = {atom.id: atom for atom in change.atoms}
    _check_plans(plans, atoms)
    obligations: list[Obligation] = []
    statuses: dict[str, ObligationStatus] = {}
    if anchor == "receipt":
        obligations.append(Obligation(id="O1", owner=CORE_OWNER, role="precondition", kind="anchor", target=Target()))
        statuses["O1"] = ObligationStatus(status="unsatisfied", reason=ANCHOR_REASON)

    plan_ids, claims = _number_plan_obligations(plans, obligations)
    placed = {atom.id: _row_targets(change, atom, expected) for atom in change.atoms}
    rows = [(atom, target) for atom in change.atoms for target in placed[atom.id]]
    untargeted = _untargeted_reason(change, [atom for atom in change.atoms if not placed[atom.id]])
    targeted = _ByTarget[str]()
    for global_id, obligation in claims:
        targeted.add(obligation.target, global_id)
    row_devices = RowDevices(target for _, target in rows)
    for mac in [mac for mac, target in row_devices.targets.items() if targeted.reaching(target)]:
        obligations.append(
            Obligation(
                id=f"O{len(obligations) + 1}",
                owner=CORE_OWNER,
                role="precondition",
                kind="deployment",
                target=row_devices.targets[mac],
            )
        )

    resolver = _RowResolver(claims, [e for plugin in sorted(plans) for e in plans[plugin].exclusions])
    ledger_rows: list[LedgerRow] = []
    for atom, target in rows:
        row = resolver.resolve(atom, target)
        ledger_rows.append(row)
        if row.resolution == "uncovered":
            observation = Obligation(
                id=f"O{len(obligations) + 1}",
                owner=CORE_OWNER,
                change_ref=atom.id,
                paths=row.uncovered_paths,
                role="observation",
                kind="rule",
                target=target,
            )
            obligations.append(observation)
            statuses[observation.id] = ObligationStatus(status="unsatisfied", reason=_uncovered_reason(atom, row))
    gaps = tuple(_bounded(reason) for reason in (*inputs, *untargeted))
    _append_gaps(obligations, statuses, gaps)
    return Ledger(
        rows=tuple(ledger_rows),
        obligations=tuple(obligations),
        statuses=statuses,
        plan_ids=plan_ids,
        gaps=gaps,
    )


def resolve_statuses(ledger: Ledger, reported: Mapping[str, ObligationStatus]) -> dict[ObligationId, ObligationStatus]:
    """A status for every obligation: the core's own statuses win, and an obligation nobody reported is unsatisfied."""
    unreported = ObligationStatus(status="unsatisfied", reason=NO_STATUS_REASON)
    return {o.id: ledger.statuses.get(o.id) or reported.get(o.id) or unreported for o in ledger.obligations}


def coverage(ledger: Ledger, reported: Mapping[str, ObligationStatus]) -> Coverage:
    """The deterministic coverage table, in its order.

    A precondition that is anything but satisfied, including one reported as not exercised, leaves coverage partial:
    the table only reaches not_applicable or complete when every precondition is satisfied.
    """
    statuses = resolve_statuses(ledger, reported)
    observations = [statuses[o.id].status for o in ledger.obligations if o.role == "observation"]
    preconditions = [statuses[o.id].status for o in ledger.obligations if o.role == "precondition"]
    if not observations:
        return "insufficient"
    if "unsatisfied" in observations or any(value != "satisfied" for value in preconditions):
        return "partial"
    if all(value == "not_exercised" for value in observations):
        return "not_applicable"
    return "complete"


class RowView(Contract):
    """A ledger row for display: its first few obligation ids and uncovered paths, with their totals."""

    atom_id: AtomId
    device_mac: DeviceMac | None = None
    site_id: Identifier | None = None
    resolution: LedgerResolution
    obligation_ids: tuple[ObligationId, ...] = Field(default=(), max_length=VIEW_REFERENCES)
    obligation_count: int = Field(ge=0)
    uncovered_paths: tuple[ConfigPath, ...] = Field(default=(), max_length=VIEW_REFERENCES)
    uncovered_count: int = Field(ge=0)


class ObligationView(Contract):
    """An obligation with its resolved status, without its paths: rows and the change view show those."""

    id: ObligationId
    owner: PluginId
    kind: ObligationKind
    role: ObligationRole
    change_ref: AtomId | None = None
    target: Target
    metric: Identifier | None = None
    status: StatusValue
    reason: Text | None = None
    evidence_ids: tuple[EvidenceId, ...] = ()


class LedgerView(Contract):
    rows: Bounded[RowView] = Bounded[RowView]()
    obligations: Bounded[ObligationView] = Bounded[ObligationView]()


class DeterministicView(Contract):
    coverage: Coverage
    unsatisfied: Bounded[ObligationView] = Bounded[ObligationView]()


def ledger_view(
    ledger: Ledger, reported: Mapping[str, ObligationStatus], *, budget: int = LEDGER_VIEW_BUDGET
) -> LedgerView:
    """Rows (uncovered first) within half the budget, then obligation statuses (unsatisfied first) in the rest."""
    rows = bounded(
        [_row_view(row) for row in ledger.rows],
        budget=budget // 2,
        priority=lambda row: (_RESOLUTION_ORDER.index(row.resolution), int(row.atom_id[1:]), row.device_mac or ""),
        category=lambda row: row.resolution,
        build=lambda kept, omitted: LedgerView(rows=Bounded[RowView](items=kept, omitted=omitted)),
    ).rows
    return bounded(
        _obligation_views(ledger, reported),
        budget=budget,
        priority=_obligation_priority,
        category=_obligation_category,
        build=lambda kept, omitted: LedgerView(
            rows=rows, obligations=Bounded[ObligationView](items=kept, omitted=omitted)
        ),
    )


def deterministic_view(
    ledger: Ledger, reported: Mapping[str, ObligationStatus], *, budget: int = DETERMINISTIC_VIEW_BUDGET
) -> DeterministicView:
    """Coverage and the unsatisfied obligations behind it, the anchor and uncovered rows first.

    Every uncovered row is one of these obligations, carrying its atom, target and reason.
    """
    covered = coverage(ledger, reported)
    return bounded(
        [view for view in _obligation_views(ledger, reported) if view.status == "unsatisfied"],
        budget=budget,
        priority=_obligation_priority,
        category=_obligation_category,
        build=lambda kept, omitted: DeterministicView(
            coverage=covered, unsatisfied=Bounded[ObligationView](items=kept, omitted=omitted)
        ),
    )


def reaches(target: Target, row: Target) -> bool:
    """The one targeting rule: whether an obligation or exclusion target reaches a row's device.

    A device target reaches the row of that device, unless it names another site. A site target with no device
    reaches every row device at that site. A target naming neither reaches no row. ``port_id`` and ``wlan_id`` narrow
    what is observed on the device; the paths say which changes that covers.
    """
    if target.device_mac is not None:
        return target.device_mac == row.device_mac and target.site_id in (None, row.site_id)
    return target.site_id is not None and target.site_id == row.site_id


class RowDevices:
    """Every device a ledger row targets, and the row devices a target reaches under :func:`reaches`.

    Replays evaluate exactly these devices, so monitoring, deployment pairing and the deployment preconditions agree
    on which devices a change applies to and which of them an obligation targets.
    """

    def __init__(self, row_targets: Iterable[Target]) -> None:
        targets: dict[str, Target] = {}
        for target in row_targets:
            if target.device_mac is not None:
                targets[target.device_mac] = target
        self._targets = dict(sorted(targets.items()))
        self._by_site: defaultdict[str, list[str]] = defaultdict(list)
        for mac, target in self._targets.items():
            if target.site_id is not None:
                self._by_site[target.site_id].append(mac)

    @classmethod
    def of(cls, ledger: Ledger) -> "RowDevices":
        return cls(row.target for row in ledger.rows)

    @property
    def targets(self) -> Mapping[str, Target]:
        """Each row device's target, by MAC in order."""
        return self._targets

    def reached_by(self, target: Target) -> tuple[str, ...]:
        """The row devices ``target`` reaches, by MAC."""
        if target.device_mac is not None:
            indexed: Sequence[str] = (target.device_mac,) if target.device_mac in self._targets else ()
        else:
            indexed = self._by_site.get(target.site_id or "", ())
        return tuple(mac for mac in indexed if reaches(target, self._targets[mac]))


class _ByTarget[T]:
    """Obligations or exclusions indexed by the device or site their target names, answering which of them reach a
    row under :func:`reaches`."""

    def __init__(self) -> None:
        self._devices: defaultdict[str, list[tuple[Target, T]]] = defaultdict(list)
        self._sites: defaultdict[str, list[tuple[Target, T]]] = defaultdict(list)

    def add(self, target: Target, item: T) -> None:
        if target.device_mac is not None:
            self._devices[target.device_mac].append((target, item))
        elif target.site_id is not None:
            self._sites[target.site_id].append((target, item))

    def reaching(self, row: Target) -> list[T]:
        indexed = (*self._devices.get(row.device_mac or "", ()), *self._sites.get(row.site_id or "", ()))
        return [item for target, item in indexed if reaches(target, row)]


class _RowResolver:
    """Resolves rows from claims and exclusions indexed by atom and target, caching coverage per prefix set."""

    def __init__(self, claims: Sequence[tuple[str, Obligation]], exclusions: Sequence[Exclusion]) -> None:
        self._claims: defaultdict[str, _ByTarget[tuple[str, frozenset[ConfigPath]]]] = defaultdict(_ByTarget)
        for global_id, obligation in claims:
            if obligation.change_ref is not None:
                self._claims[obligation.change_ref].add(obligation.target, (global_id, frozenset(obligation.paths)))
        self._exclusions: defaultdict[str, _ByTarget[frozenset[ConfigPath]]] = defaultdict(_ByTarget)
        for exclusion in exclusions:
            self._exclusions[exclusion.change_ref].add(exclusion.target, frozenset(exclusion.paths))
        self._missing: dict[tuple[str, frozenset[ConfigPath]], tuple[ConfigPath, ...]] = {}

    def resolve(self, atom: ChangeAtom, target: Target) -> LedgerRow:
        claims = self._claims[atom.id].reaching(target)
        contributing = sorted(
            {obligation_id for obligation_id, paths in claims if self._uncovered(atom, paths) != atom.paths},
            key=lambda obligation_id: int(obligation_id[1:]),
        )
        prefixes = frozenset().union(*(paths for _, paths in claims), *self._exclusions[atom.id].reaching(target))
        missing = self._uncovered(atom, prefixes)
        if not atom.paths_complete or missing:
            uncovered = missing if atom.paths_complete else ((atom.attribute,),)
            return LedgerRow(
                atom_id=atom.id,
                target=target,
                resolution="uncovered",
                obligation_ids=tuple(contributing),
                uncovered_paths=uncovered,
            )
        resolution: LedgerResolution = "claimed" if contributing else "excluded"
        return LedgerRow(atom_id=atom.id, target=target, resolution=resolution, obligation_ids=tuple(contributing))

    def _uncovered(self, atom: ChangeAtom, prefixes: frozenset[ConfigPath]) -> tuple[ConfigPath, ...]:
        key = (atom.id, prefixes)
        if key not in self._missing:
            self._missing[key] = tuple(
                path for path in atom.paths if not any(covers(prefix, path) for prefix in prefixes)
            )
        return self._missing[key]


def _expected_devices(devices: Iterable[ExpectedDevice]) -> dict[str, ExpectedDevice]:
    expected: dict[str, ExpectedDevice] = {}
    for item in devices:
        if item.mac in expected:
            msg = f"Expected device {item.mac} appears more than once"
            raise LedgerError(msg)
        expected[item.mac] = item
    return dict(sorted(expected.items()))


def _check_plans(plans: Mapping[str, RulePlan], atoms: Mapping[str, ChangeAtom]) -> None:
    for plugin, plan in plans.items():
        if plugin == CORE_OWNER:
            msg = f"{CORE_OWNER} owns core obligations and cannot be a plug-in"
            raise LedgerError(msg)
        for item in (*plan.obligations, *plan.exclusions):
            if item.owner != plugin:
                msg = f"{plugin}'s plan holds an item owned by {item.owner}"
                raise LedgerError(msg)
            if item.change_ref not in atoms:
                msg = f"{plugin} refers to {item.change_ref}, which is not an atom of this change"
                raise LedgerError(msg)


def _number_plan_obligations(
    plans: Mapping[str, RulePlan], obligations: list[Obligation]
) -> tuple[dict[str, dict[str, str]], list[tuple[str, Obligation]]]:
    """Append plug-in obligations under ledger ids; return each plug-in's id map and every obligation as planned."""
    plan_ids: dict[str, dict[str, str]] = {}
    claims: list[tuple[str, Obligation]] = []
    monitored: dict[tuple[Target, str | None], int] = {}
    for plugin in sorted(plans):
        ids = plan_ids.setdefault(plugin, {})
        for obligation in plans[plugin].obligations:
            key = (obligation.target, obligation.metric)
            if obligation.kind == "monitoring" and key in monitored:
                index = monitored[key]
                merged = obligations[index]
                policies = (merged.empty_policy, obligation.empty_policy)
                strictest = max(policies, key=lambda policy: _STRICTNESS.index(policy) if policy else -1)
                obligations[index] = merged.model_copy(update={"empty_policy": strictest})
            else:
                if obligation.kind == "monitoring":
                    monitored[key] = len(obligations)
                obligations.append(obligation.model_copy(update={"id": f"O{len(obligations) + 1}"}))
                index = len(obligations) - 1
            ids[obligation.id] = obligations[index].id
            claims.append((obligations[index].id, obligation))
    return plan_ids, claims


def _row_targets(change: ChangeSet, atom: ChangeAtom, expected: Mapping[str, ExpectedDevice]) -> list[Target]:
    changed = change.object_of(atom)
    if changed.device_mac is not None:
        return [Target(device_mac=changed.device_mac, site_id=changed.site_id)]
    return [Target(device_mac=item.mac, site_id=item.site_id) for item in expected.values()]


def _append_gaps(obligations: list[Obligation], statuses: dict[str, ObligationStatus], reasons: Iterable[Text]) -> None:
    """One unsatisfied core observation per gap reason, numbered after every obligation already there.

    These carry the ``input`` kind: each says the attempt could not see something it was asked to judge, and an
    unsatisfied observation is what keeps coverage off complete until it can.
    """
    for reason in reasons:
        missing = Obligation(
            id=f"O{len(obligations) + 1}",
            owner=CORE_OWNER,
            role="observation",
            kind=INPUT_OBLIGATION_KIND,
            target=Target(),
        )
        obligations.append(missing)
        statuses[missing.id] = ObligationStatus(status="unsatisfied", reason=reason)


def _untargeted_reason(change: ChangeSet, atoms: Sequence[ChangeAtom]) -> tuple[str, ...]:
    """The one reason covering every atom that sat on no row, or nothing when they all did.

    They share a single obligation rather than one each: they are all the same condition, and one per atom would
    fill the verdict's gap list and the agent's deterministic view with repetition, crowding out the phase
    failures and uncovered rows a reader needs first.
    """
    if not atoms:
        return ()
    named = ", ".join(
        f"{atom.id} {atom.attribute} on {change.object_of(atom).name or change.object_of(atom).logical_object_id}"
        for atom in atoms[:VIEW_REFERENCES]
    )
    more = len(atoms) - VIEW_REFERENCES
    return (
        UNTARGETED_REASON.format(
            count=len(atoms),
            plural="" if len(atoms) == 1 else "s",
            named=f"{named} and {more} more" if more > 0 else named,
            pronoun="it" if len(atoms) == 1 else "them",
        ),
    )


def _bounded(reason: str) -> Text:
    """One stored reason within what a contract holds."""
    return reason if len(reason) <= MAX_TEXT_CHARS else f"{reason[: MAX_TEXT_CHARS - 1]}…"


def _uncovered_reason(atom: ChangeAtom, row: LedgerRow) -> str:
    if atom.paths_complete:
        shown = ", ".join(".".join(path) for path in row.uncovered_paths[:VIEW_REFERENCES])
        more = len(row.uncovered_paths) - VIEW_REFERENCES
        paths = f"{shown} and {more} more" if more > 0 else shown
    else:
        paths = f"{atom.attribute} (changed paths truncated)"
    return _bounded(f"no plugin addressed {atom.id} {paths} on {row.target.device_mac}")


def _row_view(row: LedgerRow) -> RowView:
    return RowView(
        atom_id=row.atom_id,
        device_mac=row.target.device_mac,
        site_id=row.target.site_id,
        resolution=row.resolution,
        obligation_ids=row.obligation_ids[:VIEW_REFERENCES],
        obligation_count=len(row.obligation_ids),
        uncovered_paths=row.uncovered_paths[:VIEW_REFERENCES],
        uncovered_count=len(row.uncovered_paths),
    )


def _obligation_views(ledger: Ledger, reported: Mapping[str, ObligationStatus]) -> list[ObligationView]:
    statuses = resolve_statuses(ledger, reported)
    return [
        ObligationView(
            id=o.id,
            owner=o.owner,
            kind=o.kind,
            role=o.role,
            change_ref=o.change_ref,
            target=o.target,
            metric=o.metric,
            status=statuses[o.id].status,
            reason=statuses[o.id].reason,
            evidence_ids=statuses[o.id].evidence_ids,
        )
        for o in ledger.obligations
    ]


def _label(view: ObligationView) -> str:
    """How a view names an obligation: an input names itself, because it is derived from no change at all."""
    if view.kind == INPUT_OBLIGATION_KIND:
        return INPUT_OBLIGATION_KIND
    return "uncovered" if view.owner == CORE_OWNER and view.role == "observation" else view.kind


def _obligation_priority(view: ObligationView) -> tuple[int, int, int]:
    return (_STATUS_ORDER.index(view.status), _LABEL_ORDER.index(_label(view)), int(view.id[1:]))


def _obligation_category(view: ObligationView) -> str:
    return f"{_label(view)}:{view.status}"
