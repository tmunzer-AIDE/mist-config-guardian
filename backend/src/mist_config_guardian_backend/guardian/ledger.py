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
VIEW_REFERENCES = 3

_RESOLUTION_ORDER: tuple[LedgerResolution, ...] = ("uncovered", "claimed", "excluded")
_STATUS_ORDER: tuple[StatusValue, ...] = ("unsatisfied", "not_exercised", "satisfied")
_LABEL_ORDER = ("anchor", "uncovered", "rule", "monitoring", "deployment")
_STRICTNESS: tuple[EmptyPolicy, ...] = ("not_exercised", "incomplete")


class LedgerError(ValueError):
    """The plans or devices given to the ledger break its contract: a programming error, never a data condition."""


class Ledger(Contract):
    """Rows, every obligation numbered once, the statuses the core already knows, and each plug-in's id map."""

    rows: tuple[LedgerRow, ...] = ()
    obligations: tuple[Obligation, ...] = ()
    statuses: dict[ObligationId, ObligationStatus] = Field(default_factory=dict)
    plan_ids: dict[PluginId, dict[ObligationId, ObligationId]] = Field(default_factory=dict)

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
) -> Ledger:
    """Resolve every atom-target row and number every obligation.

    Ids follow one order: the anchor precondition, plug-in obligations (plug-ins by id, each in plan order, a
    duplicate monitoring obligation folded into the first), deployment preconditions by MAC, then one unsatisfied
    observation per uncovered row in row order.
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
    rows = [(atom, target) for atom in change.atoms for target in _row_targets(change, atom, expected)]
    targeted = _ByTarget[str]()
    for global_id, obligation in claims:
        targeted.add(obligation.target, global_id)
    row_devices = {target.device_mac: target for _, target in rows if target.device_mac is not None}
    for mac in sorted(mac for mac, target in row_devices.items() if targeted.reaching(target)):
        obligations.append(
            Obligation(
                id=f"O{len(obligations) + 1}",
                owner=CORE_OWNER,
                role="precondition",
                kind="deployment",
                target=row_devices[mac],
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
    return Ledger(rows=tuple(ledger_rows), obligations=tuple(obligations), statuses=statuses, plan_ids=plan_ids)


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


class _ByTarget[T]:
    """Obligations or exclusions by the device or site their target names: which of them reach a row's device.

    A device target reaches the row of that device, unless it names another site. A site target with no device
    reaches every row device at that site. A target naming neither reaches no row. ``port_id`` and ``wlan_id`` narrow
    what is observed on the device; the paths say which changes that covers.
    """

    def __init__(self) -> None:
        self._devices: defaultdict[str, list[tuple[str | None, T]]] = defaultdict(list)
        self._sites: defaultdict[str, list[T]] = defaultdict(list)

    def add(self, target: Target, item: T) -> None:
        if target.device_mac is not None:
            self._devices[target.device_mac].append((target.site_id, item))
        elif target.site_id is not None:
            self._sites[target.site_id].append(item)

    def reaching(self, row: Target) -> list[T]:
        found = [
            item for site_id, item in self._devices.get(row.device_mac or "", ()) if site_id in (None, row.site_id)
        ]
        if row.site_id is not None:
            found.extend(self._sites.get(row.site_id, ()))
        return found


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


def _uncovered_reason(atom: ChangeAtom, row: LedgerRow) -> str:
    if atom.paths_complete:
        shown = ", ".join(".".join(path) for path in row.uncovered_paths[:VIEW_REFERENCES])
        more = len(row.uncovered_paths) - VIEW_REFERENCES
        paths = f"{shown} and {more} more" if more > 0 else shown
    else:
        paths = f"{atom.attribute} (changed paths truncated)"
    reason = f"no plugin addressed {atom.id} {paths} on {row.target.device_mac}"
    return reason if len(reason) <= MAX_TEXT_CHARS else f"{reason[: MAX_TEXT_CHARS - 1]}…"


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
    return "uncovered" if view.owner == CORE_OWNER and view.role == "observation" else view.kind


def _obligation_priority(view: ObligationView) -> tuple[int, int, int]:
    return (_STATUS_ORDER.index(view.status), _LABEL_ORDER.index(_label(view)), int(view.id[1:]))


def _obligation_category(view: ObligationView) -> str:
    return f"{_label(view)}:{view.status}"
