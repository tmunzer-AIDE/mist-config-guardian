"""Guardian's evidence registry and aggregate byte budgets.

Every E-id is assigned when its read is reserved and is never renumbered. The registry refuses evidence above its
source's budget, so what reaches a run or a prompt is bounded before persistence, not after.

Each source degrades to a count-only digest that always fits: :func:`pack` keeps items in priority order while they
fit and counts the rest per category, and :func:`bounded` builds a view from that and re-measures it, dropping more
items until it fits. Budgets count serialized UTF-8 JSON bytes, with KB = 1,000 bytes.
"""

from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field, TypeAdapter
from pydantic_core import to_json

from mist_config_guardian_backend.guardian.contracts import (
    MAX_MCP_CALLS,
    MAX_RULE_READS,
    Contract,
    Evidence,
    EvidenceId,
    EvidenceSource,
)

if TYPE_CHECKING:
    from _typeshed import SupportsRichComparison

KB = 1_000

# The design's "Limits" table. The fixed part of every prompt:
SYSTEM_PROMPT_BUDGET = 3 * KB
TOOL_CATALOGUE_BUDGET = 8 * KB
CHANGE_VIEW_BUDGET = 6 * KB
DETERMINISTIC_VIEW_BUDGET = 6 * KB
MONITORING_EVIDENCE_BUDGET = 18 * KB
DEPLOYMENT_EVIDENCE_BUDGET = 4 * KB
FEEDBACK_BUDGET = 1 * KB
PROMPT_FIXED_BUDGET = 48 * KB
# Payloads a prompt may withhold, oldest MCP first:
RULE_EVIDENCE_ITEM_BUDGET = 4 * KB
MCP_EVIDENCE_ITEM_BUDGET = 4 * KB
PROMPT_WITHHOLDABLE_BUDGET = MAX_RULE_READS * RULE_EVIDENCE_ITEM_BUDGET + MAX_MCP_CALLS * MCP_EVIDENCE_ITEM_BUDGET
PROMPT_CAP = 96 * KB
# Stored on the run only:
LEDGER_VIEW_BUDGET = 24 * KB
CONCLUSIONS_BUDGET = 8 * KB
IMPACTED_DEVICES_BUDGET = 12 * KB
MODEL_OUTPUT_BUDGET = 3 * KB
STEPS_BUDGET = 40 * KB
RUN_STORED_BUDGET = 180 * KB
RUN_ENVELOPE_BUDGET = 8 * KB

# An id no attempt can exceed. Sizing an item under it before its id is reserved gives an upper bound.
WIDEST_EVIDENCE_ID = "E999999"

_ITEM_BUDGETS = {
    "deployment": DEPLOYMENT_EVIDENCE_BUDGET,
    "rule": RULE_EVIDENCE_ITEM_BUDGET,
    "mcp": MCP_EVIDENCE_ITEM_BUDGET,
}
_SOURCE_BUDGETS = {
    "monitoring": MONITORING_EVIDENCE_BUDGET,
    "deployment": DEPLOYMENT_EVIDENCE_BUDGET,
    "rule": MAX_RULE_READS * RULE_EVIDENCE_ITEM_BUDGET,
    "mcp": MAX_MCP_CALLS * MCP_EVIDENCE_ITEM_BUDGET,
}
_SOURCE = TypeAdapter(EvidenceSource)


def json_size(value: object) -> int:
    """Serialized UTF-8 JSON bytes, as every budget counts them."""
    return len(to_json(value))


class BudgetError(ValueError):
    """Even a count-only digest does not fit: its categories are not a small closed set. A programming error."""


class EvidenceError(ValueError):
    """Evidence was recorded without its reservation, twice, or above its source's budget."""


@dataclass(frozen=True, slots=True)
class Packed[T]:
    """Items kept in priority order, and how many of each category were left out."""

    kept: tuple[T, ...]
    omitted: dict[str, int]


def pack[T](  # noqa: PLR0913 - every argument is one decision of the budget
    items: Iterable[T],
    *,
    budget: int,
    priority: "Callable[[T], SupportsRichComparison]",
    category: Callable[[T], str],
    overhead: Callable[[Mapping[str, int], int], int],
    size: Callable[[T], int] = json_size,
) -> Packed[T]:
    """Keep items in priority order while they fit, and count the rest per category.

    ``priority`` must order items totally, so the result does not depend on input order. ``overhead(omitted, kept)``
    returns every byte besides the kept items themselves: the envelope, separators and the digest of those omitted
    counts. The result fits only as far as ``overhead`` is exact or an upper bound; :func:`bounded` re-measures what it
    builds instead of relying on that. Categories must come from a small closed set, so the digest alone always fits;
    if it does not, that is a programming error and :class:`BudgetError` is raised. An item too large for the space
    left is counted and packing continues with the next one.
    """
    ordered = sorted(items, key=priority)
    omitted = Counter(category(item) for item in ordered)
    if overhead(omitted, 0) > budget:
        msg = f"A count-only digest of {sum(omitted.values())} items does not fit {budget} bytes"
        raise BudgetError(msg)
    kept: list[T] = []
    used = 0
    for item in ordered:
        name = category(item)
        omitted[name] -= 1
        item_size = size(item)
        if used + item_size + overhead(omitted, len(kept) + 1) <= budget:
            kept.append(item)
            used += item_size
        else:
            omitted[name] += 1
    return Packed(kept=tuple(kept), omitted=_counts(omitted))


def _counts(omitted: Mapping[str, int]) -> dict[str, int]:
    return {name: count for name, count in sorted(omitted.items()) if count}


class Bounded[T](Contract):
    """A list kept within a byte budget: items in priority order and a count per category of those left out."""

    items: tuple[T, ...] = ()
    omitted: dict[str, int] = Field(default_factory=dict)

    @property
    def omitted_count(self) -> int:
        return sum(self.omitted.values())


def bounded[T, V: BaseModel](
    items: Iterable[T],
    *,
    budget: int,
    priority: "Callable[[T], SupportsRichComparison]",
    category: Callable[[T], str],
    build: Callable[[tuple[T, ...], dict[str, int]], V],
) -> V:
    """Build a view within ``budget`` from the items :func:`pack` keeps; it degrades, it never fails on size.

    ``build(items, omitted)`` embeds the kept items and their omitted counts. Packing estimates the wrapper as it is
    emitted, with nothing omitted and with a digest (a wrapper may change then, as a ``full``/``digest``
    representation does). The built view is then measured, and while it is still too large the lowest-priority kept
    item moves into the counts. That ends at the count-only digest, which :func:`pack` checks fits before anything
    else, so the only error is :class:`BudgetError` for a digest that cannot fit at all.
    """
    ordered = sorted(items, key=priority)
    everything = _counts(Counter(category(item) for item in ordered))
    digest_only = json_size(build((), everything))
    whole_wrapper = json_size(build((), {})) - json_size({})
    digest_wrapper = digest_only - json_size(everything)

    def overhead(omitted: Mapping[str, int], kept: int) -> int:
        counts = _counts(omitted)
        return (digest_wrapper if counts else whole_wrapper) + json_size(counts) + max(kept - 1, 0)

    packed = pack(ordered, budget=budget, priority=priority, category=category, overhead=overhead)
    kept = list(packed.kept)
    omitted = Counter(packed.omitted)
    view = build(tuple(kept), _counts(omitted))
    while kept and json_size(view) > budget:
        omitted[category(kept.pop())] += 1
        view = build(tuple(kept), _counts(omitted))
    return view


def _source_family(source: str) -> str:
    """``monitoring``, ``deployment``, ``rule`` or ``mcp``: the budget an evidence source draws on."""
    return source.split(":", 1)[0]


class EvidenceRegistry:
    """One attempt's evidence: E-ids assigned at reservation, in order, and never renumbered.

    Database (monitoring and deployment), rule and MCP evidence all take their ids here. A reservation that is never
    recorded, such as a read cut off by the deadline, leaves a gap in the numbering rather than a renumbering.
    """

    def __init__(self) -> None:
        self._reserved: dict[EvidenceId, EvidenceSource] = {}
        self._recorded: dict[EvidenceId, Evidence] = {}
        self._bytes: Counter[str] = Counter()

    def reserve(self, source: str) -> EvidenceId:
        """Assign the next E-id to a read from ``source`` before the read starts."""
        evidence_id = f"E{len(self._reserved) + 1}"
        self._reserved[evidence_id] = _SOURCE.validate_python(source)
        return evidence_id

    def record(self, evidence: Evidence) -> Evidence:
        """Store evidence under its reserved id, within the item and aggregate budgets of its source."""
        if self._reserved.get(evidence.id) != evidence.source:
            msg = f"{evidence.id} was not reserved for {evidence.source}"
            raise EvidenceError(msg)
        if evidence.id in self._recorded:
            msg = f"{evidence.id} is already recorded"
            raise EvidenceError(msg)
        family = _source_family(evidence.source)
        size = json_size(evidence)
        item_budget = _ITEM_BUDGETS.get(family)
        if item_budget is not None and size > item_budget:
            msg = f"{evidence.id} is {size} bytes, above the {item_budget}-byte {family} item budget"
            raise EvidenceError(msg)
        if self._bytes[family] + size > _SOURCE_BUDGETS[family]:
            msg = f"{evidence.id} would take {family} evidence above its {_SOURCE_BUDGETS[family]}-byte budget"
            raise EvidenceError(msg)
        self._bytes[family] += size
        self._recorded[evidence.id] = evidence
        return evidence

    def get(self, evidence_id: str) -> Evidence | None:
        return self._recorded.get(evidence_id)

    @property
    def evidence(self) -> tuple[Evidence, ...]:
        """Recorded evidence in E-id order, as a run stores it."""
        return tuple(sorted(self._recorded.values(), key=lambda item: int(item.id[1:])))
