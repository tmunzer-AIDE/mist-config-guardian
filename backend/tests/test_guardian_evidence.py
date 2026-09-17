"""Guardian evidence: E-ids assigned at reservation, per-source budgets, and count-only digests that always fit."""

from datetime import UTC, datetime

import pytest

from mist_config_guardian_backend.guardian import evidence as budgets
from mist_config_guardian_backend.guardian.contracts import (
    MAX_MCP_CALLS,
    MAX_MODEL_TURNS,
    MAX_RULE_READS,
    RUN_DOCUMENT_MAX_BYTES,
    Contract,
    Evidence,
)
from mist_config_guardian_backend.guardian.evidence import (
    WIDEST_EVIDENCE_ID,
    Bounded,
    BudgetError,
    EvidenceError,
    EvidenceRegistry,
    bounded,
    json_size,
    pack,
)

NOW = datetime(2026, 9, 16, 4, 41, 35, tzinfo=UTC)


class Row(Contract):
    name: str
    rank: int
    group: str
    text: str = ""


def rows(count: int, *, text: str = "x" * 20) -> list[Row]:
    return [Row(name=f"row-{index:04}", rank=index % 3, group=f"g{index % 3}", text=text) for index in range(count)]


def rows_view(budget: int, items: list[Row]) -> Bounded[Row]:
    return bounded(
        items,
        budget=budget,
        priority=lambda row: (row.rank, row.name),
        category=lambda row: row.group,
        build=lambda kept, omitted: Bounded[Row](items=kept, omitted=omitted),
    )


def evidence(evidence_id: str, source: str, *, payload_bytes: int = 10, **overrides: object) -> Evidence:
    kind = {"monitoring": "service_health", "deployment": "deployment"}.get(source, "configuration")
    values = {
        "id": evidence_id,
        "source": source,
        "kind": kind,
        "title": "Evidence",
        "captured_at": NOW,
        "collection": "complete",
        "representation": "full",
        "payload": {"data": "p" * payload_bytes},
    }
    return Evidence.model_validate(values | overrides)


@pytest.mark.parametrize(
    ("name", "kb"),
    [
        ("SYSTEM_PROMPT_BUDGET", 3),
        ("TOOL_CATALOGUE_BUDGET", 8),
        ("CHANGE_VIEW_BUDGET", 6),
        ("DETERMINISTIC_VIEW_BUDGET", 6),
        ("MONITORING_EVIDENCE_BUDGET", 18),
        ("DEPLOYMENT_EVIDENCE_BUDGET", 4),
        ("FEEDBACK_BUDGET", 1),
        ("RULE_EVIDENCE_ITEM_BUDGET", 4),
        ("MCP_EVIDENCE_ITEM_BUDGET", 4),
        ("LEDGER_VIEW_BUDGET", 24),
        ("CONCLUSIONS_BUDGET", 8),
        ("IMPACTED_DEVICES_BUDGET", 12),
        ("MODEL_OUTPUT_BUDGET", 3),
        ("STEPS_BUDGET", 40),
        ("PROMPT_FIXED_BUDGET", 48),
        ("PROMPT_WITHHOLDABLE_BUDGET", 60),
        ("PROMPT_CAP", 96),
        ("RUN_STORED_BUDGET", 180),
    ],
)
def test_budgets_follow_the_limits_table_in_thousand_byte_kb(name, kb):
    assert getattr(budgets, name) == kb * 1_000


def test_budget_sums_hold_the_prompt_cap_and_the_run_bound():
    fixed = (
        budgets.SYSTEM_PROMPT_BUDGET
        + budgets.TOOL_CATALOGUE_BUDGET
        + budgets.CHANGE_VIEW_BUDGET
        + budgets.DETERMINISTIC_VIEW_BUDGET
        + budgets.MONITORING_EVIDENCE_BUDGET
        + budgets.DEPLOYMENT_EVIDENCE_BUDGET
        + budgets.FEEDBACK_BUDGET
    )
    withholdable = (MAX_RULE_READS * budgets.RULE_EVIDENCE_ITEM_BUDGET) + (
        MAX_MCP_CALLS * budgets.MCP_EVIDENCE_ITEM_BUDGET
    )
    stored = (
        budgets.CHANGE_VIEW_BUDGET
        + budgets.DETERMINISTIC_VIEW_BUDGET
        + budgets.MONITORING_EVIDENCE_BUDGET
        + budgets.DEPLOYMENT_EVIDENCE_BUDGET
        + withholdable
        + budgets.LEDGER_VIEW_BUDGET
        + budgets.CONCLUSIONS_BUDGET
        + budgets.IMPACTED_DEVICES_BUDGET
        + budgets.STEPS_BUDGET
    )

    assert fixed <= budgets.PROMPT_FIXED_BUDGET <= budgets.PROMPT_CAP
    assert withholdable == budgets.PROMPT_WITHHOLDABLE_BUDGET
    assert budgets.PROMPT_FIXED_BUDGET + withholdable > budgets.PROMPT_CAP  # so withholding is a real path
    assert MAX_MODEL_TURNS * budgets.MODEL_OUTPUT_BUDGET <= budgets.STEPS_BUDGET
    assert stored <= budgets.RUN_STORED_BUDGET
    assert budgets.RUN_STORED_BUDGET + budgets.RUN_ENVELOPE_BUDGET <= RUN_DOCUMENT_MAX_BYTES


def test_packing_keeps_priority_order_whatever_the_input_order():
    items = rows(40)

    def packed(ordering: list[Row]):
        return pack(
            ordering,
            budget=700,
            priority=lambda row: (row.rank, row.name),
            category=lambda row: row.group,
            overhead=lambda _omitted, _kept: 0,
        )

    expected = packed(items)
    for ordering in (items[::-1], items[1::2] + items[::2], items[17:] + items[:17]):
        assert packed(ordering) == expected
    assert [row.rank for row in expected.kept] == sorted(row.rank for row in expected.kept)
    assert expected.kept == tuple(sorted(items, key=lambda row: (row.rank, row.name))[: len(expected.kept)])


def test_digest_counts_every_omitted_item_by_category():
    items = rows(30)

    view = rows_view(600, items)

    assert 0 < len(view.items) < len(items)
    assert view.omitted_count == len(items) - len(view.items)
    for group in ("g0", "g1", "g2"):
        shown = sum(row.group == group for row in view.items)
        assert shown + view.omitted.get(group, 0) == sum(row.group == group for row in items)
    assert list(view.omitted) == sorted(view.omitted)
    assert all(count > 0 for count in view.omitted.values())


def test_a_view_is_the_largest_prefix_that_fits_exactly():
    items = sorted(rows(12), key=lambda row: (row.rank, row.name))
    for kept in range(len(items) + 1):
        remainder: dict[str, int] = {}
        for row in items[kept:]:
            remainder[row.group] = remainder.get(row.group, 0) + 1
        exact = json_size(Bounded[Row](items=tuple(items[:kept]), omitted=dict(sorted(remainder.items()))))

        assert len(rows_view(exact, items).items) == kept
        if kept:
            assert len(rows_view(exact - 1, items).items) == kept - 1


def test_an_item_too_large_for_the_space_left_is_counted_and_packing_continues():
    items = [Row(name="a", rank=0, group="big", text="x" * 2_000), *rows(5)]

    view = rows_view(800, items)

    assert "a" not in {row.name for row in view.items}
    assert view.omitted["big"] == 1
    assert len(view.items) == 5
    assert json_size(view) <= 800


def test_nothing_is_omitted_when_everything_fits():
    view = rows_view(10_000, rows(5))

    assert len(view.items) == 5
    assert view.omitted == {}


def test_a_digest_that_cannot_fit_is_a_programming_error():
    with pytest.raises(BudgetError, match="digest"):
        rows_view(20, rows(5))


def test_a_view_that_does_not_embed_its_items_as_measured_is_refused():
    class Doubled(Contract):
        first: tuple[Row, ...]
        second: tuple[Row, ...]
        omitted: dict[str, int]

    with pytest.raises(BudgetError, match="Doubled"):
        bounded(
            rows(20),
            budget=1_500,
            priority=lambda row: row.name,
            category=lambda row: row.group,
            build=lambda kept, omitted: Doubled(first=kept, second=kept, omitted=omitted),
        )


def test_registry_assigns_ids_at_reservation_across_sources_and_never_renumbers():
    registry = EvidenceRegistry()

    ids = [registry.reserve(source) for source in ("rule:switch-port", "monitoring", "mcp:search_events", "deployment")]
    registry.record(evidence(ids[3], "deployment"))
    registry.record(evidence(ids[1], "monitoring"))

    assert ids == ["E1", "E2", "E3", "E4"]
    assert [item.id for item in registry.evidence] == ["E2", "E4"]
    assert registry.reserve("mcp:search_events") == "E5"
    assert registry.get("E1") is None
    assert registry.get("E4") is not None


def test_stored_evidence_is_in_numeric_id_order():
    registry = EvidenceRegistry()
    ids = [registry.reserve("monitoring") for _ in range(11)]

    for evidence_id in reversed(ids):
        registry.record(evidence(evidence_id, "monitoring"))

    assert [item.id for item in registry.evidence] == [f"E{number}" for number in range(1, 12)]


@pytest.mark.parametrize(
    ("reserve_as", "record"),
    [
        (None, evidence("E1", "monitoring")),
        ("mcp:search_events", evidence("E1", "rule:switch-port")),
    ],
    ids=["unreserved", "other source"],
)
def test_evidence_is_recorded_only_under_its_own_reservation(reserve_as, record):
    registry = EvidenceRegistry()
    if reserve_as:
        registry.reserve(reserve_as)

    with pytest.raises(EvidenceError, match="not reserved"):
        registry.record(record)


def test_evidence_is_recorded_once():
    registry = EvidenceRegistry()
    registry.record(evidence(registry.reserve("monitoring"), "monitoring"))

    with pytest.raises(EvidenceError, match="already"):
        registry.record(evidence("E1", "monitoring"))


def test_an_unknown_source_cannot_be_reserved():
    with pytest.raises(ValueError, match="pattern"):
        EvidenceRegistry().reserve("webhook")


@pytest.mark.parametrize("source", ["rule:switch-port", "mcp:search_events", "deployment"])
def test_an_item_above_its_source_item_budget_is_refused(source):
    registry = EvidenceRegistry()
    evidence_id = registry.reserve(source)
    small = evidence(evidence_id, source, payload_bytes=3_000)
    assert json_size(small) <= 4_000

    with pytest.raises(EvidenceError, match="item budget"):
        registry.record(evidence(evidence_id, source, payload_bytes=4_000))
    assert registry.record(small) is small


@pytest.mark.parametrize(
    ("source", "aggregate", "fits"),
    [
        ("monitoring", 18_000, 6),
        ("rule:wlan-auth", 32_000, MAX_RULE_READS),
        ("mcp:search_events", 28_000, MAX_MCP_CALLS),
    ],
)
def test_a_source_cannot_exceed_its_aggregate_budget(source, aggregate, fits):
    registry = EvidenceRegistry()
    item_bytes = aggregate // fits - json_size(evidence("E9", source, payload_bytes=0))
    assert fits * json_size(evidence("E9", source, payload_bytes=item_bytes)) <= aggregate
    for _ in range(fits):
        registry.record(evidence(registry.reserve(source), source, payload_bytes=item_bytes))

    with pytest.raises(EvidenceError, match="above its"):
        registry.record(evidence(registry.reserve(source), source, payload_bytes=item_bytes))


def test_sizing_under_the_widest_id_bounds_the_reserved_item():
    placeholder = evidence(WIDEST_EVIDENCE_ID, "monitoring")

    assert json_size(placeholder.model_copy(update={"id": "E12"})) <= json_size(placeholder)
