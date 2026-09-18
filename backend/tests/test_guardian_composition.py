"""Guardian's verdict composition: one pure function over separately stored conclusions.

Every case here is the spec's "Verdict composition" numbered rules, driven as a table: the base from deterministic
coverage, the warning-and-above floor, an agent contribution that needs a cited service-health item, confidence,
recovery, sources, impacted devices and gaps.
"""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from mist_config_guardian_backend.guardian.composition import (
    MAX_VERDICT_GAPS,
    NOT_EXERCISED_SUMMARY,
    DeviceSeverity,
    compose,
)
from mist_config_guardian_backend.guardian.contracts import (
    AgentConclusion,
    CompactImpactedDevice,
    Conclusion,
    DeviceImpact,
    Evidence,
    Finding,
    Verdict,
    band_rank,
)
from mist_config_guardian_backend.guardian.evidence import IMPACTED_DEVICES_BUDGET, json_size

NOW = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)
SITE = "978c48e6-6ef6-11e6-8bbf-02e208b2d34f"
MAC = "5c5b35000001"
OTHER_MAC = "5c5b35000002"


def health(identity: str = "E1", **overrides) -> Evidence:
    values = {
        "id": identity,
        "source": "monitoring",
        "kind": "service_health",
        "title": "Monitoring 5c5b35000001",
        "captured_at": NOW,
        "collection": "complete",
        "representation": "full",
    }
    return Evidence.model_validate(values | overrides)


DEPLOYMENT_ITEM = health("E2", source="deployment", kind="deployment", title="Deployment pairing")
CONFIGURATION_ITEM = health("E3", source="mcp:get_mist_config", kind="configuration", title="WLANs")
EVIDENCE = (health(), DEPLOYMENT_ITEM, CONFIGURATION_ITEM)


def report(**overrides) -> AgentConclusion:
    values = {
        "concluded": True,
        "peak": "warning",
        "current": "none",
        "confidence": "low",
        "summary": "Clients reconnected within the window.",
        "evidence_ids": ("E1",),
    }
    return AgentConclusion.model_validate(values | overrides)


def device(mac: str = MAC, **overrides) -> DeviceSeverity:
    values = {"mac": mac, "site_id": SITE, "name": "ap-1", "peak": "none", "current": "none"}
    return DeviceSeverity.model_validate(values | overrides)


# --- rule 1: the base from deterministic coverage -------------------------------------------------------------


@pytest.mark.parametrize(
    ("coverage", "peak", "current"),
    [
        ("complete", "none", "none"),
        ("not_applicable", "info", "info"),
        ("partial", "info", "info"),
        ("insufficient", "info", "info"),
    ],
)
def test_the_base_comes_from_deterministic_coverage(coverage, peak, current) -> None:
    verdict = compose(coverage=coverage)

    assert (verdict.peak, verdict.current) == (peak, current)
    assert verdict.coverage == coverage


def test_not_applicable_coverage_says_the_change_was_not_exercised() -> None:
    assert compose(coverage="not_applicable").summary == NOT_EXERCISED_SUMMARY


def test_a_floor_replaces_the_not_exercised_sentence() -> None:
    verdict = compose(coverage="not_applicable", deployment=Conclusion(peak="warning", current="warning"))

    assert verdict.summary != NOT_EXERCISED_SUMMARY
    assert verdict.peak == "warning"


# --- rule 2: the floor counts warning and critical only --------------------------------------------------------


@pytest.mark.parametrize(
    ("source_peak", "source_current", "peak", "current"),
    [
        ("none", "none", "none", "none"),
        ("info", "info", "none", "none"),
        ("warning", "none", "warning", "none"),
        ("warning", "warning", "warning", "warning"),
        ("critical", "info", "critical", "none"),
        ("critical", "critical", "critical", "critical"),
    ],
)
@pytest.mark.parametrize("name", ["monitoring", "deployment", "rules"])
def test_only_warning_and_above_sets_a_floor(name, source_peak, source_current, peak, current) -> None:
    conclusion = Conclusion(peak=source_peak, current=source_current)
    inputs = {name: {"wlan-removal": conclusion} if name == "rules" else conclusion}

    verdict = compose(coverage="complete", **inputs)

    assert (verdict.peak, verdict.current) == (peak, current)


def test_the_floor_is_the_maximum_over_every_deterministic_source() -> None:
    verdict = compose(
        coverage="complete",
        monitoring=Conclusion(peak="warning", current="none"),
        deployment=Conclusion(peak="warning", current="warning"),
        rules={"switch-port": Conclusion(peak="critical", current="none")},
    )

    assert (verdict.peak, verdict.current) == ("critical", "warning")


# --- rule 3 and 4: the agent contributes only with a cited service-health item ----------------------------------


def test_an_agent_report_citing_service_health_contributes_its_bands() -> None:
    verdict = compose(coverage="partial", agent=report(peak="critical", current="warning"), evidence=EVIDENCE)

    assert (verdict.peak, verdict.current) == ("critical", "warning")
    assert "agent" in verdict.sources


@pytest.mark.parametrize("cited", [(), ("E2",), ("E3",), ("E2", "E3")])
def test_an_agent_report_without_a_cited_service_health_item_changes_nothing(cited) -> None:
    verdict = compose(
        coverage="partial", agent=report(peak="critical", current="critical", evidence_ids=cited), evidence=EVIDENCE
    )

    assert (verdict.peak, verdict.current) == ("info", "info")
    assert "agent" not in verdict.sources
    assert verdict.confidence == "low"


def test_service_health_cited_from_a_finding_contributes() -> None:
    agent = report(
        peak="warning",
        current="warning",
        evidence_ids=(),
        findings=(Finding(text="Clients dropped", severity="warning", evidence_ids=("E1",)),),
    )

    assert compose(coverage="partial", agent=agent, evidence=EVIDENCE).peak == "warning"


def test_an_agent_that_did_not_conclude_adds_its_reason_as_a_gap() -> None:
    agent = AgentConclusion(concluded=False, reason="The provider returned no usable action")

    verdict = compose(coverage="partial", agent=agent, evidence=EVIDENCE)

    assert verdict.peak == "info"
    assert [gap.text for gap in verdict.gaps] == ["AI agent did not conclude: The provider returned no usable action"]
    assert [gap.source for gap in verdict.gaps] == ["agent"]


def test_an_agent_below_the_published_peak_is_recorded_as_a_gap() -> None:
    verdict = compose(
        coverage="partial",
        monitoring=Conclusion(peak="critical", current="critical"),
        agent=report(peak="warning", current="warning"),
        evidence=EVIDENCE,
    )

    assert verdict.peak == "critical"
    assert "AI assessment (warning) was below the published verdict (critical)" in [g.text for g in verdict.gaps]


def test_an_agent_at_or_above_the_published_peak_adds_no_such_gap() -> None:
    verdict = compose(
        coverage="partial",
        monitoring=Conclusion(peak="warning", current="warning"),
        agent=report(peak="warning", current="warning"),
        evidence=EVIDENCE,
    )

    assert not verdict.gaps


# --- rule 5: confidence ----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("agent_peak", "floor_peak", "confidence"),
    [
        ("warning", "warning", "medium"),
        ("warning", "critical", "low"),
        ("critical", "warning", "medium"),
        (None, "warning", "low"),
    ],
)
def test_confidence_is_medium_only_when_a_contributing_agent_matches_the_published_peak(
    agent_peak, floor_peak, confidence
) -> None:
    agent = None if agent_peak is None else report(peak=agent_peak, current="none")

    verdict = compose(
        coverage="partial", monitoring=Conclusion(peak=floor_peak, current="none"), agent=agent, evidence=EVIDENCE
    )

    assert verdict.confidence == confidence


@pytest.mark.parametrize("coverage", ["complete", "not_applicable", "partial", "insufficient"])
def test_confidence_stays_low_without_a_contributing_agent(coverage) -> None:
    assert compose(coverage=coverage).confidence == "low"
    assert compose(coverage=coverage, agent=report(peak="none", current="none", evidence_ids=())).confidence == "low"


def test_a_monitoring_backed_none_reaches_medium_when_the_agent_concurs() -> None:
    verdict = compose(coverage="complete", agent=report(peak="none", current="none"), evidence=EVIDENCE)

    assert (verdict.peak, verdict.confidence, verdict.coverage) == ("none", "medium", "complete")


# --- rule 6: recovery ------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("peak", "current", "recovery"),
    [
        ("none", "none", "none"),
        ("warning", "none", "recovered"),
        ("critical", "info", "recovered"),
        ("warning", "warning", "unrecovered"),
        ("critical", "critical", "unrecovered"),
    ],
)
def test_recovery_follows_the_published_bands(peak, current, recovery) -> None:
    verdict = compose(coverage="complete", monitoring=Conclusion(peak=peak, current=current))

    assert verdict.recovery == recovery


# --- rule 7: sources -------------------------------------------------------------------------------------------


def test_the_base_names_the_coverage_inputs() -> None:
    verdict = compose(
        coverage="complete",
        monitoring=Conclusion(),
        deployment=Conclusion(),
        rules={"dns": Conclusion(), "wlan-auth": Conclusion()},
    )

    assert verdict.sources == ("monitoring", "deployment", "rule:dns", "rule:wlan-auth")


def test_a_floor_names_only_the_inputs_that_set_it() -> None:
    verdict = compose(
        coverage="partial",
        monitoring=Conclusion(peak="warning", current="warning"),
        deployment=Conclusion(),
        rules={"switch-port": Conclusion(peak="critical", current="none")},
    )

    assert verdict.peak == "critical"
    assert verdict.sources == ("monitoring", "rule:switch-port")


def test_the_agent_is_a_source_when_it_alone_sets_the_published_bands() -> None:
    verdict = compose(coverage="partial", agent=report(peak="warning", current="warning"), evidence=EVIDENCE)

    assert verdict.sources == ("agent",)


def test_sources_are_empty_when_nothing_was_available() -> None:
    assert compose(coverage="insufficient").sources == ()


# --- impacted devices ------------------------------------------------------------------------------------------


def test_impacted_devices_carry_the_replay_peak_and_current() -> None:
    verdict = compose(
        coverage="partial",
        monitoring=Conclusion(peak="warning", current="none"),
        devices=(device(peak="warning", current="none"), device(OTHER_MAC, peak="none", current="none")),
    )

    assert [(row.mac, row.peak, row.current, row.name) for row in verdict.impacted_devices] == [
        (MAC, "warning", "none", "ap-1")
    ]


def test_a_rule_device_is_listed_with_its_sources_current_as_its_ceiling() -> None:
    rules = {
        "wlan-removal": Conclusion(
            peak="warning",
            current="none",
            impacted_devices=(DeviceImpact(mac=MAC, severity="warning", evidence_ids=("E1",)),),
        )
    }

    verdict = compose(coverage="partial", rules=rules, devices=(device(),))

    assert [(row.mac, row.peak, row.current) for row in verdict.impacted_devices] == [(MAC, "warning", "none")]


def test_devices_are_worst_first_and_never_exceed_the_published_peak() -> None:
    monitoring = Conclusion(peak="critical", current="critical")
    rows = (
        device(MAC, peak="warning", current="none"),
        device(OTHER_MAC, peak="critical", current="critical"),
    )

    verdict = compose(coverage="partial", monitoring=monitoring, devices=rows)

    assert [row.mac for row in verdict.impacted_devices] == [OTHER_MAC, MAC]
    assert all(row.peak in ("warning", "critical") for row in verdict.impacted_devices)


def test_an_unidentified_impacted_device_is_counted_in_a_gap_rather_than_listed() -> None:
    rules = {
        "switch-port": Conclusion(
            peak="warning",
            current="warning",
            impacted_devices=(DeviceImpact(mac=OTHER_MAC, severity="warning", evidence_ids=("E1",)),),
        )
    }

    verdict = compose(coverage="partial", rules=rules)

    assert verdict.impacted_devices == ()
    assert any("1 impacted device" in gap.text and gap.source == "core" for gap in verdict.gaps)


def test_impacted_devices_stay_within_their_budget_and_count_what_was_left_out() -> None:
    rows = tuple(
        device(f"5c5b35{index:06d}", name="ap-" + "n" * 100, peak="warning", current="warning") for index in range(900)
    )

    verdict = compose(coverage="partial", monitoring=Conclusion(peak="warning", current="warning"), devices=rows)

    assert json_size(verdict.impacted_devices) <= IMPACTED_DEVICES_BUDGET
    assert len(verdict.impacted_devices) + verdict.impacted_devices_omitted == len(rows)
    assert verdict.impacted_devices_omitted > 0


def test_an_agent_device_is_listed_only_while_the_agent_contributes() -> None:
    agent = report(
        peak="warning",
        current="warning",
        impacted_devices=(DeviceImpact(mac=MAC, severity="warning", evidence_ids=("E1",)),),
    )
    uncited = report(
        peak="warning",
        current="warning",
        evidence_ids=(),
        impacted_devices=(DeviceImpact(mac=MAC, severity="warning", evidence_ids=("E2",)),),
    )

    listed = compose(coverage="partial", agent=agent, evidence=EVIDENCE, devices=(device(),))
    ignored = compose(coverage="partial", agent=uncited, evidence=EVIDENCE, devices=(device(),))

    assert [row.mac for row in listed.impacted_devices] == [MAC]
    assert (ignored.peak, ignored.impacted_devices) == ("info", ())


# --- gaps ------------------------------------------------------------------------------------------------------


def test_every_conclusions_gaps_are_kept_under_their_own_source() -> None:
    verdict = compose(
        coverage="partial",
        monitoring=Conclusion(gaps=("shared session",)),
        deployment=Conclusion(gaps=("receipt time only",)),
        rules={"dns": Conclusion(gaps=("no mapping",))},
        agent=AgentConclusion(concluded=True, peak="info", current="info", confidence="low", gaps=("thin evidence",)),
        evidence=EVIDENCE,
    )

    assert [(gap.source, gap.text) for gap in verdict.gaps] == [
        ("monitoring", "shared session"),
        ("deployment", "receipt time only"),
        ("rule:dns", "no mapping"),
        ("agent", "thin evidence"),
    ]


def test_duplicate_gaps_from_one_source_are_kept_once() -> None:
    verdict = compose(coverage="partial", monitoring=Conclusion(gaps=("shared session", "shared session")))

    assert len(verdict.gaps) == 1


def test_gaps_are_capped_and_the_rest_are_counted() -> None:
    rules = {f"rule{index}": Conclusion(gaps=tuple(f"gap {index}.{n}" for n in range(8))) for index in range(6)}

    verdict = compose(coverage="partial", rules=rules)

    assert len(verdict.gaps) == MAX_VERDICT_GAPS + 1
    assert verdict.gaps[-1].source == "core"
    assert "24 further gap" in verdict.gaps[-1].text


# --- ruling R36: composition is a total function ----------------------------------------------------------------


def test_a_device_row_cannot_be_worse_now_than_it_ever_was() -> None:
    with pytest.raises(ValidationError, match="cannot exceed peak"):
        DeviceSeverity(mac=MAC, site_id=SITE, peak="warning", current="critical")


def test_a_verdict_cannot_list_a_device_above_its_own_peak() -> None:
    with pytest.raises(ValidationError, match="exceed the verdict's peak"):
        Verdict(
            peak="info",
            current="info",
            recovery="none",
            confidence="low",
            coverage="partial",
            summary="",
            impacted_devices=(CompactImpactedDevice(mac=MAC, site_id=SITE, peak="critical", current="critical"),),
        )


@pytest.mark.parametrize("coverage", ["complete", "partial", "insufficient", "not_applicable"])
@pytest.mark.parametrize(("peak", "current"), [("warning", "none"), ("critical", "critical"), ("info", "info")])
def test_a_measured_device_never_outruns_the_verdict_that_lists_it(coverage, peak, current) -> None:
    """A device row is the monitoring replay's own measurement, so it is part of the floor it was measured for."""
    verdict = compose(coverage=coverage, devices=(device(peak=peak, current=current),))

    assert all(band_rank(row.peak) <= band_rank(verdict.peak) for row in verdict.impacted_devices)
    assert all(band_rank(row.current) <= band_rank(verdict.current) for row in verdict.impacted_devices)


def test_a_device_row_raises_the_floor_its_conclusion_understated() -> None:
    verdict = compose(
        coverage="partial",
        monitoring=Conclusion(peak="warning", current="none"),
        devices=(device(peak="critical", current="critical"),),
    )

    assert (verdict.peak, verdict.current) == ("critical", "critical")
    assert verdict.sources == ("monitoring",)
