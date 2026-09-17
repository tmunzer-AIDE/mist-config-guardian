"""The Guardian design's external facts are recorded, frozen and cannot drift silently."""

import copy
import json
import re
from datetime import datetime, timedelta

import pytest

from guardian_verification import (
    DNS_SEMANTICS,
    EVIDENCE_KINDS,
    REPO_ROOT,
    RESULTS,
    ToolNotAllowlistedError,
    UnknownDnsAttributeError,
    decision,
    dns_mappings,
    dns_semantics_errors,
    evidence_kind,
    fixture_errors,
    load_fixture,
    load_verification,
    schema_sha256,
    sha256_file,
    verification_errors,
)
from mist_config_guardian_backend.snapshots.registry import DEFAULT_IGNORED_FIELDS

TRIGGER = re.compile(r"^(AP|SW|GW)_CONFIG_CHANGED_BY_USER$")
OUTCOME = re.compile(r"^(AP|SW|GW)_(CONFIGURED|CONFIG_FAILED|CONFIG_REVERTED)$")
DEVICE_PREFIX = {"AP": "ap", "SW": "switch", "GW": "gateway"}


def at(value: str) -> datetime:
    return datetime.fromisoformat(value)


def invariant(record: dict, invariant_id: str) -> dict:
    (match,) = [row for row in record["dnt_ntr_expected_outcomes"]["invariants"] if row["id"] == invariant_id]
    return match


# Decision record gate


def test_every_decision_is_recorded_with_its_fixture_hashes():
    assert verification_errors(load_verification()) == []


@pytest.mark.parametrize("decision_id", sorted(RESULTS))
def test_a_missing_decision_fails_the_gate(decision_id):
    record = load_verification()
    record["decisions"] = [item for item in record["decisions"] if item["id"] != decision_id]
    assert f"decision {decision_id!r} is missing" in verification_errors(record)


def test_a_drifted_fixture_hash_fails_the_gate():
    record = load_verification()
    fixture = decision(record, "dns_attribute_semantics")["fixtures"][0]
    fixture["sha256"] = "0" * 64
    assert any("sha256 drifted" in error for error in verification_errors(record))


@pytest.mark.parametrize(
    ("decision_id", "change", "expected"),
    [
        ("sw_configured_emission", {"result": "assumed"}, "is not one of"),
        ("sw_configured_emission", {"fixtures": []}, "must cite at least one fixture"),
        ("structured_output_capability", {"reason": None}, "must give a reason"),
        ("device_event_ordering", {"observed_at": "2026-09-17T13:52:26"}, "must carry a timezone"),
        ("mcp_evidence_kind_allowlist", {"source": None}, "source is missing"),
    ],
)
def test_an_incomplete_decision_fails_the_gate(decision_id, change, expected):
    record = load_verification()
    decision(record, decision_id).update(change)
    assert any(expected in error for error in verification_errors(record))


def test_a_duplicated_decision_fails_the_gate():
    record = load_verification()
    record["decisions"].append(copy.deepcopy(decision(record, "device_event_ordering")))
    assert "decision 'device_event_ordering' is recorded more than once" in verification_errors(record)


def test_the_recorded_results_are_the_conservative_ones():
    record = load_verification()
    ordering = decision(record, "device_event_ordering")
    assert ordering["result"] == "same_second_ambiguous"
    assert ordering["details"]["device_event_timestamp_precision"] == "second"
    assert ordering["details"]["sequence_field"] is None
    assert decision(record, "sw_configured_emission")["result"] == "unknown"
    capability = decision(record, "structured_output_capability")
    assert capability["result"] == "inconclusive"
    assert capability["details"]["provider_fingerprint"] is None


# Event ordering


def test_the_provider_contract_has_no_sequence_field_and_second_timestamps():
    contract = load_fixture("mist_event_timestamp_contract.json")
    event = contract["device_event"]
    assert event["additional_properties"] is False
    assert not [name for name in event["properties"] if re.search(r"seq|order|offset|cursor|index|serial", name)]
    assert event["timestamp"]["description"] == "Epoch timestamp, in seconds"
    assert contract["source"]["sha256"] == decision(load_verification(), "device_event_ordering")["source"][0]["sha256"]


def test_recorded_device_events_are_whole_seconds_while_the_audit_is_sub_second():
    change = load_fixture("dnt_ntr_change.json")
    receipts = load_fixture("dnt_ntr_device_events.json")["receipts"]
    assert at(change["audit"]["occurred_at"]).microsecond == 242_000
    assert {at(receipt["occurred_at"]).microsecond for receipt in receipts} == {0}


# DNT-NTR invariants that hold for any DNS mapping


def test_second_precision_removes_the_sub_second_anchor_regression():
    change = load_fixture("dnt_ntr_change.json")
    receipts = load_fixture("dnt_ntr_device_events.json")["receipts"]
    anchor = at(change["audit"]["occurred_at"])
    triggers = [receipt for receipt in receipts if TRIGGER.match(receipt["event_type"])]
    outcomes = [receipt for receipt in receipts if OUTCOME.match(receipt["event_type"])]
    assert all(DEVICE_PREFIX[row["event_type"][:2]] == row["device_type"] for row in [*triggers, *outcomes])

    # The legacy millisecond comparison placed every trigger before the change.
    assert all(at(trigger["occurred_at"]) < anchor for trigger in triggers)
    assert all(at(trigger["occurred_at"]) >= anchor.replace(microsecond=0) for trigger in triggers)
    assert {trigger["audit_id"] for trigger in triggers} == {change["audit"]["audit_id"]}
    by_device = {trigger["device_mac"]: trigger for trigger in triggers}
    assert len(by_device) == len(triggers)  # No same-second trigger conflict on any device.
    for outcome in outcomes:
        delay = at(outcome["occurred_at"]) - at(by_device[outcome["device_mac"]]["occurred_at"])
        assert timedelta(0) <= delay <= timedelta(minutes=30)

    recorded = invariant(load_verification(), "no_false_deployment_unknown_at_second_precision")
    assert sorted(recorded["devices"]) == sorted(by_device) == sorted(d["device_mac"] for d in change["devices"])


def test_every_unconfirmed_switch_is_recorded_as_an_unsatisfied_precondition():
    receipts = load_fixture("dnt_ntr_device_events.json")["receipts"]
    switches = {row["device_mac"] for row in receipts if row["event_type"] == "SW_CONFIG_CHANGED_BY_USER"}
    confirmed = {row["device_mac"] for row in receipts if row["event_type"] == "SW_CONFIGURED"}
    assert not [row for row in receipts if row["event_type"].endswith(("_CONFIG_FAILED", "_CONFIG_REVERTED"))]
    recorded = invariant(load_verification(), "unconfirmed_switch_precondition_unsatisfied")
    assert sorted(recorded["devices"]) == sorted(switches - confirmed)
    assert len(recorded["devices"]) == 3


def test_dnt_ntr_expectations_stay_conditional_while_a_dependency_is_open():
    record = load_verification()
    expected = record["dnt_ntr_expected_outcomes"]
    assert set(expected["depends_on"]) <= set(RESULTS)
    assert fixture_errors("dnt_ntr_expected_outcomes", expected["fixtures"]) == []
    change = load_fixture("dnt_ntr_change.json")
    unverified = [
        row
        for changed in change["changed_objects"]
        for field in changed["changed_fields"]
        if field not in DEFAULT_IGNORED_FIELDS
        for row in dns_mappings(f"{changed['scope']}:{changed['object_type']}", field)
        if row["semantics"] == "unverified"
    ]
    open_dependency = bool(unverified) or decision(record, "sw_configured_emission")["result"] == "unknown"
    assert expected["status"] == ("conditional" if open_dependency else "fixed")
    assert {condition["decision"] for condition in expected["conditions"]} <= set(expected["depends_on"])


def test_dnt_ntr_fixtures_are_pseudonymized_reconstructions():
    change = load_fixture("dnt_ntr_change.json")
    monitoring = load_fixture("dnt_ntr_monitoring.json")
    events = load_fixture("dnt_ntr_device_events.json")
    synthetic_uuid = re.compile(r"^[1-3]0000000-0000-4000-8000-0{11}\d$")
    synthetic_object_id = re.compile(r"^0{20}[0-9a-f]{4}$")
    synthetic_mac = re.compile(r"^020000\d{6}$")
    for document in (change, monitoring, events):
        assert "reconstructed from API projections" in document["label"]
        assert synthetic_uuid.match(document["site_id"])
    assert synthetic_uuid.match(change["organization_id"])
    assert synthetic_uuid.match(events["organization_id"])
    assert synthetic_uuid.match(change["audit"]["audit_id"])
    assert all(synthetic_object_id.match(row["logical_object_id"]) for row in change["changed_objects"])
    assert all(synthetic_mac.match(row["device_mac"]) for row in change["devices"])
    assert all(synthetic_object_id.match(row["session_id"]) for row in monitoring["sessions"])
    assert all(synthetic_mac.match(row["device_mac"]) for row in monitoring["sessions"])
    assert all(synthetic_object_id.match(row["receipt_id"]) for row in events["receipts"])
    assert all(synthetic_mac.match(row["device_mac"]) for row in events["receipts"])


# DNS attribute semantics


def test_dns_semantics_are_complete_and_cite_the_schema():
    table = load_fixture("dns_attribute_semantics.json")
    schema_source = decision(load_verification(), "dns_attribute_semantics")["source"][0]
    assert table["source"]["sha256"] == schema_source["sha256"]
    assert set(table["semantics"]) == DNS_SEMANTICS
    assert dns_semantics_errors(table) == []


@pytest.mark.parametrize("semantics", ["unknown", "management", None])
def test_an_unknown_dns_class_is_rejected(semantics):
    table = load_fixture("dns_attribute_semantics.json")
    table["mappings"][0]["semantics"] = semantics
    assert any("is not one of" in error for error in dns_semantics_errors(table))


def test_a_dns_class_without_targets_is_rejected():
    table = load_fixture("dns_attribute_semantics.json")
    (row,) = dns_mappings("org:networktemplates", "dns_servers", semantics=table)
    row["device_types"] = []
    assert any("device_types must be empty" in error for error in dns_semantics_errors(table))


@pytest.mark.parametrize(
    ("object_type", "attribute", "variant"),
    [
        ("org:networktemplates", "ntp_servers", None),
        ("org:unknownobjects", "dns_servers", None),
        ("site:devices", "ip_config", None),
        ("site:devices", "dns_servers", "ap"),
    ],
)
def test_an_unknown_dns_attribute_is_rejected(object_type, attribute, variant):
    with pytest.raises(UnknownDnsAttributeError):
        dns_mappings(object_type, attribute, variant=variant)


@pytest.mark.parametrize(
    ("object_type", "path", "variant", "device_type"),
    [
        ("org:networktemplates", ["dns_servers"], None, "switch"),  # The DNT-NTR change.
        ("org:networktemplates", ["dns_suffix"], None, "switch"),
        ("org:switchprofiles", ["ip_config", "dns"], None, "switch"),
        ("org:gatewaytemplates", ["dnsOverride"], None, "gateway"),
        ("site:devices", ["dns_servers"], "switch", "switch"),
        ("site:devices", ["dns_servers"], "gateway", "gateway"),
        ("site:settings", ["gateway", "dns_servers"], None, "gateway"),
    ],
)
def test_dual_use_resolver_settings_carry_both_classes(object_type, path, variant, device_type):
    (row,) = [row for row in dns_mappings(object_type, path[0], variant=variant) if path in row["paths"]]
    assert row["semantics"] == "management_and_client_resolution"
    assert row["device_types"] == [device_type]
    assert "if not defined, system one will be used" in row["reason"]


def test_every_documented_dual_use_row_carries_both_classes():
    rows = load_fixture("dns_attribute_semantics.json")["mappings"]
    fallback = [row for row in rows if "system one will be used" in row["reason"]]
    assert len(fallback) == 18
    assert {row["semantics"] for row in fallback} == {"management_and_client_resolution"}
    assert len({row["reason"] for row in fallback}) == 1


def test_recorded_dns_attributes_resolve_to_their_semantics():
    assert [row["semantics"] for row in dns_mappings("site:settings", "dns_servers")] == ["unverified"]
    assert [row["semantics"] for row in dns_mappings("site:devices", "ip_config", variant="ap")] == [
        "management_resolution"
    ]
    (dhcp,) = dns_mappings("site:devices", "dhcpd_config", variant="gateway")
    assert dhcp["semantics"] == "client_resolution"
    assert dhcp["device_types"] == ["gateway"]


# MCP evidence-kind allowlist


def test_the_allowlist_is_frozen_from_the_recorded_catalogue():
    allowlist = load_fixture("mcp_allowlist.json")
    catalogue_path = REPO_ROOT / allowlist["source"]["catalogue"]
    assert sha256_file(catalogue_path) == allowlist["source"]["catalogue_sha256"]
    tools = {tool["name"]: tool for tool in json.loads(catalogue_path.read_text(encoding="utf-8"))}
    assert set(allowlist["tools"]) | set(allowlist["excluded_tools"]) == set(tools)
    assert not set(allowlist["tools"]) & set(allowlist["excluded_tools"])
    assert {"psks", "webhooks"} <= set(allowlist["tools"]["get_mist_config"]["excluded"])
    for name, entry in allowlist["tools"].items():
        schema = tools[name]["inputSchema"]
        assert tools[name]["annotations"]["readOnlyHint"] is True
        assert schema_sha256(schema) == entry["input_schema_sha256"]
        assert "$ref" not in str(schema)
        assert entry["discriminator"] in schema["required"]
        values = schema["properties"][entry["discriminator"]]["enum"]
        assert not set(entry["kinds"]) & set(entry["excluded"])
        assert set(entry["kinds"]) | set(entry["excluded"]) == set(values)
        assert set(entry["kinds"].values()) <= EVIDENCE_KINDS


@pytest.mark.parametrize(
    ("tool", "arguments", "kind"),
    [
        ("search_mist_data", {"search_type": "device_events"}, "service_health"),
        ("search_mist_data", {"search_type": "client_sessions"}, "service_health"),
        ("get_mist_stats", {"stats_type": "site_ports"}, "service_health"),
        ("get_mist_insights", {"insight_type": "sle"}, "service_health"),
        ("get_mist_config", {"resource_type": "networktemplates"}, "configuration"),
        ("get_mist_constants", {"constant_type": "device_events"}, "reference"),
    ],
)
def test_allowlisted_calls_resolve_to_their_evidence_kind(tool, arguments, kind):
    assert evidence_kind(tool, arguments) == kind


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("get_mist_self", {}),
        ("find_mist_entity", {"query": "aabbccddeeff"}),
        ("mist_change_configuration_objects", {"object_type": "org_wlans"}),
        ("search_mist_data", {"search_type": "rogue_events"}),
        ("search_mist_data", {"search_type": "inventory"}),
        ("get_mist_config", {"resource_type": "psks"}),
        ("get_mist_config", {"resource_type": "webhooks"}),
        ("search_mist_data", {"search_type": "not_a_search_type"}),
        ("search_mist_data", {}),
        ("get_mist_config", {"resource_type": ["networktemplates"]}),
        ("get_mist_stats", {"search_type": "device_events"}),
    ],
)
def test_a_tool_or_discriminator_absent_from_the_allowlist_is_rejected(tool, arguments):
    with pytest.raises(ToolNotAllowlistedError):
        evidence_kind(tool, arguments)
