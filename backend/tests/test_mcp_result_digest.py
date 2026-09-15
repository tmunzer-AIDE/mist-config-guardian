"""Oversized MCP results become bounded, citable server digests instead of omissions."""

import json
from datetime import timedelta
from uuid import UUID, uuid4

import pytest

from mist_config_guardian_backend.impact.mcp_contracts import MAX_MCP_EVIDENCE_BYTES, McpEvidence, McpReportAction
from mist_config_guardian_backend.impact.mcp_scope import (
    McpScope,
    McpScopeError,
    normalize_result,
    normalize_result_detail,
)
from mist_config_guardian_backend.services import mcp_impact_agent
from test_impact_agent import AI_URL, ai_response, read_context
from test_mcp_investigation import MIST_ORG, mcp_responses, mcp_runtime
from test_wlan_investigation import LATER, NOW, SITE

LATE_MAC = "aabbccdd0027"  # First appears in row 39, beyond every shown-row bound.


def events(count=200, secret=""):
    return {
        "search_type": "device_events",
        "total": count,
        "results": [
            {
                "org_id": MIST_ORG,
                "site_id": SITE,
                "mac": f"aabbccdd{n % 40:04x}",
                "type": "SW_PORT_UP" if n < 80 else "SW_PORT_DOWN",
                "timestamp": int((NOW + timedelta(seconds=(n - 80) * 30)).timestamp()),
                "text": f"Port ge-0/0/{n % 48} changed state {secret}",
                "severity": n % 5,
            }
            for n in range(count)
        ],
    }


def test_oversized_result_becomes_bounded_digest_with_change_buckets():
    normalized = normalize_result_detail(
        {"structuredContent": events(secret="test-token")}, secrets=("test-token",), changed_at=NOW
    )
    assert normalized.reduction == "digest"
    assert normalized.partial
    data = normalized.data
    assert len(json.dumps(data, ensure_ascii=False).encode()) <= MAX_MCP_EVIDENCE_BYTES
    assert "test-token" not in json.dumps(data)
    assert (data["total"], data["search_type"]) == (200, "device_events")
    assert data["digest"]["rows_shown_per_list"] == len(data["results"])
    summary = data["results_summary"]
    assert (summary["row_count"], summary["time_field"], summary["changed_at"]) == (
        200,
        "timestamp",
        int(NOW.timestamp()),
    )
    buckets = {(b["field"], b["value"]): (b["before_change"], b["after_change"]) for b in summary["change_buckets"]}
    assert buckets[("type", "SW_PORT_UP")] == (80, 0)
    assert buckets[("type", "SW_PORT_DOWN")] == (0, 120)
    assert {"field": "severity", "count": 200, "min": 0.0, "max": 4.0, "avg": 2.0} in summary["numeric"]
    assert not any(v["field"] in {"text", "mac"} for v in summary["value_counts"])  # High cardinality.
    assert len(summary["devices"]) == 40


def test_digest_keeps_device_identities_beyond_shown_rows_citable():
    data = normalize_result_detail({"structuredContent": events()}, changed_at=NOW).data
    assert LATE_MAC not in {row["mac"] for row in data["results"]}
    evidence = McpEvidence(
        id=uuid4(),
        tool="search_mist_data",
        arguments={"search_type": "device_events"},
        data=data,
        state="partial",
        captured_at=LATER,
        schema_hash="test",
    )
    assert McpScope.contains_device(evidence, UUID(SITE), LATE_MAC)
    scope = McpScope(org_id=UUID(MIST_ORG), changed_at=NOW, as_of=LATER, sites=[SITE])
    scope.observe("search_mist_data", {"search_type": "device_events"}, data)
    assert (SITE, LATE_MAC) in scope.devices
    action = McpReportAction.model_validate(
        {
            "action": "report",
            "report": {
                "summary": "Port-down events appeared only after the change.",
                "scope": "Device events for the changed site.",
                "impact": "warning",
                "confidence": "low",
                "coverage": "partial",
                "evidence": [str(evidence.id)],
                "impacted_devices": [
                    {
                        "device_mac": LATE_MAC,
                        "site_id": SITE,
                        "service": "switching",
                        "impact": "warning",
                        "evidence": [str(evidence.id)],
                        "explanation": "Port-down events for this switch after the change.",
                    }
                ],
                "views": [
                    {
                        "evidence_id": str(evidence.id),
                        "kind": "bar",
                        "rows_path": ["results_summary", "change_buckets"],
                        "label_key": "value",
                        "value_key": "after_change",
                    }
                ],
            },
        }
    )
    cleaned = mcp_impact_agent.McpImpactAgent._validate_conclusion(action, [evidence], scope)  # noqa: SLF001
    assert len(cleaned.report.views) == 1


def test_small_results_are_unchanged_and_long_row_lists_are_digested():
    small = normalize_result_detail({"structuredContent": {"results": [{"type": "ap"}], "total": 1}})
    assert small.reduction == "none"
    assert small.data == {"results": [{"type": "ap"}], "total": 1}
    series = [{"timestamp": 1_757_000_000_000 + n, "value": n} for n in range(60)]
    many = normalize_result_detail({"content": [{"type": "text", "text": json.dumps(series)}]}, changed_at=NOW)
    assert many.reduction == "digest"
    assert many.data["rows_summary"]["row_count"] == 60
    assert many.data["rows_summary"]["time_field"] == "timestamp"


@pytest.mark.parametrize(
    "raw",
    [
        {"results": [{f"f{i}": "x" * 1999 for i in range(100)}]},  # One huge row.
        {"results": [{f"f{i}": "\U0001f600" * 1999 for i in range(100)}]},  # Four-byte characters.
        {"results": [{f"field_{'k' * 100}_{i}": f"v{r % 3}" for i in range(100)} for r in range(60)]},  # Wide rows.
        {"results": [{f"f{i}": f"value-{r}-{i}" for i in range(100)} for r in range(500)]},  # High cardinality.
        {**{f"ctx{i}": "y" * 1999 for i in range(99)}, "results": [{"a": 1}] * 60},  # Large context.
        {"results": [{"n": 10**400, "m": 1e308, "timestamp": 10**400} for _ in range(60)]},  # Unrepresentable.
    ],
)
def test_pathological_results_stay_within_the_evidence_bound(raw):
    normalized = normalize_result_detail({"structuredContent": raw}, changed_at=NOW)
    assert normalized.reduction == "digest"
    assert normalized.partial
    assert len(json.dumps(normalized.data, ensure_ascii=False).encode()) <= MAX_MCP_EVIDENCE_BYTES


def undigestable():
    # 100 long-named row lists: even empty per-list summaries exceed the bound, yet the wire payload stays under 262 KB.
    return {
        f"list_{'k' * 110}_{j}": [{"mac": f"aabbccdd{r:04x}", "timestamp": int(NOW.timestamp()) + r} for r in range(30)]
        for j in range(100)
    }


def test_result_that_cannot_be_digested_within_the_bound_is_omitted():
    normalized = normalize_result_detail({"structuredContent": undigestable()}, changed_at=NOW)
    assert (normalized.reduction, normalized.partial) == ("omitted", True)
    assert "omitted" in normalized.data


def test_oversized_context_value_stays_visibly_present():
    raw = {"error": {f"k{i}": "z" * 1999 for i in range(5)}, "results": [{"a": n} for n in range(60)]}
    data = normalize_result_detail({"structuredContent": raw}).data
    assert data["error"] == {"omitted": "Value exceeded the digest context bound."}
    assert data["results_summary"]["row_count"] == 60


def test_normalize_result_keeps_its_two_value_contract():
    data, partial = normalize_result({"structuredContent": events()}, changed_at=NOW)
    assert partial
    assert "results_summary" in data


def search_once_then_report(check):
    def respond(request):
        context = read_context(request)
        if context["observations"]:
            check(context["observations"][0]["data"])
            return ai_response(
                {
                    "action": "report",
                    "report": {
                        "summary": "Port events were summarized by the server.",
                        "scope": "Device events for the changed site.",
                        "impact": "info",
                        "confidence": "low",
                        "coverage": "partial",
                        "gaps": ["Causation is not established."],
                    },
                }
            )
        return ai_response(
            {
                "action": "tool",
                "tool": "search_mist_data",
                "arguments": {"search_type": "device_events", "site_id": SITE},
                "purpose": "Compare port events before and after the change.",
            }
        )

    return respond


async def test_digested_result_is_counted_and_marked_partial(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    mcp_responses(httpx_mock, stored, result=events())

    def check(data):
        assert data["results_summary"]["row_count"] == 200

    httpx_mock.add_callback(search_once_then_report(check), method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    mcp = artifacts[0].mcp
    assert mcp.state == "complete", mcp.reason
    assert mcp.evidence[0].state == "partial"
    assert "digest" in mcp.evidence[0].data
    assert (mcp.diagnostics.results_digested, mcp.diagnostics.results_omitted) == (1, 0)


async def test_result_too_large_to_digest_is_counted_as_omitted(monkeypatch, httpx_mock):
    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    mcp_responses(httpx_mock, stored, result=undigestable())

    def check(data):
        assert "omitted" in data

    httpx_mock.add_callback(search_once_then_report(check), method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    mcp = artifacts[0].mcp
    assert mcp.state == "complete", mcp.reason
    assert mcp.evidence[0].state == "partial"
    assert "omitted" in mcp.evidence[0].data
    assert (mcp.diagnostics.results_digested, mcp.diagnostics.results_omitted) == (0, 1)


def foreign_row_beyond_shown(raw):
    raw["results"][-5]["org_id"] = str(uuid4())
    return raw


def short_rows():
    # More than 50 rows but under 12 KB: sanitize alone would cut the foreign row before today's check.
    return {"results": [{"org_id": MIST_ORG, "site_id": SITE, "mac": f"aabbccdd{n:04x}"} for n in range(60)]}


@pytest.mark.parametrize("raw", [foreign_row_beyond_shown(events()), foreign_row_beyond_shown(short_rows())])
def test_foreign_organization_beyond_shown_rows_rejects_the_whole_result(raw):
    scope = McpScope(org_id=UUID(MIST_ORG), changed_at=NOW, as_of=LATER, sites=[SITE])
    assert normalize_result_detail({"structuredContent": raw}, changed_at=NOW).reduction == "digest"
    with pytest.raises(McpScopeError, match="foreign organization"):
        normalize_result_detail({"structuredContent": raw}, changed_at=NOW, authority=scope.validate_response)


@pytest.mark.parametrize(
    ("result", "error"),
    [
        (foreign_row_beyond_shown(events()), "invalid_response"),
        ({"error": "Search backend failed.", "results": short_rows()["results"]}, "tool_error"),
    ],
)
async def test_rejected_reduced_results_are_errors_and_not_counted(monkeypatch, httpx_mock, result, error):
    service, root, _, artifacts, stored = mcp_runtime(monkeypatch)
    mcp_responses(httpx_mock, stored, result=result)

    def check(data):
        assert data is None

    httpx_mock.add_callback(search_once_then_report(check), method="POST", url=AI_URL, is_reusable=True)
    await service._poll(root)  # noqa: SLF001
    mcp = artifacts[0].mcp
    assert mcp.state == "complete", mcp.reason
    assert (mcp.evidence[0].state, mcp.evidence[0].error, mcp.evidence[0].data) == ("error", error, None)
    assert (mcp.diagnostics.results_digested, mcp.diagnostics.results_omitted) == (0, 0)
