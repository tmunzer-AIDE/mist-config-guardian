"""Scope exclusions and invalid responses are observable without retaining provider prose."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.impact.agent import evidence_view
from mist_config_guardian_backend.impact.port_scope import compile_port_targets
from mist_config_guardian_backend.impact.wlan_removal import compile_wlan_removal
from mist_config_guardian_backend.integrations.mist_port_evidence import MistPortEvidenceClient
from mist_config_guardian_backend.models.organization import MistCloudRegion
from mist_config_guardian_backend.services import investigation_reads
from test_impact_change_context import use_data
from test_impact_dispatch_journal import journal_runtime
from test_impact_port_scope import parse, payload, port_inputs
from test_wlan_investigation import inputs


@pytest.mark.parametrize("case", ["multiple", "removed", "missing_identity"])
def test_port_resolver_itself_records_unresolved_device_changes(case):
    data = port_inputs()
    if case == "multiple":
        data["after"].append(data["after"][0].model_copy(update={"version": 3}))
        expected = "multiple times"
    elif case == "removed":
        data["after"][0].is_deleted = True
        data["after"][0].changed_fields = ["*"]
        expected = "Removed device"
    else:
        data["after"][0].id = None
        expected = "immutable configuration identity"
    targets, gaps = compile_port_targets(**{k: v for k, v in data.items() if k != "changed_at"})
    assert not targets
    assert any(expected in gap for gap in gaps)


def test_resolvers_use_same_ordered_version_prefix_and_port_limit_is_self_describing():
    data = port_inputs()
    data.update(logicals=[], before=[], after=[])
    for index in range(1, 66):
        entry = inputs() if index == 65 else port_inputs()
        identity = PydanticObjectId(f"{index:024x}")
        entry["logicals"][0].id = identity
        for version in [*entry["before"], *entry["after"]]:
            version.logical_object_id = identity
            if index != 65:
                version.configuration["mac"] = f"{index:012x}"
        for key in ("logicals", "before", "after"):
            data[key].extend(entry[key])
    targets, gaps = compile_port_targets(**{k: v for k, v in data.items() if k != "changed_at"})
    assert len(targets) == 2
    assert any("Port discovery configuration version limit" in gap for gap in gaps)
    first = compile_wlan_removal(**data)
    assert not first.targets  # The WLAN is outside the prefix in either input order.
    data["after"].reverse()
    second = compile_wlan_removal(**data)
    assert second == first


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("scope", "scope_mismatch"),
        ("future", "invalid_timestamp"),
        ("bad_timestamp", "invalid_timestamp"),
        ("malformed", "invalid_response"),
        ("http", None),
        ("timeout", None),
    ],
)
async def test_port_capture_distinguishes_response_rejection_from_transport_failure(httpx_mock, case, expected):
    plan, check, _ = parse()

    def respond(request):
        if case == "scope":
            return httpx.Response(200, json=payload(site_id="foreign-provider-secret"))
        if case == "future":
            return httpx.Response(200, json=payload(timestamp=253402300799))
        if case == "bad_timestamp":
            return httpx.Response(200, json=payload(timestamp="provider-secret"))
        if case == "malformed":
            return httpx.Response(200, text="provider-secret")
        if case == "http":
            return httpx.Response(429, text="provider-secret")
        message = "provider-secret"
        raise httpx.ReadTimeout(message, request=request)

    httpx_mock.add_callback(respond)
    async with MistPortEvidenceClient(token="test", region=MistCloudRegion.GLOBAL_01) as client:
        reading = await client.capture_port(
            plan=plan,
            target_handle=check.target_handle,
            window=check.window,
            reserve_dispatch=AsyncMock(return_value=None),
        )
    assert reading.state == "error"
    assert not reading.rows
    assert reading.response_error == expected
    assert reading.http_status == (None if case == "timeout" else 429 if case == "http" else 200)
    view = evidence_view(check, reading, plan.changed_at)
    assert view.response_error == expected
    assert "provider-secret" not in reading.model_dump_json()
    if case == "http":
        assert "HTTP 429" in reading.reason
    elif case == "timeout":
        assert "transport failed" in reading.reason
    else:
        assert "transport" not in reading.reason


async def test_rejected_port_response_publishes_visible_diagnostic(monkeypatch, httpx_mock):
    service, root, _, artifacts, _ = journal_runtime(monkeypatch)
    use_data(service, port_inputs())
    httpx_mock.add_response(json=payload(mac="001122334455"))
    await service._poll(root)  # noqa: SLF001
    artifact = artifacts[0]
    root.report_id, root.revision = artifact.id, artifact.revision
    monkeypatch.setattr(investigation_reads, "read_investigation_root", AsyncMock(return_value=root))
    monkeypatch.setattr(investigation_reads.InvestigationRevision, "find_one", AsyncMock(return_value=artifact))
    monkeypatch.setattr(
        investigation_reads.AuditChangeGroup,
        "find_one",
        AsyncMock(return_value=SimpleNamespace(audit_id=root.audit_id)),
    )
    result = await investigation_reads.shadow_investigation(root.organization_id, PydanticObjectId())
    assert result.checks[0].response_error == "scope_mismatch"
    assert "response rejected" in result.checks[0].reason
    assert result.checks[0].port is None
