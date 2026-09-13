"""Site workspace contracts preserve scope, lifecycle evidence, and unknown health."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from beanie import PydanticObjectId
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mist_config_guardian_backend.api.dependencies import get_credential_vault, require_organization, require_viewer
from mist_config_guardian_backend.api.routes import impact
from mist_config_guardian_backend.integrations.mist_topology import fetch_site_topology, topology_from_stats
from mist_config_guardian_backend.models.monitoring import MonitoringSession
from mist_config_guardian_backend.models.organization import MistCloudRegion
from mist_config_guardian_backend.models.webhook import AuditChangeGroup
from mist_config_guardian_backend.schemas.impact import ImpactSite, ImpactSiteList, SiteTopology
from mist_config_guardian_backend.services import site_impact

NOW = datetime(2026, 9, 9, 12, tzinfo=UTC)
SITE = "d6fb4f96-3ba4-4cf5-8af2-a8d7b85087ac"
MAC = "aabbccddeeff"


def session(**overrides):
    return {
        "_id": PydanticObjectId(),
        "device_mac": MAC,
        "audit_ids": ["audit"],
        "device_name": "Switch 1",
        "status": "monitoring",
        "impact_severity": "none",
        "change_triggered_at": NOW - timedelta(minutes=35),
        "config_applied_at": NOW - timedelta(minutes=30),
        "monitoring_started_at": NOW - timedelta(minutes=30),
        "monitoring_ends_at": NOW + timedelta(minutes=30),
        "baseline": {"captured_at": NOW - timedelta(minutes=35), "scope": "device", "values": {"coverage": 99}},
        "observations": [{"captured_at": NOW, "scope": "device", "values": {"coverage": 98}}],
        "timeline": [],
        **overrides,
    }


def test_topology_only_links_observed_chassis_and_keeps_unknown_distinct_from_ok():
    rows = [
        {
            "mac": MAC,
            "type": "switch",
            "name": "Core",
            "status": "connected",
            "module_stat": [{"mac": "112233445566"}],
            "clients_stats": {"total": {"num_wired_clients": 5}},
            "secret": "hidden",
        },
        {
            "mac": "ffeeddccbbaa",
            "type": "ap",
            "status": "disconnected",
            "lldp_stat": {"chassis_id": "11:22:33:44:55:66", "port_id": "ge-0/0/1"},
        },
        {"mac": "123456abcdef", "type": "ap", "lldp_stat": {"system_name": "Core"}},
        {"mac": "invalid", "type": "ap"},
    ]
    result = topology_from_stats(SITE, rows)
    by_id = {d.id: d for d in result.devices}
    assert len(by_id) == 3
    assert by_id[MAC].health == "unknown"
    assert by_id[MAC].clients == 5
    assert by_id["ffeeddccbbaa"].parent == MAC
    assert by_id["ffeeddccbbaa"].health == "error"
    assert by_id["123456abcdef"].parent is None
    assert "hidden" not in result.model_dump_json()
    assert [d.id for d in topology_from_stats(SITE, list(reversed(rows))).devices] == [d.id for d in result.devices]


@pytest.mark.parametrize("malformed", [None, [], 4, "unexpected"])
def test_optional_provider_stats_do_not_crash_topology(malformed):
    result = topology_from_stats(
        SITE,
        [
            {
                "mac": MAC,
                "type": "switch",
                "clients_stats": malformed,
                "module_stat": malformed,
                "last_seen": float("nan"),
            }
        ],
    )
    assert result.devices[0].clients is None
    assert result.devices[0].last_seen is None


async def test_all_device_statistics_are_paginated_and_requests_are_read_only(httpx_mock):
    def respond(request):
        assert request.method == "GET"
        if request.url.path == "/api/v1/orgs/mist-org/stats/ports/search":
            return httpx.Response(200, json={"results": [], "total": 0})
        assert request.url.path == f"/api/v1/sites/{SITE}/stats/devices"
        assert request.url.params["type"] == "all"
        assert request.url.params["limit"] == "1000"
        rows = (
            [{"mac": f"{i:012x}", "type": "ap"} for i in range(1000)]
            if request.url.params["page"] == "1"
            else [{"mac": MAC, "type": "switch"}]
        )
        return httpx.Response(200, json=rows)

    httpx_mock.add_callback(respond, is_reusable=True)
    result = await fetch_site_topology(
        site_id=SITE, org_id="mist-org", token="test-read-token", region=MistCloudRegion.GLOBAL_02
    )
    assert len(httpx_mock.get_requests()) == 3
    assert len(result.devices) == 1001
    assert result.complete


async def test_topology_cap_is_explicit_and_malformed_response_is_not_empty(httpx_mock):
    httpx_mock.add_response(json=[{"mac": MAC, "type": "ap"}] * 1000, is_reusable=True)
    result = await fetch_site_topology(site_id=SITE, org_id="mist-org", token="test", region=MistCloudRegion.GLOBAL_02)
    assert not result.complete
    assert "5000" in result.warnings[0]
    assert len(httpx_mock.get_requests()) == 5


@pytest.mark.parametrize("payload", [{}, [None], [{}, "invalid"]])
async def test_invalid_stats_raise(payload, httpx_mock):
    httpx_mock.add_response(json=payload)
    with pytest.raises(ValueError, match="Invalid site"):
        await fetch_site_topology(site_id=SITE, org_id="mist-org", token="test", region=MistCloudRegion.GLOBAL_02)


def test_progress_measures_time_while_health_requires_comparable_measurements():
    result = site_impact.impact_from_session(session(), NOW, historical=False)
    assert result.progress == 50
    assert result.config_state == "applied"
    assert result.severity == "ok"
    assert result.metrics[0].delta == -1
    empty = site_impact.impact_from_session(session(observations=[]), NOW, historical=False)
    assert empty.progress == 50
    assert empty.severity == "unknown"
    assert empty.monitoring_state == "stalled"


def test_cross_scope_and_future_measurements_cannot_generate_a_healthy_verdict():
    for sample in [
        {"captured_at": NOW, "scope": "site", "values": {"coverage": 99}},
        {"captured_at": NOW + timedelta(seconds=1), "scope": "device", "values": {"coverage": 99}},
    ]:
        result = site_impact.impact_from_session(session(observations=[sample]), NOW, historical=False)
        assert len(result.metrics) == 1
        assert result.metrics[0].delta is None
        assert not result.metrics[0].comparable
        assert result.severity == "unknown"


def test_revert_and_shared_window_remain_explicit():
    row = session(
        status="failed",
        completed_at=NOW,
        audit_ids=["a", "b"],
        timeline=[{"event_type": "SW_CONFIG_REVERTED", "received_at": NOW}],
    )
    result = site_impact.impact_from_session(row, NOW, historical=False)
    assert result.config_state == "rolled_back"
    assert result.shared_window
    assert result.severity == "error"
    # A failed/reverted window cannot be labeled successfully completed.
    assert result.monitoring_state == "aborted"


def test_historical_projection_withholds_live_verdict_and_later_lifecycle():
    result = site_impact.impact_from_session(
        session(
            impact_severity="critical",
            config_applied_at=NOW + timedelta(minutes=1),
            monitoring_started_at=NOW + timedelta(minutes=1),
        ),
        NOW,
        historical=True,
    )
    assert result.severity == "unknown"
    assert result.metrics == []
    assert result.configured_at is None
    assert result.config_state == "pending"
    assert "Historical" in result.headline


async def test_event_page_scopes_both_collections_before_expanding_devices(monkeypatch):
    org = PydanticObjectId()
    queries = []

    def aggregate(pipeline):
        queries.append(pipeline)
        return SimpleNamespace(
            to_list=AsyncMock(
                return_value=[
                    {
                        "items": [
                            {
                                "_id": str(PydanticObjectId()),
                                "audit_id": "audit",
                                "at": NOW,
                                "message": "Template updated",
                            }
                        ],
                        "count": [{"total": 51}],
                    }
                ]
            )
        )

    def sessions(pipeline):
        queries.append(pipeline)
        return SimpleNamespace(to_list=AsyncMock(return_value=[session(), session(device_mac="112233445566")]))

    monkeypatch.setattr(AuditChangeGroup, "aggregate", aggregate)
    monkeypatch.setattr(MonitoringSession, "aggregate", sessions)
    result = await site_impact.list_changes(org, SITE, range_key="24h", end=None, skip=50, limit=1)
    assert result.total == 51
    assert len(result.items) == 1
    assert len(result.items[0].impacts) == 2
    assert queries[0][0]["$match"]["organization_id"] == org
    assert queries[0][0]["$match"]["affected_site_ids"] == SITE
    assert "created_at" in queries[0][0]["$match"]
    orphan = queries[0][4]["$unionWith"]["pipeline"][0]["$match"]
    assert orphan["organization_id"] == org
    assert orphan["site_id"] == SITE
    assert queries[0][-1]["$facet"]["items"][-2:] == [{"$skip": 50}, {"$limit": 1}]
    assert queries[1][0]["$match"]["site_id"] == SITE
    projection = queries[1][-1]["$project"]
    assert "device_comparisons" not in projection
    assert "configuration" not in projection


@pytest.fixture
def api(monkeypatch):
    app = FastAPI()
    app.include_router(impact.router, prefix="/api/v1")
    org = SimpleNamespace(id=PydanticObjectId(), mist_org_id="mist-org", cloud_region=MistCloudRegion.GLOBAL_02)
    app.dependency_overrides[require_organization] = lambda: org
    app.dependency_overrides[require_viewer] = lambda: SimpleNamespace(role="viewer")
    app.dependency_overrides[get_credential_vault] = object
    monkeypatch.setattr(
        site_impact, "list_sites", AsyncMock(return_value=ImpactSiteList(items=[ImpactSite(id=SITE, name="Paris")]))
    )
    monkeypatch.setattr(
        site_impact, "stored_topology", AsyncMock(return_value=SiteTopology(site_id=SITE, source="historical"))
    )
    monkeypatch.setattr(impact, "service_token", AsyncMock(return_value="read-token"))
    monkeypatch.setattr(
        impact, "fetch_site_topology", AsyncMock(return_value=SiteTopology(site_id=SITE, source="mist"))
    )
    return TestClient(app), app, org


def test_historical_api_never_calls_mist_and_unknown_sites_are_rejected(api):
    client, _app, org = api
    root = f"/api/v1/organizations/{org.id}/impact/sites"
    response = client.get(f"{root}/{SITE}/topology", params={"as_of": NOW.isoformat()})
    assert response.status_code == 200
    impact.fetch_site_topology.assert_not_awaited()
    assert client.get(f"{root}/00000000-0000-0000-0000-000000000000/topology").status_code == 404
    impact.fetch_site_topology.assert_not_awaited()
    assert client.get(f"{root}/{SITE}/changes?limit=101").status_code == 422


def test_live_provider_failure_is_sanitized_and_uses_stored_inventory(api):
    client, _app, org = api
    impact.fetch_site_topology.side_effect = httpx.ConnectError("private-token-in-provider-error")
    response = client.get(f"/api/v1/organizations/{org.id}/impact/sites/{SITE}/topology")
    assert response.status_code == 200
    assert "private-token" not in response.text
    assert "Live topology unavailable" in response.text


def test_all_site_endpoints_require_login(api):
    client, app, org = api
    app.dependency_overrides.pop(require_viewer)
    root = f"/api/v1/organizations/{org.id}/impact/sites"
    for path in [root, f"{root}/{SITE}/topology", f"{root}/{SITE}/changes"]:
        assert client.get(path).status_code == 401


def test_partial_metric_coverage_cannot_reuse_a_default_none_verdict():
    row = session(baseline={"scope": "device", "values": {"coverage": 99, "capacity": 98}})
    result = site_impact.impact_from_session(row, NOW, historical=False)
    assert len(result.metrics) == 2
    assert result.metrics[0].name == "capacity"
    assert result.metrics[0].latest is None
    assert result.metrics[0].latest_state == "missing"
    assert result.severity == "unknown"


async def test_inventory_fallback_selects_only_versions_known_at_the_requested_instant(monkeypatch):
    from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectVersion  # noqa: PLC0415

    org = PydanticObjectId()
    logical_id = PydanticObjectId()
    queries = []

    class Objects:
        def limit(self, value):
            assert value == 5000
            return self

        async def to_list(self):
            return [SimpleNamespace(id=logical_id)]

    def find(query):
        queries.append(query)
        return Objects()

    def aggregate(pipeline):
        queries.append(pipeline)
        return SimpleNamespace(
            to_list=AsyncMock(return_value=[{"config": {"mac": MAC, "name": "Old switch name", "type": "switch"}}])
        )

    monkeypatch.setattr(LogicalObject, "find", find)
    monkeypatch.setattr(ObjectVersion, "aggregate", aggregate)
    result = await site_impact.stored_topology(org, SITE, NOW, historical=True)
    assert queries[0]["organization_id"] == org
    assert queries[0]["site_mist_id"] == SITE
    assert queries[1][0]["$match"] == {
        "organization_id": org,
        "logical_object_id": {"$in": [logical_id]},
        "observed_at": {"$lte": NOW},
    }
    assert queries[1][3] == {"$match": {"latest.is_deleted": False}}
    assert set(queries[1][-1]["$project"]["config"]) == {"mac", "name", "type", "model"}
    assert result.source == "historical"
    assert result.devices[0].name == "Old switch name"
    assert result.devices[0].health == "unknown"
    assert result.devices[0].parent is None
    assert result.devices[0].clients is None


async def test_expansion_limit_is_explicit_instead_of_silently_hiding_devices(monkeypatch):
    monkeypatch.setattr(site_impact, "_MAX_SESSIONS", 1)
    group = {"_id": str(PydanticObjectId()), "audit_id": "audit", "at": NOW}
    monkeypatch.setattr(
        AuditChangeGroup,
        "aggregate",
        lambda _pipeline: SimpleNamespace(
            to_list=AsyncMock(return_value=[{"items": [group], "count": [{"total": 1}]}])
        ),
    )
    monkeypatch.setattr(
        MonitoringSession,
        "aggregate",
        lambda _pipeline: SimpleNamespace(
            to_list=AsyncMock(return_value=[session(), session(device_mac="112233445566")])
        ),
    )
    result = await site_impact.list_changes(PydanticObjectId(), SITE, range_key="24h", end=None, skip=0, limit=50)
    assert not result.complete
    assert result.warnings
    assert len(result.items[0].impacts) == 1


def test_live_topology_uses_provider_org_id_not_guardian_id(api):
    client, _app, org = api
    response = client.get(f"/api/v1/organizations/{org.id}/impact/sites/{SITE}/topology")
    assert response.status_code == 200
    impact.fetch_site_topology.assert_awaited_once_with(
        site_id=SITE, org_id="mist-org", token="read-token", region=org.cloud_region
    )
