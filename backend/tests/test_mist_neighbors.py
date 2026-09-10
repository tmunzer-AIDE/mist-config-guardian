"""Neighbor evidence preserves scope, redundant adjacency and partial failures."""

import httpx
import pytest

from mist_config_guardian_backend.integrations.mist_neighbors import fetch_neighbor_ports
from mist_config_guardian_backend.integrations.mist_topology import fetch_site_topology, topology_from_stats
from mist_config_guardian_backend.models.organization import MistCloudRegion

SITE = "site-1"
ORG = "provider-org"
HOST = "https://api.gc1.mist.com"
PATH = f"/api/v1/orgs/{ORG}/stats/ports/search"
GW, CORE, ACCESS, AP = [f"aabbccddee{i:02x}" for i in range(1, 5)]
ROWS = [
    {"mac": GW, "type": "gateway"},
    {"mac": CORE, "type": "switch", "module_stat": [{"mac": "112233445566"}]},
    {"mac": ACCESS, "type": "switch"},
    {"mac": AP, "type": "ap", "lldp_stat": {"chassis_id": ACCESS, "port_id": "ge-0/0/1"}},
]


def port(mac=GW, neighbor=CORE, **extra):
    return {"org_id": ORG, "site_id": SITE, "mac": mac, "neighbor_mac": neighbor, "port_id": "ge-0/0/0", **extra}


def test_gateway_switch_switch_and_ap_links_have_stable_deduplicated_port_evidence():
    ports = [
        port(neighbor="11:22:33:44:55:66", neighbor_port_desc="upstream"),
        port(CORE, GW, port_id="ge-0/0/9"),
        port(CORE, ACCESS, port_id="ge-0/0/2", neighbor_port_desc="uplink"),
        port(CORE, ACCESS, port_id="ge-0/0/3"),
        port(ACCESS, AP, port_id="ge-0/0/1"),
    ]
    result = topology_from_stats(SITE, ROWS, ports)
    assert [(link.source, link.target) for link in result.links] == [(GW, CORE), (CORE, ACCESS), (ACCESS, AP)]
    assert result.links[0].source_ports == ["ge-0/0/0"]
    assert result.links[0].target_ports == ["ge-0/0/9"]  # Local ID beats remote description.
    assert result.links[1].source_ports == ["ge-0/0/2", "ge-0/0/3"]
    assert result.links[1].target_ports == ["uplink"]
    assert [d.tier for d in result.devices] == [0, 1, 2, 3]
    assert [d.parent for d in result.devices] == [None, GW, CORE, ACCESS]
    reverse = topology_from_stats(SITE, list(reversed(ROWS)), list(reversed(ports)))
    assert reverse.links == result.links
    assert reverse.devices == result.devices


def test_redundant_and_same_tier_links_are_not_replaced_by_an_arbitrary_parent():
    rows = [*ROWS, {"mac": "aabbccddee05", "type": "gateway"}]
    result = topology_from_stats(SITE, rows, [port(), port("aabbccddee05", CORE), port(GW, "aabbccddee05")])
    assert len(result.links) == 4  # includes the existing AP link
    assert next(d for d in result.devices if d.id == CORE).parent is None


def test_port_mac_aliases_work_without_accepting_names_foreign_sites_or_ambiguous_chassis():
    ports = [port(CORE, None, port_mac="66778899aabb"), port(GW, "66:77:88:99:aa:bb")]
    assert (GW, CORE) in [(link.source, link.target) for link in topology_from_stats(SITE, ROWS, ports).links]
    ambiguous = [*ROWS, {"mac": "aabbccddee05", "type": "switch", "module_stat": [{"mac": "112233445566"}]}]
    rejected = [
        port(neighbor="112233445566"),
        port(neighbor=GW),
        port(neighbor="unknown", neighbor_system_name="Core"),
        port(site_id="another-site"),
        port(mac="unknown-device"),
    ]
    assert len(topology_from_stats(SITE, ambiguous, rejected).links) == 1  # AP only


async def test_cursor_pagination_keeps_org_filters_and_excludes_foreign_records(httpx_mock):
    def respond(request):
        assert request.method == "GET"
        assert request.url.path == PATH
        assert request.url.params["mac"] == f"{GW},{CORE}"
        assert request.url.params["device_type"] == "all"
        assert request.url.params["limit"] == "1000"
        if "search_after" not in request.url.params:
            return httpx.Response(
                200,
                json={
                    "results": [port(), port(org_id="other-org"), port(site_id="other-site")],
                    "total": 4,
                    "next": f"{PATH}?search_after=opaque%2Bcursor&mac=foreign&limit=999999",
                },
            )
        assert request.url.params["search_after"] == "opaque+cursor"
        return httpx.Response(200, json={"results": [port(CORE, GW)], "total": 4})

    httpx_mock.add_callback(respond, is_reusable=True)
    async with httpx.AsyncClient(base_url=HOST) as client:
        rows, warnings = await fetch_neighbor_ports(client, org_id=ORG, site_id=SITE, macs=[GW, CORE])
    assert rows == [port(), port(CORE, GW)]
    assert warnings == []
    assert len(httpx_mock.get_requests()) == 2


@pytest.mark.parametrize(
    "following",
    [
        "https://attacker.invalid/steal?search_after=x",
        "/api/v1/orgs/other-org/stats/ports/search?search_after=x",
        "?page=2",
        12,
    ],
)
async def test_invalid_next_never_receives_token_or_discards_collected_links(httpx_mock, following):
    httpx_mock.add_response(json={"results": [port()], "total": 2, "next": following})
    async with httpx.AsyncClient(base_url=HOST, headers={"Authorization": "Token private"}) as client:
        rows, warnings = await fetch_neighbor_ports(client, org_id=ORG, site_id=SITE, macs=[GW])
    assert rows == [port()]
    assert warnings
    assert "private" not in str(warnings)
    assert len(httpx_mock.get_requests()) == 1


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"results": [None], "total": 1},
        {"results": [], "total": True},
        {"results": [], "total": 1},
        {"results": [port()] * 1001, "total": 1001},
    ],
)
async def test_malformed_or_missing_pages_are_incomplete(httpx_mock, payload):
    httpx_mock.add_response(json=payload)
    async with httpx.AsyncClient(base_url=HOST) as client:
        _rows, warnings = await fetch_neighbor_ports(client, org_id=ORG, site_id=SITE, macs=[GW])
    assert warnings


async def test_port_requests_are_bounded_even_when_provider_always_has_more(httpx_mock):
    def respond(request):
        cursor = int(request.url.params.get("search_after", "0")) + 1
        return httpx.Response(200, json={"results": [port()], "total": 99, "next": f"?search_after={cursor}"})

    httpx_mock.add_callback(respond, is_reusable=True)
    async with httpx.AsyncClient(base_url=HOST) as client:
        _rows, warnings = await fetch_neighbor_ports(client, org_id=ORG, site_id=SITE, macs=[GW])
    assert "5000" in warnings[0]
    assert len(httpx_mock.get_requests()) == 5


async def test_repeated_cursor_is_incomplete(httpx_mock):
    httpx_mock.add_response(json={"results": [port()], "total": 99, "next": "?search_after=same"}, is_reusable=True)
    async with httpx.AsyncClient(base_url=HOST) as client:
        _rows, warnings = await fetch_neighbor_ports(client, org_id=ORG, site_id=SITE, macs=[GW])
    assert warnings
    assert len(httpx_mock.get_requests()) == 2


@pytest.mark.parametrize("status", [403, 404, 429, 500])
async def test_port_failure_keeps_live_inventory_and_ap_links(httpx_mock, status):
    httpx_mock.add_response(url=f"{HOST}/api/v1/sites/{SITE}/stats/devices?type=all&limit=1000&page=1", json=ROWS)
    httpx_mock.add_response(
        url=httpx.URL(
            HOST + PATH,
            params={
                "device_type": "all",
                "mac": f"112233445566,{GW},{CORE},{ACCESS}",
                "limit": "1000",
                "sort": "-timestamp",
            },
        ),
        status_code=status,
        text="private provider details",
    )
    result = await fetch_site_topology(site_id=SITE, org_id=ORG, token="test", region=MistCloudRegion.GLOBAL_02)
    assert len(result.devices) == 4
    assert result.source == "mist"
    assert len(result.links) == 1
    assert not result.complete
    assert result.warnings
    assert "private" not in str(result.warnings)


async def test_device_filters_are_batched_without_fetching_the_whole_organization(httpx_mock):
    macs = [f"{i:012x}" for i in range(101)]

    def respond(request):
        assert len(request.url.params["mac"].split(",")) <= 100
        return httpx.Response(200, json={"results": [], "total": 0})

    httpx_mock.add_callback(respond, is_reusable=True)
    async with httpx.AsyncClient(base_url=HOST) as client:
        rows, warnings = await fetch_neighbor_ports(client, org_id=ORG, site_id=SITE, macs=macs)
    assert rows == warnings == []
    assert [r.url.params["mac"] for r in httpx_mock.get_requests()] == [",".join(macs[:100]), macs[-1]]


async def test_timeout_is_incomplete_and_leaves_partial_neighbors_available(httpx_mock):
    httpx_mock.add_response(json={"results": [port()], "total": 2, "next": "?search_after=second"})
    httpx_mock.add_exception(TimeoutError())
    async with httpx.AsyncClient(base_url=HOST) as client:
        rows, warnings = await fetch_neighbor_ports(client, org_id=ORG, site_id=SITE, macs=[GW])
    assert rows == [port()]
    assert warnings
