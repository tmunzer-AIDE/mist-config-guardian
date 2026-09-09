"""Real HTTP contracts, collection completeness, and operational secret filtering."""

import json

import httpx
import pytest
from pytest_httpx import HTTPXMock

from mist_config_guardian_backend.integrations.mist_telemetry import MistTelemetryClient
from mist_config_guardian_backend.models.monitoring import DeviceType
from mist_config_guardian_backend.models.organization import MistCloudRegion

MAC = "aabbccddeeff"
UUID = f"00000000-0000-0000-1000-{MAC}"
BASE = "/api/v1/sites/site-a"


async def test_ap_captures_rf_site_wlans_and_clients_without_configuration_secrets(httpx_mock: HTTPXMock) -> None:
    requests = []

    def respond(request):
        requests.append(request)
        path = request.url.path
        if path.endswith("/clients"):
            payload = [{"mac": "client-a", "wlan_id": "wlan-a", "ssid": "Staff", "username": "private"}]
        elif path.endswith("/wlans/derived"):
            payload = [{"id": "wlan-a", "ssid": "Staff", "enabled": True, "passphrase": "private"}]
        else:
            assert path == f"{BASE}/stats/devices/{UUID}"
            payload = {
                "mac": MAC,
                "status": "connected",
                "password": "private",
                "radio_stat": {
                    "band_5": {"channel": 36, "num_clients": 12, "util_all": 25, "secret": "private"},
                },
            }
        return httpx.Response(200, json=payload)

    httpx_mock.add_callback(respond, is_reusable=True)
    async with MistTelemetryClient(token="read-token", region=MistCloudRegion.GLOBAL_01) as client:
        state = await client.capture(site_id="site-a", device_mac=MAC, device_type=DeviceType.AP)
    assert set(state.available) == {"device", "radios", "wlans", "clients"}
    assert state.radios[0]["channel"] == 36
    assert state.clients[0]["wlan_id"] == "wlan-a"
    assert "private" not in state.model_dump_json()
    assert len(requests) == 3
    assert all(request.headers["authorization"] == "Token read-token" for request in requests)


@pytest.mark.parametrize("kind", [DeviceType.SWITCH, DeviceType.GATEWAY])
async def test_wired_telemetry_uses_device_filters_and_includes_gateway_vpn_fields(kind, httpx_mock: HTTPXMock) -> None:
    def respond(request):
        path = request.url.path
        if "/stats/devices/" in path:
            if kind is DeviceType.GATEWAY:
                assert request.url.params["fields"] == "tunnels,vpn_peers"
            return httpx.Response(
                200, json={"mac": MAC, "tunnels": [], "vpn_peers": [], "cpu_stat": {"usage": 12, "secret": "private"}}
            )
        if "wired_clients" in path:
            assert request.url.params["device_mac"] == MAC
        else:
            assert request.url.params["mac"] == MAC
        if not path.endswith("ports/search"):
            assert int(request.url.params["end"]) - int(request.url.params["start"]) == 300
        return httpx.Response(200, json={"results": [], "total": 0})

    httpx_mock.add_callback(respond, is_reusable=True)
    async with MistTelemetryClient(token="read-token", region=MistCloudRegion.GLOBAL_01) as client:
        state = await client.capture(site_id="site-a", device_mac=MAC, device_type=kind)
    assert {"device", "ports", "bgp", "ospf"} <= set(state.available)
    assert ("clients" in state.available) == (kind is DeviceType.SWITCH)
    assert ("vpn_peers" in state.available) == (kind is DeviceType.GATEWAY)
    assert "private" not in state.model_dump_json()


@pytest.mark.parametrize(
    "failure", ["http", "malformed", "missing_identity", "foreign_cursor", "truncated", "short_truncated"]
)
async def test_unavailable_or_incomplete_sources_are_not_reported_as_empty(failure, httpx_mock: HTTPXMock) -> None:
    def respond(request):  # noqa: PLR0911 - one response for each failure fixture
        if request.url.path.endswith("/wlans/derived"):
            if failure == "http":
                return httpx.Response(403, json={"error": "private"})
            if failure == "missing_identity":
                return httpx.Response(200, json=[{"unsupported_id": "wlan-a"}])
            if failure == "short_truncated":
                return httpx.Response(200, json={"results": [{"id": "a"}], "total": 1001})
            if failure == "malformed":
                return httpx.Response(200, json={"unsupported": []})
            if failure == "foreign_cursor":
                return httpx.Response(200, json={"results": [{"id": "a"}], "next": "https://evil.test/steal"})
            return httpx.Response(200, json={"results": [{"id": str(i)} for i in range(1000)], "total": 1001})
        if request.url.path.endswith("/clients"):
            return httpx.Response(200, json=[])
        return httpx.Response(200, json={"mac": MAC, "radio_stat": {}})

    httpx_mock.add_callback(respond, is_reusable=True)
    async with MistTelemetryClient(token="read-token", region=MistCloudRegion.GLOBAL_01) as client:
        state = await client.capture(site_id="site-a", device_mac=MAC, device_type=DeviceType.AP)
    assert "wlans" not in state.available
    assert "wlans" in state.errors
    assert "clients" in state.available
    assert "private" not in json.dumps(state.errors)
    assert all(request.url.host == "api.mist.com" for request in httpx_mock.get_requests())


async def test_same_endpoint_cursor_collects_all_pages(httpx_mock: HTTPXMock) -> None:
    def respond(request):
        if request.url.path.endswith("/wlans/derived"):
            if "cursor" in request.url.params:
                return httpx.Response(200, json={"results": [{"id": "b", "ssid": "Guests"}]})
            return httpx.Response(
                200, json={"results": [{"id": "a", "ssid": "Staff"}], "next": f"{BASE}/wlans/derived?cursor=2"}
            )
        if request.url.path.endswith("/clients"):
            return httpx.Response(200, json=[])
        return httpx.Response(200, json={"mac": MAC})

    httpx_mock.add_callback(respond, is_reusable=True)
    async with MistTelemetryClient(token="read-token", region=MistCloudRegion.GLOBAL_01) as client:
        state = await client.capture(site_id="site-a", device_mac=MAC, device_type=DeviceType.AP)
    assert "wlans" in state.available
    assert [item["id"] for item in state.wlans] == ["a", "b"]
