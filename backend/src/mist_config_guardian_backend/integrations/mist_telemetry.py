"""Read-only operational snapshots using documented Mist stats endpoints."""

import asyncio
from contextlib import AbstractAsyncContextManager
from types import TracebackType
from typing import Self
from urllib.parse import urljoin, urlsplit

import httpx

from mist_config_guardian_backend.integrations.mist import REGION_HOSTS
from mist_config_guardian_backend.models.monitoring import DeviceType
from mist_config_guardian_backend.models.organization import MistCloudRegion
from mist_config_guardian_backend.models.telemetry import DeviceStateObservation, TelemetrySource

_PAGE_SIZE = 1000
_MAX_PAGES = 5
_DEVICE_FIELDS = [
    "id",
    "mac",
    "name",
    "type",
    "model",
    "status",
    "uptime",
    "last_seen",
    "num_clients",
    "num_wlans",
    "cpu_util",
    "cpu_user",
    "cpu_system",
    "mem_used_kb",
    "mem_total_kb",
    "version",
]
_FIELDS = {
    "radios": [
        "band",
        "channel",
        "bandwidth",
        "power",
        "noise_floor",
        "num_clients",
        "num_wlans",
        "util_all",
        "util_non_wifi",
        "util_tx",
        "util_rx_in_bss",
        "rx_bytes",
        "tx_bytes",
    ],
    "wlans": ["id", "ssid", "enabled"],
    "clients": [
        "mac",
        "ap_mac",
        "device_mac",
        "wlan_id",
        "ssid",
        "port_id",
        "last_seen",
        "timestamp",
        "rssi",
        "snr",
        "rx_bps",
        "tx_bps",
        "auth_state",
    ],
    "ports": [
        "timestamp",
        "port_id",
        "up",
        "active",
        "disabled",
        "speed",
        "mac_count",
        "rx_errors",
        "tx_errors",
        "rx_bytes",
        "tx_bytes",
        "rx_bps",
        "tx_bps",
        "poe_on",
        "loss",
        "latency",
        "jitter",
    ],
    "bgp": ["neighbor", "vrf_name", "node", "up", "state", "rx_routes", "tx_routes", "uptime", "timestamp"],
    "ospf": ["peer_ip", "port_id", "vrf_name", "up", "state", "priority", "timestamp"],
    "tunnels": ["tunnel_name", "wan_name", "node", "peer_ip", "up", "uptime", "rx_bytes", "tx_bytes", "last_flapped"],
    "vpn_peers": [
        "peer_mac",
        "peer_port_id",
        "port_id",
        "peer_router_name",
        "up",
        "is_active",
        "loss",
        "latency",
        "jitter",
        "uptime",
    ],
}


def device_id(mac: str) -> str:
    """Mist infrastructure UUIDs encode the normalized device MAC."""
    return f"00000000-0000-0000-1000-{mac.replace(':', '').replace('-', '').lower()}"


def _select(record: dict[str, object], fields: list[str]) -> dict[str, object]:
    return {key: record[key] for key in fields if key in record and isinstance(record[key], (str, int, float, bool))}


class MistTelemetryClient(AbstractAsyncContextManager["MistTelemetryClient"]):
    """Capture independent sources concurrently; failed sources remain unknown."""

    def __init__(self, *, token: str, region: MistCloudRegion) -> None:
        self._client = httpx.AsyncClient(
            base_url=REGION_HOSTS[region],
            headers={"Authorization": f"Token {token}"},
            timeout=30,
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: TracebackType | None
    ) -> None:
        await self._client.aclose()

    async def capture(
        self,
        *,
        site_id: str,
        device_mac: str,
        device_type: DeviceType,
        sources: frozenset[TelemetrySource] | None = None,
    ) -> DeviceStateObservation:
        """Persist only operational fields, never raw WLAN or device configuration."""
        state = DeviceStateObservation()
        base = f"/api/v1/sites/{site_id}"
        path = f"{base}/stats/devices/{device_id(device_mac)}"
        tables: dict[str, tuple[str, dict[str, str]]] = {}
        embedded = {"device"}
        if device_type is DeviceType.AP:
            embedded.add("radios")
            tables = {"wlans": (f"{base}/wlans/derived", {}), "clients": (f"{path}/clients", {})}
        else:
            now = int(state.captured_at.timestamp())
            window = {"start": str(now - 300), "end": str(now)}
            tables = {
                "ports": (f"{base}/stats/ports/search", {"mac": device_mac}),
                "bgp": (f"{base}/stats/bgp_peers/search", {"mac": device_mac, **window}),
                "ospf": (f"{base}/stats/ospf_peers/search", {"mac": device_mac, **window}),
            }
            if device_type is DeviceType.SWITCH:
                tables["clients"] = (f"{base}/wired_clients/search", {"device_mac": device_mac, **window})
            else:
                embedded.update({"tunnels", "vpn_peers"})
        selected: set[str] = set(sources) if sources is not None else embedded | tables.keys()
        state.errors.update(
            dict.fromkeys(selected - embedded - tables.keys(), "Unsupported source for this device type.")
        )
        jobs = [self._table(state, key, url, params) for key, (url, params) in tables.items() if key in selected]
        if selected & embedded:
            jobs.append(self._device(state, path, device_type, selected))
        await asyncio.gather(*jobs)
        return state

    async def _device(self, state: DeviceStateObservation, path: str, kind: DeviceType, selected: set[str]) -> None:
        try:
            fields = ",".join(key for key in ("tunnels", "vpn_peers") if key in selected)
            params = {"fields": fields} if kind is DeviceType.GATEWAY and fields else {}
            response = await self._client.get(path, params=params)
            response.raise_for_status()
            record = response.json()
            if not isinstance(record, dict) or not record.get("mac"):
                state.errors["device"] = "Device statistics were not returned."
                return
            state.device = _select(record, _DEVICE_FIELDS)
            for key in ("cpu_stat", "memory_stat"):
                value = record.get(key)
                if isinstance(value, dict):
                    state.device[key] = _select(value, ["usage", "idle", "user", "system"])
            state.available.append("device")
            if kind is DeviceType.AP and "radios" in selected:
                radios = record.get("radio_stat")
                if isinstance(radios, dict) and all(isinstance(value, dict) for value in radios.values()):
                    state.radios = [
                        _select({**v, "band": k}, _FIELDS["radios"]) for k, v in radios.items() if isinstance(v, dict)
                    ]
                    state.available.append("radios")
                else:
                    state.errors["radios"] = "RF statistics unavailable for this device."
            if kind is DeviceType.GATEWAY:
                for key in ("tunnels", "vpn_peers"):
                    if key in selected:
                        self._store_rows(state, key, record.get(key))
        except (httpx.HTTPError, ValueError):
            state.errors["device"] = "Device statistics unavailable; check Mist permissions and connectivity."

    @staticmethod
    def _store_rows(state: DeviceStateObservation, key: str, rows: object) -> None:
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            state.errors[key] = "This telemetry source did not return a supported list."
            return
        identity = {
            "wlans": "id",
            "clients": "mac",
            "ports": "port_id",
            "bgp": "neighbor",
            "ospf": "peer_ip",
            "tunnels": "tunnel_name",
            "vpn_peers": "peer_mac",
        }[key]
        if any(not isinstance(row.get(identity), str) or not row[identity] for row in rows):
            state.errors[key] = "Records lack resource identities; collection cannot be compared."
            return
        setattr(state, key, [_select(row, _FIELDS[key]) for row in rows[: _PAGE_SIZE * _MAX_PAGES]])
        if len(rows) > _PAGE_SIZE * _MAX_PAGES:
            state.errors[key] = "Collection limit reached; missing entries cannot be treated as removed."
        else:
            state.available.append(key)

    async def _table(self, state: DeviceStateObservation, key: str, path: str, params: dict[str, str]) -> None:
        rows: list[dict[str, object]] = []
        next_url = path
        query: dict[str, str] | None = {**params, "limit": str(_PAGE_SIZE)}
        try:
            for page in range(1, _MAX_PAGES + 1):
                response = await self._client.get(next_url, params=query)
                response.raise_for_status()
                payload = response.json()
                batch = payload.get("results") if isinstance(payload, dict) else payload
                if not isinstance(batch, list) or not all(isinstance(row, dict) for row in batch):
                    state.errors[key] = "Unexpected response; this telemetry source is unavailable."
                    return
                rows.extend(batch)
                following = payload.get("next") if isinstance(payload, dict) else None
                if following:
                    destination = self._pagination_destination(following, response.url, path)
                    if destination is None:
                        state.errors[key] = "Unexpected pagination destination; collection incomplete."
                        return
                    next_url, query = destination, None
                elif (
                    isinstance(payload, dict) and isinstance(payload.get("total"), int) and payload["total"] > len(rows)
                ):
                    break
                elif len(batch) < _PAGE_SIZE:
                    self._store_rows(state, key, rows)
                    return
                elif isinstance(payload, dict):
                    # Search results must provide a cursor if more pages exist.
                    if not isinstance(payload.get("total"), int) or payload["total"] > len(rows):
                        break
                    self._store_rows(state, key, rows)
                    return
                else:
                    query = {**params, "limit": str(_PAGE_SIZE), "page": str(page + 1)}
            state.errors[key] = "Collection incomplete; missing entries cannot be treated as removed."
        except (httpx.HTTPError, ValueError):
            state.errors[key] = "Telemetry unavailable; check Mist permissions, licensing and connectivity."

    def _pagination_destination(self, following: object, current: httpx.URL, path: str) -> str | None:
        if not isinstance(following, str):
            return None
        resolved = urlsplit(urljoin(str(current), following))
        origin = urlsplit(str(self._client.base_url))
        if (resolved.scheme, resolved.netloc, resolved.path) != (origin.scheme, origin.netloc, path):
            return None
        return resolved.geturl()
