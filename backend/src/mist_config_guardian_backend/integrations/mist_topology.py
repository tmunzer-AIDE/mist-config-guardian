"""Bounded read-only site statistics; no provider configurations leave this module."""

from datetime import UTC, datetime
from typing import Any

import httpx

from mist_config_guardian_backend.integrations.mist import REGION_HOSTS
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.organization import MistCloudRegion
from mist_config_guardian_backend.schemas.impact import SiteTopology, TopologyDevice

_MAC_LENGTH = 12
_MAX_TIMESTAMP = 253402300799
_PAGE_SIZE = 1000


def normalized_mac(value: object) -> str:
    return str(value or "").replace(":", "").replace("-", "").lower()


def device_from_stats(record: dict[str, Any]) -> TopologyDevice | None:
    mac = normalized_mac(record.get("mac"))
    if len(mac) != _MAC_LENGTH or any(char not in "0123456789abcdef" for char in mac):
        return None
    kind = record.get("type", "unknown")
    if not isinstance(kind, str) or kind not in {"ap", "switch", "gateway"}:
        kind = "unknown"
    status = record.get("status")
    count = record.get("num_clients")
    if kind == "switch":
        stats = record.get("clients_stats")
        total = stats.get("total") if isinstance(stats, dict) else None
        count = total.get("num_wired_clients") if isinstance(total, dict) else None
    seen = record.get("last_seen")
    return TopologyDevice(
        id=mac,
        mac=mac,
        name=str(record.get("name") or mac),
        model=str(record.get("model") or ""),
        kind=kind,
        ip=record.get("ip") if isinstance(record.get("ip"), str) else None,
        clients=count if isinstance(count, int) and not isinstance(count, bool) and count >= 0 else None,
        health="error" if status == "disconnected" else "unknown",
        health_label="Disconnected"
        if status == "disconnected"
        else "Connected · SLE not assessed"
        if status == "connected"
        else "No connectivity evidence",
        tier={"gateway": 0, "switch": 2, "ap": 3}.get(kind, 2),
        last_seen=datetime.fromtimestamp(seen, UTC)
        if isinstance(seen, (int, float)) and not isinstance(seen, bool) and 0 < seen < _MAX_TIMESTAMP
        else None,
    )


def topology_from_stats(site_id: str, rows: list[dict[str, Any]]) -> SiteTopology:
    devices = {item.id: item for row in rows if (item := device_from_stats(row)) is not None}
    # AP LLDP chassis identities are evidence. Names and guessed subnets are not.
    aliases = {
        normalized_mac(module.get("mac")): normalized_mac(row.get("mac"))
        for row in rows
        for module in (row["module_stat"] if isinstance(row.get("module_stat"), list) else [])
        if isinstance(module, dict)
    }
    for row in rows:
        child = devices.get(normalized_mac(row.get("mac")))
        lldp = row.get("lldp_stat")
        if child is None or not isinstance(lldp, dict):
            continue
        parent_id = normalized_mac(lldp.get("chassis_id"))
        parent_id = aliases.get(parent_id, parent_id)
        parent = devices.get(parent_id)
        if parent is not None and parent.id != child.id and parent.tier < child.tier:
            child.parent = parent.id
            child.uplink = str(lldp.get("port_id") or "LLDP neighbor")
    ordered = sorted(devices.values(), key=lambda item: (item.tier, item.name.casefold(), item.id))
    for tier in range(4):
        peers = [item for item in ordered if item.tier == tier]
        for index, item in enumerate(peers):
            item.col = float(index)
    return SiteTopology(site_id=site_id, devices=ordered, source="mist", collected_at=utc_now(), complete=True)


async def fetch_site_topology(*, site_id: str, token: str, region: MistCloudRegion) -> SiteTopology:
    rows: list[dict[str, Any]] = []
    async with httpx.AsyncClient(
        base_url=REGION_HOSTS[region], headers={"Authorization": f"Token {token}"}, timeout=20
    ) as client:
        for page in range(1, 6):
            response = await client.get(
                f"/api/v1/sites/{site_id}/stats/devices", params={"type": "all", "limit": _PAGE_SIZE, "page": page}
            )
            response.raise_for_status()
            batch = response.json()
            if not isinstance(batch, list) or any(not isinstance(row, dict) for row in batch):
                message = "Invalid site statistics response"
                raise ValueError(message)
            rows.extend(batch)
            if len(batch) < _PAGE_SIZE:
                return topology_from_stats(site_id, rows)
    result = topology_from_stats(site_id, rows)
    result.complete = False
    result.warnings.append("Device collection reached its 5000-device limit; topology is incomplete.")
    return result
