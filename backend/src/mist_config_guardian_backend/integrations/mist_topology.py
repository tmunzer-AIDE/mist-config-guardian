"""Bounded read-only site statistics; no provider configurations leave this module."""

from datetime import UTC, datetime
from typing import Any

import httpx

from mist_config_guardian_backend.integrations.mist import REGION_HOSTS
from mist_config_guardian_backend.integrations.mist_neighbors import fetch_neighbor_ports
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.organization import MistCloudRegion
from mist_config_guardian_backend.schemas.impact import SiteTopology, TopologyDevice, TopologyLink

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


def _identities(rows: list[dict[str, Any]], devices: dict[str, TopologyDevice]) -> dict[str, set[str]]:
    aliases: dict[str, set[str]] = {}
    for row in rows:
        owner = normalized_mac(row.get("mac"))
        if owner not in devices:
            continue
        modules = row.get("module_stat")
        identities = [owner] + [
            normalized_mac(module.get("mac"))
            for module in (modules if isinstance(modules, list) else [])
            if isinstance(module, dict)
        ]
        for identity in identities:
            if len(identity) == _MAC_LENGTH and all(c in "0123456789abcdef" for c in identity):
                aliases.setdefault(identity, set()).add(owner)
    return aliases


def _resolve(aliases: dict[str, set[str]], value: object) -> str | None:
    matches = aliases.get(normalized_mac(value), set())
    return next(iter(matches)) if len(matches) == 1 else None


def _add_port_aliases(aliases: dict[str, set[str]], ports: list[dict[str, Any]]) -> None:
    # Port chassis MACs can differ from the management/virtual-chassis MAC.
    port_aliases: dict[str, set[str]] = {}
    for port in ports:
        owner = _resolve(aliases, port.get("mac"))
        identity = normalized_mac(port.get("port_mac"))
        if owner and len(identity) == _MAC_LENGTH and all(c in "0123456789abcdef" for c in identity):
            port_aliases.setdefault(identity, set()).add(owner)
    for identity, owners in port_aliases.items():
        aliases.setdefault(identity, set()).update(owners)


def _observed_links(
    rows: list[dict[str, Any]], ports: list[dict[str, Any]], devices: dict[str, TopologyDevice]
) -> list[TopologyLink]:
    aliases = _identities(rows, devices)
    _add_port_aliases(aliases, ports)
    # One adjacency per pair, retaining all observed ports on each endpoint.
    links: dict[tuple[str, str], dict[str, set[str]]] = {}
    hints: dict[tuple[str, str], dict[str, set[str]]] = {}

    def add(a: str | None, b: str | None, local: object, remote: object) -> None:
        if not a or not b or a == b:
            return
        pair = (a, b) if a < b else (b, a)
        observed = links.setdefault(pair, {a: set(), b: set()})
        descriptions = hints.setdefault(pair, {a: set(), b: set()})
        if isinstance(local, str) and local:
            observed[a].add(local)
        if isinstance(remote, str) and remote:
            descriptions[b].add(remote)

    for row in rows:
        child = _resolve(aliases, row.get("mac"))
        lldp = row.get("lldp_stat")
        if child and isinstance(lldp, dict):
            add(child, _resolve(aliases, lldp.get("chassis_id")), None, lldp.get("port_id"))
    for port in ports:
        add(
            _resolve(aliases, port.get("mac")),
            _resolve(aliases, port.get("neighbor_mac")),
            port.get("port_id"),
            port.get("neighbor_port_desc"),
        )
    return [
        TopologyLink(
            source=a,
            target=b,
            source_ports=sorted(observed[a] or hints[(a, b)][a]),
            target_ports=sorted(observed[b] or hints[(a, b)][b]),
        )
        for (a, b), observed in sorted(links.items())
    ]


def topology_from_stats(
    site_id: str, rows: list[dict[str, Any]], ports: list[dict[str, Any]] | None = None
) -> SiteTopology:
    devices = {item.id: item for row in rows if (item := device_from_stats(row)) is not None}
    links = _observed_links(rows, [p for p in ports or [] if p.get("site_id") == site_id], devices)
    neighbors: dict[str, dict[str, TopologyLink]] = {identity: {} for identity in devices}
    for link in links:
        neighbors[link.source][link.target] = link
        neighbors[link.target][link.source] = link
    # This is only a layout convention; links retain loops and redundant peers.
    for item in devices.values():
        if item.kind == "switch" and any(devices[n].kind == "gateway" for n in neighbors[item.id]):
            item.tier = 1
    for item in devices.values():
        parents = [n for n in neighbors[item.id] if devices[n].tier < item.tier]
        if len(parents) == 1:
            item.parent = parents[0]
            link = neighbors[item.id][item.parent]
            upstream_ports = link.source_ports if link.source == item.parent else link.target_ports
            item.uplink = ", ".join(upstream_ports) or "LLDP neighbor"
    ordered = sorted(devices.values(), key=lambda item: (item.tier, item.name.casefold(), item.id))
    for tier in range(4):
        for index, item in enumerate(d for d in ordered if d.tier == tier):
            item.col = float(index)
    return SiteTopology(
        site_id=site_id, devices=ordered, links=links, source="mist", collected_at=utc_now(), complete=True
    )


async def fetch_site_topology(*, site_id: str, org_id: str, token: str, region: MistCloudRegion) -> SiteTopology:
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
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
                break
        else:
            warnings.append("Device collection reached its 5000-device limit; topology is incomplete.")
        devices = {item.id: item for row in rows if (item := device_from_stats(row)) is not None}
        aliases = _identities(rows, devices)
        macs = sorted(
            identity
            for identity, owners in aliases.items()
            if len(owners) == 1 and devices[next(iter(owners))].kind in {"switch", "gateway"}
        )
        ports, port_warnings = await fetch_neighbor_ports(client, org_id=org_id, site_id=site_id, macs=macs)
    result = topology_from_stats(site_id, rows, ports)
    result.warnings = warnings + port_warnings
    result.complete = not result.warnings
    return result
