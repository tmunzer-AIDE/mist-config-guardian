"""Deterministic comparison of operational snapshots captured around a change."""

from mist_config_guardian_backend.models.telemetry import DeviceStateFinding, DeviceStateObservation


def _number(value: object) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _index(rows: list[dict[str, object]], keys: tuple[str, ...]) -> dict[str, dict[str, object]]:
    # Search endpoints may include historical samples: retain the latest state.
    result: dict[str, dict[str, object]] = {}
    for row in sorted(rows, key=lambda row: _number(row.get("timestamp")) or 0):
        identity = " / ".join(str(row[key]) for key in keys if row.get(key) is not None)
        if identity:
            result[identity] = row
    return result


def _finding(  # noqa: PLR0913 - one argument per evidence field
    kind: str, subject: str, before: object, after: object, detail: str, *, clients: int = 0, severity: str = "warning"
) -> DeviceStateFinding:
    return DeviceStateFinding(
        kind=kind,
        subject=subject,
        before=str(before),
        after=str(after),
        detail=detail,
        affected_clients=clients,
        severity=severity,
    )


def compare_device_states(before: DeviceStateObservation, after: DeviceStateObservation) -> list[DeviceStateFinding]:
    """Flag evidence of disruption only where both collections are complete."""
    findings: list[DeviceStateFinding] = []
    common = set(before.available) & set(after.available)
    if "device" in common:
        findings.extend(_device_findings(before.device, after.device))
    if "wlans" in common:
        findings.extend(_wlans(before, after))
    if "ports" in common:
        findings.extend(_ports(before, after))
    if "radios" in common:
        findings.extend(_radios(before, after))
    for source, keys in [
        ("bgp", ("vrf_name", "neighbor", "node")),
        ("ospf", ("vrf_name", "peer_ip", "port_id")),
        ("tunnels", ("tunnel_name", "wan_name", "node")),
        ("vpn_peers", ("peer_mac", "port_id", "peer_port_id")),
    ]:
        if source in common:
            findings.extend(_peers(before, after, source, keys))
    return findings


def _ports(before: DeviceStateObservation, after: DeviceStateObservation) -> list[DeviceStateFinding]:
    findings: list[DeviceStateFinding] = []
    old, new = _index(before.ports, ("port_id",)), _index(after.ports, ("port_id",))
    for key, port in old.items():
        current = new.get(key)
        clients = len(
            {str(client.get("mac")) for client in before.clients if client.get("port_id") == key and client.get("mac")}
        )
        clients = max(clients, int(_number(port.get("mac_count")) or 0))
        powered = port.get("poe_on") is True and port.get("up") is True
        if powered and current and current.get("poe_on") is False:
            findings.append(
                _finding(
                    "poe_power_lost",
                    key,
                    "powered and linked",
                    "PoE off",
                    "PoE was removed from a previously linked powered port; its downstream device may be offline.",
                    clients=clients,
                    severity="critical",
                )
            )
        elif port.get("up") is True and (current is None or current.get("up") is False):
            findings.append(
                _finding(
                    "occupied_port_down" if clients else "port_down",
                    key,
                    "up",
                    "missing" if current is None else "down",
                    (
                        f"Interface was up and is now unavailable; {clients} clients were previously observed on it."
                        if "clients" in before.available or "mac_count" in port
                        else "Interface was up and is now unavailable; its previous client occupancy is unknown."
                    ),
                    clients=clients,
                    severity="critical" if clients or powered else "warning",
                )
            )
        if current:
            for counter in ("rx_errors", "tx_errors"):
                findings.extend(
                    _rise(
                        "interface_errors",
                        f"{key} {counter}",
                        port.get(counter),
                        current.get(counter),
                        threshold=100,
                        increase=100,
                    )
                )
    return findings


def refresh_device_findings(
    baseline: DeviceStateObservation,
    latest: DeviceStateObservation,
    previous: list[DeviceStateFinding],
    previous_observation: DeviceStateObservation | None = None,
) -> list[DeviceStateFinding]:
    """Reassess current conditions, retaining unresolved evidence for unavailable sources."""
    current = compare_device_states(baseline, latest)
    incremental = {"device_restarted", "interface_errors"}
    if previous_observation is not None:
        # Uptime resets and counter increases describe an interval, not an
        # ongoing outage relative to the original baseline forever.
        current = [finding for finding in current if finding.kind not in incremental]
        current.extend(f for f in compare_device_states(previous_observation, latest) if f.kind in incremental)
    common = set(baseline.available) & set(latest.available)
    for finding in previous:
        source = finding_source(finding.kind)
        if (source not in common or not _recovery_observed(finding, latest, previous_observation)) and not any(
            f.kind == finding.kind and f.subject == finding.subject for f in current
        ):
            current.append(finding)
    return current


def _recovery_observed(
    finding: DeviceStateFinding, latest: DeviceStateObservation, previous: DeviceStateObservation | None
) -> bool:
    """Missing fields are unknown, never positive recovery evidence."""
    source = finding_source(finding.kind)
    if finding.kind in {"device_restarted", "interface_errors"}:
        return _interval_measured(finding, previous, latest)
    if source == "ports":
        port = _index(latest.ports, ("port_id",)).get(finding.subject, {})
        if finding.kind == "poe_power_lost":
            return port.get("up") is True and port.get("poe_on") is True
        return finding.kind in {"occupied_port_down", "port_down"} and port.get("up") is True
    if finding.kind == "device_disconnected":
        return latest.device.get("status") == "connected"
    if finding.kind.endswith("_down") and source in {"bgp", "ospf", "tunnels", "vpn_peers"}:
        keys = {
            "bgp": ("vrf_name", "neighbor", "node"),
            "ospf": ("vrf_name", "peer_ip", "port_id"),
            "tunnels": ("tunnel_name", "wan_name", "node"),
            "vpn_peers": ("peer_mac", "port_id", "peer_port_id"),
        }
        return _index(getattr(latest, source), keys[source]).get(finding.subject, {}).get("up") is True
    return _measurement_present(finding, latest)


def _measurement_present(finding: DeviceStateFinding, latest: DeviceStateObservation) -> bool:
    """A successful source response can still omit the field we need."""
    kind = finding.kind
    if kind in {"cpu_stat", "memory_stat"}:
        stats = latest.device.get(kind)
        return isinstance(stats, dict) and _number(stats.get("usage")) is not None
    if kind == "cpu_util":
        return _number(latest.device.get(kind)) is not None
    if kind == "ssid_removed":
        return any(str(wlan.get("ssid", wlan.get("id"))) == finding.subject for wlan in latest.wlans)
    if kind in {"radio_missing", "rf_utilization", "radio_wlans_reduced"}:
        radio = _index(latest.radios, ("band",)).get(finding.subject)
        return radio is not None and (
            kind == "radio_missing"
            or _number(radio.get("util_all" if kind == "rf_utilization" else "num_wlans")) is not None
        )
    if kind == "vpn_loss":
        peer = _index(latest.vpn_peers, ("peer_mac", "port_id", "peer_port_id")).get(finding.subject, {})
        return _number(peer.get("loss")) is not None
    return False


def _interval_measured(
    finding: DeviceStateFinding, previous: DeviceStateObservation | None, latest: DeviceStateObservation
) -> bool:
    if previous is None or finding_source(finding.kind) not in set(previous.available) & set(latest.available):
        return False
    if finding.kind == "device_restarted":
        return _number(previous.device.get("uptime")) is not None and _number(latest.device.get("uptime")) is not None
    port_id, _, counter = finding.subject.rpartition(" ")
    return all(
        _number(_index(observation.ports, ("port_id",)).get(port_id, {}).get(counter)) is not None
        for observation in (previous, latest)
    )


def finding_source(kind: str) -> str:
    """The collection needed to confirm or clear a previously detected condition."""
    if kind in {"occupied_port_down", "port_down", "poe_power_lost", "interface_errors"}:
        return "ports"
    if kind == "ssid_removed":
        return "wlans"
    if kind in {"radio_missing", "rf_utilization", "radio_wlans_reduced"}:
        return "radios"
    for source in ("bgp", "ospf", "tunnels", "vpn_peers"):
        if kind == f"{source}_down":
            return source
    if kind == "vpn_loss":
        return "vpn_peers"
    return "device"


def _rise(  # noqa: PLR0913 - explicit comparison thresholds
    kind: str, subject: str, before: object, after: object, *, threshold: float, increase: float
) -> list[DeviceStateFinding]:
    old, new = _number(before), _number(after)
    if old is None or new is None or new < threshold or new - old < increase:
        return []
    return [
        _finding(
            kind, subject, old, new, f"{subject} increased from {old:g} to {new:g} after the configuration trigger."
        )
    ]


def _device_findings(before: dict[str, object], after: dict[str, object]) -> list[DeviceStateFinding]:
    findings: list[DeviceStateFinding] = []
    if before.get("status") == "connected" and after.get("status") == "disconnected":
        findings.append(
            _finding(
                "device_disconnected",
                "device",
                "connected",
                "disconnected",
                "Device disconnected after the configuration trigger.",
                severity="critical",
            )
        )
    old_up, new_up = _number(before.get("uptime")), _number(after.get("uptime"))
    if old_up is not None and new_up is not None and new_up < old_up:
        findings.append(
            _finding(
                "device_restarted",
                "uptime",
                old_up,
                new_up,
                "Uptime reset; the device restarted during the comparison interval.",
            )
        )
    for key, threshold, increase in [("cpu_stat", 85, 25), ("memory_stat", 90, 15)]:
        old = before.get(key)
        new = after.get(key)
        if isinstance(old, dict) and isinstance(new, dict):
            findings.extend(_rise(key, key, old.get("usage"), new.get("usage"), threshold=threshold, increase=increase))
    findings.extend(
        _rise(
            "cpu_util", "AP CPU utilization", before.get("cpu_util"), after.get("cpu_util"), threshold=85, increase=25
        )
    )
    return findings


def _wlans(before: DeviceStateObservation, after: DeviceStateObservation) -> list[DeviceStateFinding]:
    findings: list[DeviceStateFinding] = []
    old = _index(before.wlans, ("id",))
    new = _index(after.wlans, ("id",))
    for key, wlan in old.items():
        if wlan.get("enabled") is False:
            continue
        if key in new and new[key].get("enabled") is not False:
            continue
        clients = len(
            {
                str(client.get("mac"))
                for client in before.clients
                if client.get("mac")
                and (
                    client.get("wlan_id") == key
                    or (wlan.get("ssid") is not None and client.get("ssid") == wlan.get("ssid"))
                )
            }
        )
        findings.append(
            _finding(
                "ssid_removed",
                str(wlan.get("ssid", key)),
                "configured",
                "removed or disabled",
                (
                    f"SSID removed or disabled; {clients} clients were observed on it at the initial capture."
                    if "clients" in before.available
                    else (
                        "SSID removed or disabled; initial client data was unavailable, "
                        "so the affected client count is unknown."
                    )
                ),
                clients=clients,
            )
        )
    return findings


def _peers(
    before: DeviceStateObservation, after: DeviceStateObservation, source: str, keys: tuple[str, ...]
) -> list[DeviceStateFinding]:
    findings: list[DeviceStateFinding] = []
    old = _index(getattr(before, source), keys)
    new = _index(getattr(after, source), keys)
    for key, peer in old.items():
        current = new.get(key)
        if peer.get("up") is True and (current is None or current.get("up") is False):
            findings.append(
                _finding(
                    f"{source}_down",
                    key,
                    "up",
                    "missing" if current is None else "down",
                    f"Previously established {source.replace('_', ' ')} is no longer up.",
                    severity="critical",
                )
            )
        if source == "vpn_peers" and current:
            findings.extend(_rise("vpn_loss", key, peer.get("loss"), current.get("loss"), threshold=5, increase=5))
    return findings


def _radios(before: DeviceStateObservation, after: DeviceStateObservation) -> list[DeviceStateFinding]:
    findings: list[DeviceStateFinding] = []
    old = _index(before.radios, ("band",))
    new = _index(after.radios, ("band",))
    for key, radio in old.items():
        current = new.get(key)
        clients = int(_number(radio.get("num_clients")) or 0)
        if current is None and clients:
            findings.append(
                _finding(
                    "radio_missing",
                    key,
                    "present",
                    "missing",
                    f"Radio with {clients} observed clients disappeared.",
                    clients=clients,
                )
            )
        elif current:
            findings.extend(
                _rise("rf_utilization", key, radio.get("util_all"), current.get("util_all"), threshold=85, increase=25)
            )
            old_wlans, new_wlans = _number(radio.get("num_wlans")), _number(current.get("num_wlans"))
            if old_wlans is not None and new_wlans is not None and new_wlans < old_wlans:
                findings.append(
                    _finding(
                        "radio_wlans_reduced",
                        key,
                        old_wlans,
                        new_wlans,
                        f"Fewer WLANs are advertised on this radio; {clients} clients were initially observed.",
                        clients=clients,
                    )
                )
    return findings
