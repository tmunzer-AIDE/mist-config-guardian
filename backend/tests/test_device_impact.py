"""Evidence-based disruption detection across APs, switches and gateways."""

from mist_config_guardian_backend.models.telemetry import DeviceStateObservation
from mist_config_guardian_backend.services.device_impact import compare_device_states


def test_removed_ssid_reports_previously_connected_clients_and_rf_degradation():
    before = DeviceStateObservation(
        available=["wlans", "clients", "radios"],
        wlans=[{"id": "a", "ssid": "Staff", "enabled": True}],
        clients=[{"mac": "c1", "wlan_id": "a"}, {"mac": "c2", "ssid": "Staff"}],
        radios=[{"band": "band_5", "util_all": 20}],
    )
    after = DeviceStateObservation(
        available=["wlans", "clients", "radios"], radios=[{"band": "band_5", "util_all": 92}]
    )
    findings = compare_device_states(before, after)
    assert [finding.kind for finding in findings] == ["ssid_removed", "rf_utilization"]
    assert findings[0].affected_clients == 2


def test_missing_client_source_does_not_claim_zero_affected_clients():
    before = DeviceStateObservation(available=["wlans"], wlans=[{"id": "a", "ssid": "Staff"}])
    after = DeviceStateObservation(available=["wlans"])
    assert "unknown" in compare_device_states(before, after)[0].detail


def test_occupied_switch_port_down_reports_clients_and_interface_errors():
    before = DeviceStateObservation(
        available=["ports", "clients"],
        ports=[{"port_id": "ge-0/0/1", "up": True, "mac_count": 2, "rx_errors": 4}],
        clients=[{"mac": "c1", "port_id": "ge-0/0/1"}],
    )
    after = DeviceStateObservation(
        available=["ports", "clients"], ports=[{"port_id": "ge-0/0/1", "up": False, "rx_errors": 150}]
    )
    findings = compare_device_states(before, after)
    assert findings[0].kind == "occupied_port_down"
    assert findings[0].affected_clients == 2
    assert findings[0].severity == "critical"
    assert findings[1].kind == "interface_errors"


def test_gateway_reports_lost_peers_and_tunnels_using_latest_samples():
    before = DeviceStateObservation(
        available=["bgp", "ospf", "tunnels", "vpn_peers"],
        bgp=[{"neighbor": "192.0.2.1", "up": True}],
        ospf=[{"peer_ip": "192.0.2.2", "up": True}],
        tunnels=[{"tunnel_name": "HQ", "up": True}],
        vpn_peers=[{"peer_mac": "peer-a", "up": True, "loss": 0}],
    )
    after = DeviceStateObservation(
        available=before.available,
        bgp=[
            {"neighbor": "192.0.2.1", "up": False, "timestamp": 200},
            {"neighbor": "192.0.2.1", "up": True, "timestamp": 100},
        ],
        vpn_peers=[{"peer_mac": "peer-a", "up": True, "loss": 10}],
    )
    assert {finding.kind for finding in compare_device_states(before, after)} == {
        "bgp_down",
        "ospf_down",
        "tunnels_down",
        "vpn_loss",
    }


def test_failed_telemetry_and_normal_roaming_do_not_create_outages():
    before = DeviceStateObservation(
        available=["ports", "wlans", "bgp", "clients"],
        ports=[{"port_id": "ge-0/0/1", "up": True}],
        wlans=[{"id": "a"}],
        bgp=[{"neighbor": "192.0.2.1", "up": True}],
        clients=[{"mac": "client-a"}],
    )
    after = DeviceStateObservation(available=["clients"], errors={"ports": "unavailable"})
    assert compare_device_states(before, after) == []


def test_device_restart_and_resource_pressure_are_explained():
    before = DeviceStateObservation(
        available=["device"],
        device={"uptime": 10000, "status": "connected", "cpu_stat": {"usage": 25}, "memory_stat": {"usage": 50}},
    )
    after = DeviceStateObservation(
        available=["device"],
        device={"uptime": 60, "status": "disconnected", "cpu_stat": {"usage": 95}, "memory_stat": {"usage": 95}},
    )
    assert {finding.kind for finding in compare_device_states(before, after)} == {
        "device_restarted",
        "device_disconnected",
        "cpu_stat",
        "memory_stat",
    }
