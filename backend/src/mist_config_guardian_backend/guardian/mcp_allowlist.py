"""The frozen MCP read allowlist: ``(tool, discriminator value)`` to the server-owned evidence kind.

Ported verbatim from the Task 1 fixture ``backend/tests/fixtures/guardian/mcp_allowlist.json``, which was frozen
from the recorded catalogue. ``tests/test_guardian_reader.py`` cross-checks this table against that fixture, so the
two cannot drift.

Events, statistics, SLE, insights and operational searches are ``service_health``; configuration and schema reads
are ``configuration``; constants and documentation are ``reference``. A combination that is absent is not
allowlisted: the secret-bearing ``psks`` and ``webhooks`` objects, the discovery, inventory, identity and rogue
searches, and the ``find_mist_entity`` and ``get_mist_self`` tools are all absent on purpose.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from mist_config_guardian_backend.guardian.contracts import EvidenceKind

_CONFIGURATION_OBJECTS = (
    "sites",
    "alarmtemplates",
    "deviceprofiles",
    "gatewaytemplates",
    "networktemplates",
    "networks",
    "rftemplates",
    "services",
    "servicepolicies",
    "sitegroups",
    "sitetemplates",
    "vpns",
    "wlantemplates",
    "wlans",
    "wxrules",
    "wxtags",
    "evpn_topologies",
    "nactags",
    "nacrules",
    "avprofiles",
    "idpprofiles",
    "aamwprofiles",
    "mxclusters",
    "mxedges",
    "mxtunnels",
    "devices",
    "maps",
)
_CONSTANTS = (
    "insight_metrics",
    "device_events",
    "client_events",
    "nac_events",
    "mxedge_events",
    "system_events",
    "otherdevice_events",
    "alarm_definitions",
    "device_models",
    "mxedge_models",
    "otherdevice_models",
    "ap_channels",
    "ap_led_status",
    "default_gateway_config",
    "traffic_types",
    "app_categories",
    "app_subcategories",
    "applications",
    "gateway_applications",
    "license_types",
    "fingerprint_types",
    "webhook_topics",
    "ap_esl_versions",
    "marvisclient_versions",
    "countries",
    "states",
    "languages",
)
_INSIGHTS = ("marvis_actions", "troubleshoot", "insight_metrics", "sle")
_STATISTICS = (
    "org",
    "sites",
    "org_mxedges",
    "org_devices",
    "org_bgp",
    "org_ospf",
    "org_peer_paths",
    "org_ports",
    "org_tunnels",
    "site_mxedges",
    "site_wireless_clients",
    "site_devices",
    "site_bgp",
    "site_ospf",
    "site_ports",
)
_SEARCHES = (
    "devices",
    "wireless_clients",
    "wired_clients",
    "wan_clients",
    "nac_clients",
    "device_events",
    "wireless_client_events",
    "wan_client_events",
    "nac_client_events",
    "mxedge_events",
    "alarms",
    "client_sessions",
)


@dataclass(frozen=True, slots=True)
class AllowedTool:
    """One allowlisted read-only tool and the evidence kind of each of its discriminator values."""

    name: str
    discriminator: str
    kinds: Mapping[str, EvidenceKind]


def _tool(name: str, discriminator: str, values: tuple[str, ...], kind: EvidenceKind) -> AllowedTool:
    return AllowedTool(name, discriminator, MappingProxyType(dict.fromkeys(values, kind)))


ALLOWLIST: Mapping[str, AllowedTool] = MappingProxyType(
    {
        tool.name: tool
        for tool in (
            _tool("get_mist_config", "resource_type", _CONFIGURATION_OBJECTS, "configuration"),
            _tool("get_mist_constants", "constant_type", _CONSTANTS, "reference"),
            _tool("get_mist_insights", "insight_type", _INSIGHTS, "service_health"),
            _tool("get_mist_stats", "stats_type", _STATISTICS, "service_health"),
            _tool("search_mist_data", "search_type", _SEARCHES, "service_health"),
        )
    }
)


def discriminator_value(tool: str, arguments: Mapping[str, object]) -> str | None:
    """The discriminating argument of an allowlisted tool, when it is present and a string."""
    entry = ALLOWLIST.get(tool)
    if entry is None:
        return None
    value = arguments.get(entry.discriminator)
    return value if isinstance(value, str) else None


def evidence_kind(tool: str, arguments: Mapping[str, object]) -> EvidenceKind | None:
    """The server-owned evidence kind of one call, or ``None`` when it is outside the allowlist."""
    entry = ALLOWLIST.get(tool)
    value = discriminator_value(tool, arguments)
    if entry is None or value is None:
        return None
    return entry.kinds.get(value)
