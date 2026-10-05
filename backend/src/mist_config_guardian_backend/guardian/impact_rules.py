"""Digital-twin impact-rule applicability hints for Guardian's investigator.

The digital twin reasons over a vendor-neutral IR, while Guardian starts with the
raw object paths recorded for an audit.  This module ports the twin check
registry's ``applies_to`` relationships and conservatively maps supported Mist
configuration roots to the IR entities they can change.

The result is deliberately only an investigation guide.  A candidate check is
not a finding and does not claim deterministic coverage.  It tells the agent
which failure modes are worth testing with scoped Mist reads when the existing
rule, deployment, event, and SLE evidence does not answer the change.
"""

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass

from mist_config_guardian_backend.guardian.change import ChangeSet

SOURCE_REPOSITORY = "https://github.com/tmunzer-AIDE/digital-twin"
SOURCE_COMMIT = "6840acea3c4ac2cf27411e443c04756074362e0f"


@dataclass(frozen=True, slots=True)
class ImpactRule:
    """One digital-twin check and the IR entity kinds that make it applicable."""

    id: str
    touches: frozenset[str]


def _rule(identity: str, *touches: str) -> ImpactRule:
    return ImpactRule(identity, frozenset(touches))


# Kept in the digital twin's registry order.  The two NAC rules are evaluated
# by its separate org-NAC pipeline but share the same applicability contract.
IMPACT_RULES: tuple[ImpactRule, ...] = (
    _rule("wired.l2.topology_coverage", "device", "link", "l3intf", "port", "vlan"),
    _rule("wired.l2.loop", "link", "port", "vlan", "device"),
    _rule("wired.l2.blackhole", "link", "port", "vlan", "l3intf", "device"),
    _rule("wired.l2.isolation", "link", "port", "device"),
    _rule("wired.l2.vlan_segmentation", "link", "port", "vlan", "device"),
    _rule("wired.l2.native_mismatch", "link", "port", "device"),
    _rule("wired.l2.mtu_mismatch", "link", "port", "device"),
    _rule("wired.l1.link_param_mismatch", "link", "port", "device"),
    _rule("wired.stp.edge_on_uplink", "link", "port", "device"),
    _rule("wired.stp.policy", "port"),
    _rule("wired.stp.root_change", "device", "link", "port"),
    _rule("wired.l3.gateway_gap", "vlan", "l3intf"),
    _rule("wired.l3.ospf_withdrawal", "ospf_intf", "vlan_subnet"),
    _rule("wired.l3.bgp_adjacency", "bgp_peer"),
    _rule("wired.dhcp.path", "vlan", "device"),
    _rule("wired.dhcp.scope_lint", "dhcp_scope", "vlan"),
    _rule("wired.dhcp.snooping", "device", "port", "dhcp_scope", "vlan", "link"),
    _rule("wired.poe.disconnect", "port"),
    _rule("wired.port.admin_disable", "port"),
    _rule("wired.auth.access_change", "port", "client"),
    _rule("wired.client.impact", "port", "link", "vlan", "client", "l3intf"),
    _rule("wireless.wlan.client_impact", "wlan"),
    _rule("wireless.wlan.open_guest", "wlan"),
    _rule("wireless.wlan.duplicate_ssid", "wlan"),
    _rule("wired.l3.subnet_overlap", "vlan"),
    _rule("wired.l2.vlan_collision", "vlan"),
    _rule("wired.port.mac_limit_exceeded", "port", "client"),
    _rule("wired.port.unmodeled_change", "port"),
    _rule("wired.auth.radius_missing", "device", "port"),
    _rule("wired.l3.static_route_reachability", "static_route", "l3intf"),
    _rule("wired.l3.control_plane_reachability", "static_route", "l3intf", "port"),
    _rule("wired.port.storm_control_policy", "port", "link"),
    _rule("nac.rule.change", "nacrule"),
    _rule("nac.rule.shadowed", "nacrule"),
)

_WIRED_ENTITIES = frozenset(
    {
        "device",
        "port",
        "link",
        "vlan",
        "vlan_subnet",
        "l3intf",
        "dhcp_scope",
        "ospf_intf",
        "bgp_peer",
        "static_route",
        "client",
    }
)
_PORT_ENTITIES = frozenset({"device", "port", "link", "vlan", "client"})

# This is intentionally conservative: an entity that might change admits a
# candidate check.  The agent still has to establish the issue with evidence.
_ROOT_ENTITIES: Mapping[str, frozenset[str]] = {
    "networks": frozenset({"vlan", "vlan_subnet", "l3intf"}),
    "org_networks": frozenset({"vlan", "vlan_subnet", "l3intf"}),
    "other_ip_configs": frozenset({"vlan", "vlan_subnet", "l3intf"}),
    "ip_configs": frozenset({"vlan", "vlan_subnet", "l3intf"}),
    "ip_config": frozenset({"l3intf"}),
    "port_usages": _PORT_ENTITIES,
    "port_config": _PORT_ENTITIES,
    "local_port_config": _PORT_ENTITIES,
    "port_config_overwrite": _PORT_ENTITIES,
    "stp_config": frozenset({"device", "port", "link"}),
    "dhcpd_config": frozenset({"device", "dhcp_scope", "vlan"}),
    "dhcp_snooping": frozenset({"device", "port", "link", "dhcp_scope", "vlan"}),
    "ospf_config": frozenset({"ospf_intf", "vlan_subnet"}),
    "ospf_areas": frozenset({"ospf_intf", "vlan_subnet"}),
    "bgp_config": frozenset({"bgp_peer"}),
    "radius_config": frozenset({"device"}),
    "mist_nac": frozenset({"device"}),
    "extra_routes": frozenset({"static_route"}),
    "extra_routes6": frozenset({"static_route"}),
    "switch_matching": _PORT_ENTITIES,
    "networktemplate_id": _WIRED_ENTITIES,
    "gatewaytemplate_id": _WIRED_ENTITIES,
    "sitetemplate_id": _WIRED_ENTITIES,
    # Site settings carry nested switch/gateway configuration in Guardian's
    # snapshot shape.  Until the path is compiled to the twin IR, both are
    # broad candidates rather than grounds for silently omitting a check.
    "switch": _WIRED_ENTITIES,
    "gateway": _WIRED_ENTITIES,
    # Variables can ripple through any modeled effective configuration leaf.
    "vars": _WIRED_ENTITIES,
}

_WIRED_OBJECTS = frozenset(
    {
        "settings",
        "sites",
        "devices",
        "networktemplates",
        "gatewaytemplates",
        "sitetemplates",
        "switchprofiles",
        "hubprofiles",
    }
)
_OBJECT_ENTITIES: Mapping[str, frozenset[str]] = {
    "wlans": frozenset({"wlan"}),
    # Guardian stores Mist's generic /templates under this key. Its paths alone
    # do not identify a template subtype, so admit candidates without claiming
    # that the twin supports simulation of every template field.
    "templates": _WIRED_ENTITIES | {"wlan"},
    "nacrules": frozenset({"nacrule"}),
    "networks": frozenset({"vlan", "vlan_subnet", "l3intf"}),
}
_HINT_CHARS = 440


def candidate_rules(change: ChangeSet) -> tuple[ImpactRule, ...]:
    """Return the twin checks that could apply to this audit's changed paths."""
    attributes: defaultdict[tuple[str, int], set[str]] = defaultdict(set)
    for atom in change.atoms:
        attributes[atom.logical_object_id, atom.version].add(atom.attribute)
    entities: set[str] = set()
    for changed in change.objects:
        roots = attributes[changed.logical_object_id, changed.version]
        if changed.object_type in _OBJECT_ENTITIES:
            if changed.change_kind != "modified" or roots:
                entities.update(_OBJECT_ENTITIES[changed.object_type])
            continue
        if changed.object_type not in _WIRED_OBJECTS:
            continue
        if changed.change_kind != "modified":
            entities.update(_WIRED_ENTITIES)
        for root in roots:
            entities.update(_ROOT_ENTITIES.get(root, ()))
    return tuple(rule for rule in IMPACT_RULES if rule.touches & entities)


def agent_hints(change: ChangeSet) -> dict[str, str]:
    """Build bounded prompt hints naming applicable checks without claiming a finding."""
    identities = [rule.id for rule in candidate_rules(change)]
    if not identities:
        return {}
    prefix = "Digital-twin candidates, not findings; verify before/after service health: "
    chunks: list[str] = []
    current = prefix
    for identity in identities:
        separator = "" if current.endswith(" ") else ", "
        if len(current) + len(separator) + len(identity) > _HINT_CHARS:
            chunks.append(current)
            current = identity
        else:
            current += f"{separator}{identity}"
    chunks.append(current)
    return {f"impact-rules-{index}": chunk for index, chunk in enumerate(chunks, start=1)}
