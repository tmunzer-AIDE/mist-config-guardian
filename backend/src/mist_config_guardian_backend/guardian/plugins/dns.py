"""The DNS rule: what a changed name-resolution setting can affect, per object type and attribute.

There is no generic mapping. Every entry below is one verified row of the frozen Task 1 record
(``backend/tests/fixtures/guardian/dns_attribute_semantics.json``, decision ``dns_attribute_semantics`` in
``docs/design/guardian.md``), which cites the Mist configuration schema text it was decided from. An attribute the
record classes ``unverified``, or that it does not list at all, is not handled here, so its rows stay uncovered.

A setting the schema documents as the device's own resolver gets an infrastructure-connectivity obligation with
``empty_policy=incomplete``: no data is a hole, not an answer. One documented as what the device hands its clients
gets a client obligation with ``empty_policy=not_exercised``: no client traffic means the setting was never tried.
A dual-use setting gets both (controller ruling R12), so a healthy management path can never hide a client effect.

The plug-in reads nothing: it plans monitoring observations, and monitoring replay answers them.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from mist_config_guardian_backend.guardian.change import ChangedObject, ChangeSet
from mist_config_guardian_backend.guardian.contracts import (
    ChangeAtom,
    Conclusion,
    ConfigPath,
    EmptyPolicy,
    Evidence,
    ExpectedDevice,
    Obligation,
    RuleConclusion,
    RulePlan,
    Target,
)
from mist_config_guardian_backend.guardian.plugins import base
from mist_config_guardian_backend.guardian.reader import Reader

ID = "dns"
VERSION = "1"
MAX_READS = 0

MANAGEMENT = "management_resolution"
CLIENT = "client_resolution"
DUAL = "management_and_client_resolution"

# The metric each device family answers an infrastructure-connectivity or a client obligation with.
INFRASTRUCTURE_METRICS: dict[str, str] = {
    "ap": "ap-health",
    "switch": "switch-health",
    "gateway": "gateway-health",
}
CLIENT_METRICS: dict[str, str] = {
    "ap": "successful-connect",
    "switch": "switch-stc",
    "gateway": "application-health",
}
INFRASTRUCTURE_INCIDENTS = ("AP_DISCONNECTED", "GW_DISCONNECTED", "SW_DISCONNECTED")
INFRASTRUCTURE_FINDINGS = ("device_disconnected",)

AGENT_HINT = (
    "A changed DNS setting is judged by what the schema says it does. A device's own resolver is judged by the "
    "device's reachability and health, and no data there is a hole, not health. A resolver handed to clients is "
    "judged by client connection and application experience, and no client traffic means the setting was never "
    "exercised. A setting that is both is judged by both. Attributes with no verified effect stay uncovered; do not "
    "infer one from a name."
)

_DHCPD = (("dhcpd_config", "*", "dns_servers"), ("dhcpd_config", "*", "dns_suffix"))
_IP_CONFIG = (("ip_config", "dns"), ("ip_config", "dns_suffix"))
_SERVERS = (("dns_servers",),)
_SUFFIX = (("dns_suffix",),)


def _under(prefix: str, paths: Sequence[Sequence[str]]) -> tuple[tuple[str, ...], ...]:
    """The same patterns below one attribute, as a site setting nests a device family's own settings."""
    return tuple((prefix, *path) for path in paths)


@dataclass(frozen=True, slots=True)
class DnsMapping:
    """One verified (object type, attribute) classification, with the path patterns it covers.

    ``*`` matches one object key and ``[]`` one list index, exactly as the frozen record writes them. ``mxedge`` is
    not a device family Guardian monitors, so its one management row can match no device and stays uncovered.
    """

    object_type: str
    attribute: str
    semantics: str
    device_type: str
    paths: tuple[tuple[str, ...], ...]

    @property
    def variant(self) -> str | None:
        """The device variant of a device object; every other object type has none."""
        return self.device_type if self.object_type == "site:devices" else None

    @property
    def classes(self) -> tuple[str, ...]:
        return (MANAGEMENT, CLIENT) if self.semantics == DUAL else (self.semantics,)


MAPPINGS: tuple[DnsMapping, ...] = tuple(
    DnsMapping(*row)
    for row in (
        ("org:deviceprofiles", "ip_config", MANAGEMENT, "ap", _IP_CONFIG),
        ("org:gatewaytemplates", "dhcpd_config", CLIENT, "gateway", _DHCPD),
        ("org:gatewaytemplates", "dnsOverride", DUAL, "gateway", (("dnsOverride",),)),
        ("org:gatewaytemplates", "dns_servers", DUAL, "gateway", _SERVERS),
        ("org:gatewaytemplates", "dns_suffix", DUAL, "gateway", _SUFFIX),
        ("org:hubprofiles", "dhcpd_config", CLIENT, "gateway", _DHCPD),
        ("org:hubprofiles", "dnsOverride", DUAL, "gateway", (("dnsOverride",),)),
        ("org:hubprofiles", "dns_servers", DUAL, "gateway", _SERVERS),
        ("org:hubprofiles", "dns_suffix", DUAL, "gateway", _SUFFIX),
        ("org:mxedges", "oob_ip_config", MANAGEMENT, "mxedge", (("oob_ip_config", "dns"),)),
        ("org:networktemplates", "dns_servers", DUAL, "switch", _SERVERS),
        ("org:networktemplates", "dns_suffix", DUAL, "switch", _SUFFIX),
        ("org:switchprofiles", "dhcpd_config", CLIENT, "switch", _DHCPD),
        ("org:switchprofiles", "dns_servers", DUAL, "switch", _SERVERS),
        ("org:switchprofiles", "dns_suffix", DUAL, "switch", _SUFFIX),
        ("org:switchprofiles", "ip_config", DUAL, "switch", _IP_CONFIG),
        ("org:wlans", "dns_server_rewrite", CLIENT, "ap", (("dns_server_rewrite",),)),
        ("org:wlans", "no_static_dns", CLIENT, "ap", (("no_static_dns",),)),
        ("site:devices", "ip_config", MANAGEMENT, "ap", _IP_CONFIG),
        ("site:devices", "dhcpd_config", CLIENT, "gateway", _DHCPD),
        ("site:devices", "dns_servers", DUAL, "gateway", _SERVERS),
        ("site:devices", "dns_suffix", DUAL, "gateway", _SUFFIX),
        ("site:devices", "dhcpd_config", CLIENT, "switch", _DHCPD),
        ("site:devices", "dns_servers", DUAL, "switch", _SERVERS),
        ("site:devices", "dns_suffix", DUAL, "switch", _SUFFIX),
        ("site:devices", "ip_config", DUAL, "switch", _IP_CONFIG),
        ("site:settings", "gateway", CLIENT, "gateway", _under("gateway", _DHCPD)),
        ("site:settings", "gateway", DUAL, "gateway", _under("gateway", (("dnsOverride",), *_SERVERS, *_SUFFIX))),
        ("site:settings", "switch", DUAL, "switch", _under("switch", (*_SERVERS, *_SUFFIX))),
        ("site:wlans", "dns_server_rewrite", CLIENT, "ap", (("dns_server_rewrite",),)),
        ("site:wlans", "no_static_dns", CLIENT, "ap", (("no_static_dns",),)),
    )
)


class DnsPlugin:
    """DNS attributes, per object type: monitoring observations only, and only where Task 1 verified the effect."""

    id = ID
    version = VERSION
    max_reads = MAX_READS
    agent_hint = AGENT_HINT

    def plan(self, change: ChangeSet, devices: Sequence[ExpectedDevice]) -> RulePlan | None:
        claims: dict[tuple[str, str, str, EmptyPolicy], tuple[ConfigPath, ...]] = {}
        classes: set[str] = set()
        for changed in change.objects:
            for atom in base.atoms_of(change, changed):
                for mapping in _mappings(changed, atom):
                    matched = tuple(path for path in atom.paths if matches(mapping.paths, path))
                    if matched:
                        classes.update(mapping.classes)
                        _claim(claims, mapping, atom, matched, _targets(mapping, changed, devices))
        if not claims:
            return None
        return RulePlan(
            obligations=base.numbered(
                [
                    Obligation(
                        id="O1",
                        owner=ID,
                        change_ref=atom_id,
                        paths=paths,
                        role="observation",
                        kind="monitoring",
                        target=Target(device_mac=mac, site_id=site_id),
                        metric=metric,
                        empty_policy=policy,
                    )
                    for (atom_id, mac, metric, policy), paths in sorted(claims.items())
                    for site_id in (_site_of(mac, devices),)
                ]
            ),
            incident_types=INFRASTRUCTURE_INCIDENTS if MANAGEMENT in classes else (),
            finding_kinds=INFRASTRUCTURE_FINDINGS if MANAGEMENT in classes else (),
        )

    async def collect(self, plan: RulePlan, reader: Reader) -> list[Evidence]:  # noqa: ARG002 - reads nothing
        """This rule reads nothing: monitoring already recorded what answers its obligations."""
        return []

    def evaluate(self, plan: RulePlan, evidence: Sequence[Evidence]) -> RuleConclusion:  # noqa: ARG002 - see collect
        """It claims no rule coverage, so it reports no status of its own."""
        return Conclusion()


def _claim(
    claims: dict[tuple[str, str, str, EmptyPolicy], tuple[ConfigPath, ...]],
    mapping: DnsMapping,
    atom: ChangeAtom,
    matched: tuple[ConfigPath, ...],
    targets: Sequence[str],
) -> None:
    """One obligation per device, metric and policy, with every matched path of this atom under it."""
    for mac in targets:
        for semantics in mapping.classes:
            metric, policy = _observation(mapping.device_type, semantics)
            key = (atom.id, mac, metric, policy)
            claims[key] = tuple(sorted({*claims.get(key, ()), *matched}))


def _observation(device_type: str, semantics: str) -> tuple[str, EmptyPolicy]:
    """A monitored family's metric and empty policy for one class; :func:`_targets` admits no other family."""
    if semantics == MANAGEMENT:
        return INFRASTRUCTURE_METRICS[device_type], "incomplete"
    return CLIENT_METRICS[device_type], "not_exercised"


def _mappings(changed: ChangedObject, atom: ChangeAtom) -> tuple[DnsMapping, ...]:
    key = f"{changed.scope}:{changed.object_type}"
    return tuple(item for item in MAPPINGS if item.object_type == key and item.attribute == atom.attribute)


def _targets(mapping: DnsMapping, changed: ChangedObject, devices: Sequence[ExpectedDevice]) -> tuple[str, ...]:
    """The devices this mapping applies to: the changed device itself, or the mapped family at the changed scope.

    A device of another family, or one whose family no trigger established, is never targeted, so the row stays
    uncovered instead of being claimed or excluded.
    """
    if mapping.device_type not in INFRASTRUCTURE_METRICS.keys() & CLIENT_METRICS.keys():
        return ()
    family = base.cohort(devices, device_type=mapping.device_type, site_id=changed.site_id)
    if changed.device_mac is not None:
        return (changed.device_mac,) if changed.device_mac in family else ()
    return family


def _site_of(mac: str, devices: Sequence[ExpectedDevice]) -> str:
    return next(device.site_id for device in devices if device.mac == mac)


def matches(patterns: Sequence[Sequence[str]], path: ConfigPath) -> bool:
    """Whether a verified pattern names this changed path or an ancestor of it.

    This is the record's own path language: ``*`` stands for one object key and ``[]`` for one list index, and a
    pattern that stops above a changed leaf still names it, because a list element of ``dns_servers`` is that
    setting changing.
    """
    return any(
        len(pattern) <= len(path) and all(_segment(left, right) for left, right in zip(pattern, path, strict=False))
        for pattern in patterns
    )


def _segment(pattern: str, segment: str) -> bool:
    if pattern == "*":
        return True
    if pattern == "[]":
        return segment.isdigit()
    return pattern == segment
