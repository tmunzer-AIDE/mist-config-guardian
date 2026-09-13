"""Bounded audit-version context, without configuration values or executable identities.

This is a presentation vocabulary, not an attribute-to-impact rule catalogue.
Unrecognized keys stay masked; broadening the vocabulary never authorizes a check.
"""

import re
from collections import Counter
from collections.abc import Sequence
from hashlib import sha256
from typing import Annotated, Literal, cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from mist_config_guardian_backend.impact.limits import MAX_AUDIT_VERSIONS
from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectVersion, VersionEvent
from mist_config_guardian_backend.snapshots.registry import ObjectFamily, impact_definition

MAX_CONTEXT_OBJECTS = 8
MAX_CONTEXT_FIELDS = 6
MAX_CONTEXT_VERSIONS = MAX_AUDIT_VERSIONS
Handle = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
# Only fixed labels cross the model boundary. Dynamic keys can contain names,
# credentials or instructions, even when their corresponding values are redacted.
_LABELS = frozenset(
    {
        "enabled",
        "disabled",
        "port_config",
        "port_config_overwrite",
        "port_usages",
        "poe",
        "networks",
        "vlan_id",
        "vlan_ids",
        "vlan_config",
        "ip_config",
        "dns_servers",
        "dhcp_config",
        "radius_config",
        "auth",
        "band",
        "radio_config",
        "rateset",
        "schedule",
        "ssid",
        "name",
        "type",
        "bgp_config",
        "ospf_config",
        "routing_policies",
        "static_routes",
        "vrf_config",
        "ntp_servers",
        "wan_configs",
        "vpn_options",
        "service_policies",
        "services",
        "networks_override",
        "deviceprofile_id",
        "networktemplate_id",
        "aptemplate_id",
        "gatewaytemplate_id",
        "wxtag_ids",
        "applies",
        "rftemplate_id",
        "wlan_ids",
    }
)
_PROTECTED = frozenset(
    {"password", "root_password", "psk", "secret", "api_secret", "client_secret", "private_key", "passphrase"}
)


class ContextContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AttributeChange(ContextContract):
    ref: Handle
    attribute: str = Field(max_length=64)
    # Values (including bools/numbers), nested keys and container contents stay out.
    before: Literal["present", "absent", "unknown", "withheld"]
    after: Literal["present", "absent", "unknown", "withheld"]


class ConfigurationChange(ContextContract):
    context_handle: Handle
    object_type: str = Field(max_length=64)
    scope: Literal["org", "site"]
    operation: Literal["removed", "changed", "created", "unknown"]
    comparison: Literal["paired", "baseline_unavailable", "incarnation_changed"]
    effective_change: Literal["assume_effective"] = "assume_effective"
    attributes: tuple[AttributeChange, ...] = Field(default=(), max_length=MAX_CONTEXT_FIELDS)
    omitted_attribute_count: int = Field(default=0, ge=0)
    # Direct changed-device identity only, never a template's inferred consumers.
    device_handle: Handle | None = None
    site_handle: Handle | None = None
    device_type: Literal["ap", "switch", "gateway"] | None = None


class ChangeContext(ContextContract):
    schema_version: Literal[1] = 1
    source: Literal["audit_configuration_versions"] = "audit_configuration_versions"
    changes: tuple[ConfigurationChange, ...] = Field(default=(), max_length=MAX_CONTEXT_OBJECTS)
    omitted_object_count: int = Field(default=0, ge=0)
    gaps: tuple[str, ...] = Field(default=(), max_length=8)
    # This context cannot establish either query authorization or fleet coverage.
    expected_device_count: None = None


def device_context_handle(organization_id: str, audit_id: str, site: UUID, mac: str) -> str:
    return sha256(f"{organization_id}:{audit_id}:{site}:{mac}".encode()).hexdigest()


def compile_change_context(  # noqa: C901 - explicit baseline and identity classification
    *,
    organization_id: str,
    audit_id: str,
    logicals: Sequence[LogicalObject],
    before: Sequence[ObjectVersion],
    after: Sequence[ObjectVersion],
) -> ChangeContext:
    objects = {str(o.id): o for o in logicals if str(o.organization_id) == organization_id}
    priors = {(str(v.logical_object_id), v.version): v for v in before if str(v.organization_id) == organization_id}
    counts = Counter(str(v.logical_object_id) for v in after)
    changes = []
    gaps: set[str] = set()
    for version in sorted(after, key=lambda v: (str(v.logical_object_id), v.version))[:MAX_CONTEXT_VERSIONS]:
        key = str(version.logical_object_id)
        logical = objects.get(key)
        if (
            str(version.organization_id) != organization_id
            or version.audit_id != audit_id
            or logical is None
            or version.id is None
        ):
            gaps.add("Configuration ownership or immutable identity is unavailable.")
            continue
        if counts[key] != 1:
            gaps.add("Multiple audit versions need net-change resolution; no terminal change was guessed.")
            continue
        if len(changes) >= MAX_CONTEXT_OBJECTS:
            break
        prior = priors.get((key, version.version - 1))
        paired = (
            prior is not None
            and prior.id is not None
            and not prior.is_deleted
            and prior.incarnation_id == version.incarnation_id
        )
        comparison = (
            "paired"
            if paired
            else "incarnation_changed"
            if prior is not None and prior.incarnation_id != version.incarnation_id
            else "baseline_unavailable"
        )
        if comparison == "incarnation_changed":
            gaps.add(
                "An object was replaced across incarnations; its earlier configuration is not a comparable baseline."
            )
        elif not paired:
            gaps.add("An immutable baseline is unavailable; earlier attribute state and effective scope are unknown.")
        handle = sha256(
            f"change-context.v1:{organization_id}:{audit_id}:{prior.id if prior else None}:{version.id}".encode()
        ).hexdigest()
        attributes = []
        fields = version.changed_fields
        for index, name in enumerate(fields[:MAX_CONTEXT_FIELDS]):
            protected = name in _PROTECTED
            label = name if name in _LABELS else "protected_attribute" if protected else "unrecognized_attribute"
            attributes.append(
                AttributeChange(
                    ref=sha256(f"{handle}:{index}".encode()).hexdigest(),
                    attribute=label,
                    before="withheld"
                    if protected
                    else "present"
                    if paired and name in prior.configuration
                    else "absent"
                    if paired
                    else "unknown",
                    after="withheld"
                    if protected
                    else "absent"
                    if version.is_deleted or name not in version.configuration
                    else "present",
                )
            )
        definition = impact_definition(logical.scope, logical.object_type)
        identity = (
            immutable_device_identity(version, prior if paired else None)
            if definition and definition.family is ObjectFamily.DEVICE
            else None
        )
        if definition and definition.family is ObjectFamily.DEVICE and identity is None:
            gaps.add(
                "A changed device lacks a consistent immutable MAC, site or type; no device candidate was inferred."
            )
        site, _mac, device_type = identity or (None, None, None)
        changes.append(
            ConfigurationChange(
                context_handle=handle,
                object_type=definition.key if definition else "unknown",
                scope=logical.scope,
                operation="removed"
                if version.is_deleted
                else "changed"
                if paired
                else "created"
                if version.version == 1 and getattr(version, "event", None) == VersionEvent.CREATED
                else "unknown",
                comparison=comparison,
                attributes=tuple(attributes),
                omitted_attribute_count=max(0, len(fields) - MAX_CONTEXT_FIELDS),
                device_handle=device_context_handle(organization_id, audit_id, identity[0], identity[1])
                if identity
                else None,
                site_handle=sha256(f"site-context.v1:{organization_id}:{audit_id}:{site}".encode()).hexdigest()
                if identity
                else None,
                device_type=device_type,
            )
        )
    omitted = len(counts) - len(changes)
    if omitted:
        gaps.add("Some audit objects were omitted or unresolved; the supplied set is not complete.")
    if any(c.omitted_attribute_count for c in changes):
        gaps.add("Attribute context was truncated; additional changes remain unexamined.")
    return ChangeContext(changes=tuple(changes), omitted_object_count=omitted, gaps=tuple(sorted(gaps)))


def immutable_device_identity(
    version: ObjectVersion, prior: ObjectVersion | None
) -> tuple[UUID, str, Literal["ap", "switch", "gateway"]] | None:
    """Read identity from immutable configuration, never today's logical-object fields."""

    def parse(config: dict[str, object]) -> tuple[UUID, str, Literal["ap", "switch", "gateway"]] | None:
        mac = config.get("mac")
        kind = config.get("type")
        if not isinstance(mac, str) or kind not in ("ap", "switch", "gateway"):
            return None
        mac = mac.replace(":", "").replace("-", "").lower()
        if re.fullmatch(r"[0-9a-f]{12}", mac) is None:
            return None
        try:
            return UUID(str(config.get("site_id", ""))), mac, cast('Literal["ap", "switch", "gateway"]', kind)
        except ValueError:
            return None

    current = parse(version.configuration)
    if prior is not None and current != parse(prior.configuration):
        return None
    return current
