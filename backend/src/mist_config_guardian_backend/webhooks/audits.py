"""Resolution of Mist audit events to restorable object definitions."""

import re
from dataclasses import dataclass

from mist_config_guardian_backend.snapshots.registry import (
    ORG_OBJECTS,
    SITE_OBJECTS,
    ObjectDefinition,
)

_OBJECT_ALIASES = {
    "alarmtemplate": "alarmtemplates",
    "aptemplate": "aptemplates",
    "asset": "assets",
    "assetfilter": "assetfilters",
    "avprofile": "avprofiles",
    "beacon": "beacons",
    "device": "devices",
    "deviceprofile": "deviceprofiles",
    "gatewaytemplate": "gatewaytemplates",
    "idpprofile": "idpprofiles",
    "map": "maps",
    "mxcluster": "mxclusters",
    "mxedge": "mxedges",
    "mxtunnel": "mxtunnels",
    "nacportal": "nacportals",
    "nacrule": "nacrules",
    "nactag": "nactags",
    "network": "networks",
    "networktemplate": "networktemplates",
    "psk": "psks",
    "pskportal": "pskportals",
    "rftemplate": "rftemplates",
    "rssizone": "rssizones",
    "secpolicy": "secpolicies",
    "secintelprofile": "secintelprofiles",
    "service": "services",
    "servicepolicy": "servicepolicies",
    "site": "sites",
    "sitegroup": "sitegroups",
    "sitetemplate": "sitetemplates",
    "sso": "ssos",
    "ssorole": "ssoroles",
    "template": "templates",
    "vbeacon": "vbeacons",
    "vpn": "vpns",
    "webhook": "webhooks",
    "wlan": "wlans",
    "wxrule": "wxrules",
    "wxtag": "wxtags",
    "zone": "zones",
}
_MESSAGE_PATTERN = re.compile(
    r"^(?:add|create|delete|modify|remove|update)\s+([a-zA-Z ]+?)(?:\s+\"|$)",
    re.IGNORECASE,
)
# Mist writes the verb before the noun for most objects ("Update MxCluster") but
# after it for some org-level ones ("Org API Token ... created"), so the verb is
# matched anywhere in the message rather than only at the start.
_CONFIG_VERBS = (
    "add",
    "added",
    "assign",
    "assigned",
    "create",
    "created",
    "delete",
    "deleted",
    "disable",
    "disabled",
    "enable",
    "enabled",
    "modified",
    "modify",
    "remove",
    "removed",
    "rename",
    "renamed",
    "unassign",
    "unassigned",
    "update",
    "updated",
)
_CONFIG_VERB_PATTERN = re.compile(rf"\b(?:{'|'.join(_CONFIG_VERBS)})\b", re.IGNORECASE)
_QUOTED_SEGMENT = re.compile(r'"[^"]*"')


@dataclass(frozen=True)
class AuditTarget:
    """Resolved audit target."""

    definition: ObjectDefinition
    object_id: str | None
    site_id: str | None
    deleted: bool
    object_name: str | None


def resolve_audit_target(payload: dict[str, object]) -> AuditTarget | None:
    """Resolve common Mist audit fields without trusting message text alone."""
    site_id = _string(payload.get("site_id"))
    registry = SITE_OBJECTS if site_id else ORG_OBJECTS
    fallback = ORG_OBJECTS if site_id else SITE_OBJECTS
    definitions = {item.key: item for item in registry}
    fallback_definitions = {item.key: item for item in fallback}

    explicit_type = _string(payload.get("object"))
    if explicit_type:
        definition = definitions.get(explicit_type) or fallback_definitions.get(explicit_type)
        if definition:
            return _target(definition, _string(payload.get("id")), site_id, payload)

    for field_name, value in payload.items():
        if not field_name.endswith("_id") or field_name in {
            "admin_id",
            "audit_id",
            "org_id",
            "site_id",
        }:
            continue
        key = _OBJECT_ALIASES.get(field_name.removesuffix("_id"))
        if key is None:
            continue
        definition = definitions.get(key) or fallback_definitions.get(key)
        if definition:
            return _target(definition, _string(value), site_id, payload)

    message = _string(payload.get("message")) or ""
    match = _MESSAGE_PATTERN.match(message)
    if not match:
        return None
    normalized = match.group(1).replace(" ", "").lower()
    if normalized == "sitesettings":
        # Settings are a site singleton. The audit's `id` identifies the
        # action, not the configuration object, and a site is required.
        return _target(definitions["settings"], None, site_id, payload) if site_id is not None else None
    key = _OBJECT_ALIASES.get(normalized)
    definition = definitions.get(key or "") or fallback_definitions.get(key or "")
    if definition is None:
        return None
    object_id = site_id if definition.key == "sites" else None
    return _target(definition, object_id, site_id, payload)


def is_configuration_change(payload: dict[str, object]) -> bool:
    """Report whether an audit event changed configuration rather than operated.

    Mist audits every administrator action, most of which change nothing that
    can be backed up or restored: accessing an org, starting a packet capture,
    logging in. Storing those buries the changes that matter.

    An event counts when it resolves to a registry object, or -- for the
    org-level objects the registry does not carry -- when its message uses a
    configuration verb. Quoted names are stripped before the verb is looked
    for, so an org named "Update Test" does not make every access of it look
    like a change.
    """
    if resolve_audit_target(payload) is not None:
        return True
    message = _string(payload.get("message"))
    if message is None:
        return False
    return _CONFIG_VERB_PATTERN.search(_QUOTED_SEGMENT.sub(" ", message)) is not None


def _target(
    definition: ObjectDefinition,
    object_id: str | None,
    site_id: str | None,
    payload: dict[str, object],
) -> AuditTarget:
    message = _string(payload.get("message")) or ""
    name_match = re.search(r'"([^"]+)"', message)
    return AuditTarget(
        definition=definition,
        object_id=None if object_id == "None" else object_id,
        site_id=site_id if definition.scope == "site" else None,
        deleted=message.strip().lower().startswith(("delete ", "remove ")),
        object_name=name_match.group(1) if name_match else None,
    )


def _string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None
