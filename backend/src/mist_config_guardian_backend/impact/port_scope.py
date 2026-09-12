"""Resolve concrete changed ports without interpreting inheritance or provider prose."""

import re
from collections import Counter
from collections.abc import Sequence
from hashlib import sha256

from mist_config_guardian_backend.impact.change_context import device_context_handle, immutable_device_identity
from mist_config_guardian_backend.impact.contracts import PortTarget
from mist_config_guardian_backend.impact.limits import MAX_AUDIT_VERSIONS, MAX_PORT_TARGETS
from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectVersion
from mist_config_guardian_backend.snapshots.registry import ObjectFamily, impact_definition

_PORT = re.compile(r"^(ge|xe|et)-[0-9]{1,3}/[0-9]{1,3}/[0-9]{1,3}$")
_CONTAINERS = ("port_config", "port_config_overwrite")
_MAX_KEYS = 256


def compile_port_targets(  # noqa: C901, PLR0912, PLR0915 - bounded identity and selector resolution
    *,
    organization_id: str,
    audit_id: str,
    logicals: Sequence[LogicalObject],
    before: Sequence[ObjectVersion],
    after: Sequence[ObjectVersion],
) -> tuple[tuple[PortTarget, ...], tuple[str, ...]]:
    """At most two checks per audit. Unresolved selectors never become URL inputs.

    Missing baselines assume effective: inspect known current concrete entries.
    Their absence cannot establish the complete changed-port set. Cross-incarnation
    identity is unresolved and cannot authorize a check against the replacement.
    """
    objects = {str(o.id): o for o in logicals if str(o.organization_id) == organization_id}
    priors = {(str(v.logical_object_id), v.version): v for v in before if str(v.organization_id) == organization_id}
    counts = Counter(str(v.logical_object_id) for v in after)
    targets: dict[tuple[str, str, str], PortTarget | None] = {}
    gaps: set[str] = set()
    if len(after) > MAX_AUDIT_VERSIONS:
        gaps.add(
            "Port discovery configuration version limit reached; additional device relationships remain unresolved."
        )
    for version in sorted(after, key=lambda v: (str(v.logical_object_id), v.version))[:MAX_AUDIT_VERSIONS]:
        key = str(version.logical_object_id)
        logical = objects.get(key)
        definition = impact_definition(logical.scope, logical.object_type) if logical else None
        if (
            definition is None
            or definition.family is not ObjectFamily.DEVICE
            or str(version.organization_id) != organization_id
            or version.audit_id != audit_id
        ):
            continue
        if counts[key] != 1:
            gaps.add("Port discovery needs net-change resolution for a device changed multiple times in this audit.")
            continue
        if version.is_deleted:
            gaps.add(
                "Removed device port relationships require pre-change dependency evidence; "
                "no current port query was inferred."
            )
            continue
        if version.id is None:
            gaps.add("Port discovery lacks an immutable configuration identity.")
            continue
        if not set(version.changed_fields).intersection(_CONTAINERS):
            continue
        prior = priors.get((key, version.version - 1))
        if prior is not None and (prior.incarnation_id != version.incarnation_id or prior.is_deleted):
            gaps.add("Port discovery requires resolving the replaced device's identity.")
            continue
        comparable = prior if prior is not None and prior.id is not None else None
        identity = immutable_device_identity(version, comparable)
        if identity is None or identity[2] != "switch":
            gaps.add("Port discovery lacks a consistent immutable switch identity.")
            continue
        if comparable is None:
            gaps.add("Port discovery has no baseline; current concrete entries may omit removed ports.")
        site, mac, _ = identity
        ports: set[str] = set()
        for name in _CONTAINERS:
            if name not in version.changed_fields:
                continue
            old = comparable.configuration.get(name, {}) if comparable else {}
            new = version.configuration.get(name, {})
            if not isinstance(old, dict) or not isinstance(new, dict) or len(old) + len(new) > _MAX_KEYS:
                gaps.add("Port configuration is malformed or exceeds the bounded selector resolver.")
                continue
            for port in old.keys() | new.keys():
                if comparable and (port in old) == (port in new) and old.get(port) == new.get(port):
                    continue
                if not isinstance(port, str) or _PORT.fullmatch(port) is None:
                    gaps.add("Port ranges, aggregates and dynamic selectors require additional resolution.")
                    continue
                ports.add(port)
        for port in sorted(ports):
            handle = sha256(
                (
                    f"port-scope.v1:{organization_id}:{audit_id}:{comparable.id if comparable else None}:"
                    f"{version.id}:{site}:{mac}:{port}"
                ).encode()
            ).hexdigest()
            identity_key = (str(site), mac, port)
            if identity_key in targets:
                # Two logical objects asserting the same port are not corroboration.
                gaps.add("Multiple configuration objects assert a port identity; that port was excluded.")
                targets[identity_key] = None
            else:
                targets[identity_key] = PortTarget(
                    handle=handle,
                    device_handle=device_context_handle(organization_id, audit_id, site, mac),
                    site_id=site,
                    device_mac=mac,
                    port_id=port,
                    before_version_id=str(comparable.id) if comparable else None,
                    after_version_id=str(version.id),
                )
    resolved = tuple(t for key, t in sorted(targets.items()) if t is not None)
    if len(resolved) > MAX_PORT_TARGETS:
        gaps.add("The two-port discovery budget was reached; additional changed ports were not queried.")
    if resolved:
        gaps.add(
            "Port snapshots provide context only; managed-neighbor identity, "
            "historical transitions and impact remain unresolved."
        )
    return resolved[:MAX_PORT_TARGETS], tuple(sorted(gaps))
