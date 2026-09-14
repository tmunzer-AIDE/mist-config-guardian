"""Meaningful configuration diffs for any registered object, not a rule catalogue."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING
from uuid import UUID

from mist_config_guardian_backend.impact.limits import MAX_AUDIT_VERSIONS
from mist_config_guardian_backend.impact.mcp_scope import IGNORED, has_omissions, sanitize

if TYPE_CHECKING:
    from collections.abc import Sequence

    from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectVersion

MAX_CONTEXT_OBJECTS = 8
MAX_ATTRIBUTE_BYTES = 4000
MAX_CONTEXT_BYTES = 16_000


def configuration_context(  # noqa: C901, PLR0912 - identity and bounded per-attribute snapshot projection
    organization_id: str,
    logicals: Sequence[LogicalObject],
    before: Sequence[ObjectVersion],
    after: Sequence[ObjectVersion],
) -> dict:
    objects = {str(o.id): o for o in logicals if str(o.organization_id) == organization_id}
    priors = {(str(v.logical_object_id), v.version): v for v in before if str(v.organization_id) == organization_id}
    changes, sites, devices, gaps = [], set(), [], []
    candidates = [v for v in after if v.is_deleted or {f.split(".")[0] for f in v.changed_fields} - IGNORED]
    for version in candidates[:MAX_AUDIT_VERSIONS]:
        if str(version.organization_id) != organization_id:
            continue
        logical = objects.get(str(version.logical_object_id))
        if not logical:
            continue
        prior = priors.get((str(version.logical_object_id), version.version - 1))
        attributes = sorted({f.split(".")[0] for f in version.changed_fields} - IGNORED)
        previous = prior.configuration if prior and prior.incarnation_id == version.incarnation_id else {}
        current = version.configuration if not version.is_deleted else {}
        if "*" in attributes or version.is_deleted:
            attributes = sorted((set(previous) | set(current)) - IGNORED) or ["configuration"]
        if not attributes:
            continue
        fields = []
        for attribute in attributes[:12]:
            raw = {attribute: {"before": previous.get(attribute), "after": current.get(attribute)}}
            if has_omissions(raw):
                gaps.append("Some changed values were abbreviated to fit context bounds.")
            row = sanitize(raw)
            if len(json.dumps(row).encode()) > MAX_ATTRIBUTE_BYTES:
                row = {attribute: {"omitted": "Value exceeds bounded diff size; use MCP configuration lookup."}}
                gaps.append("Some changed configuration values were omitted for size.")
            fields.append(row)
        site = current.get("site_id", previous.get("site_id"))
        if site is None and logical.scope == "site":
            site = str(logical.site_mist_id) if logical.site_mist_id else None
        try:
            site = str(UUID(site)) if site else None
        except ValueError:
            site = None
        if site:
            sites.add(site)
        identity = {"site_id": site, "device_mac": None, "device_type": None}
        mac = current.get("mac", previous.get("mac"))
        if site and re.fullmatch(r"[0-9a-fA-F]{12}", str(mac or "")):
            identity.update(device_mac=mac.lower(), device_type=current.get("type", previous.get("type")))
            devices.append({"site_id": site, "device_mac": mac.lower()})
        changes.append(
            {
                "object_type": logical.object_type,
                "scope": logical.scope,
                "resource_id": version.configuration.get("id"),
                **identity,
                "operation": "removed" if version.is_deleted else "changed" if prior else "created_or_baseline_missing",
                "baseline_available": bool(previous),
                "effective_change": "assume_effective",
                "attributes": fields,
                "omitted_attributes": max(0, len(attributes) - 12),
            }
        )
        if len(changes) == MAX_CONTEXT_OBJECTS:
            gaps.append("Configuration context is limited to eight objects; additional changes may be omitted.")
            break
    context = {"changes": changes, "sites": sorted(sites), "devices": devices, "gaps": list(dict.fromkeys(gaps))}
    if len(json.dumps(context).encode()) > MAX_CONTEXT_BYTES:
        for change in changes:
            change["attributes"] = [
                {next(iter(row)): "[values omitted for context size]"} for row in change["attributes"]
            ]
        context["gaps"].append("Configuration values exceed the context bound; retrieve details through MCP.")
    return context
