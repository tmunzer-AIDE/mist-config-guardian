"""Pinned sparse OAS library. No network, arbitrary paths, cursors or recursive fetches."""

import json
from hashlib import sha256
from importlib.resources import files

from mist_config_guardian_backend.impact.contracts import AttributeDocumentation, DocumentationTarget, WlanRemovalPlan
from mist_config_guardian_backend.impact.limits import MAX_DOCUMENTATION_TARGETS
from mist_config_guardian_backend.snapshots.registry import ObjectFamily, impact_definition

CORPUS_HASH = "2300bed6570146c3d69a3760f1b3ff70c5d98e58d6ae124dc3a2928646513c56"
_ALLOWED = frozenset({"switch.bgp_config", "switch.ospf_config", "wlan.ssid", "wlan.schedule"})
_MAX_CORPUS_BYTES = 16_000


def documentation_plan(plan: WlanRemovalPlan) -> WlanRemovalPlan:
    selected = set()
    for change in plan.change_context.changes if plan.change_context else ():
        definition = impact_definition(change.scope, change.object_type)
        if definition is None:
            continue
        prefix = (
            "wlan"
            if definition.family is ObjectFamily.WLAN
            else "switch"
            if (definition.family is ObjectFamily.DEVICE and change.device_type == "switch")
            else ""
        )
        for attribute in change.attributes:
            key = f"{prefix}.{attribute.attribute}"
            if key in _ALLOWED:
                selected.add(key)
    targets = tuple(
        DocumentationTarget.model_validate(
            {
                "handle": sha256(
                    f"mist-docs.v1:{plan.organization_id}:{plan.audit_id}:{CORPUS_HASH}:{key}".encode()
                ).hexdigest(),
                "document_id": key,
            }
        )
        for key in sorted(selected)[:MAX_DOCUMENTATION_TARGETS]
    )
    gaps = (
        (*plan.gaps, "Documentation target limit reached; some changed attributes lack descriptions.")
        if len(selected) > MAX_DOCUMENTATION_TARGETS
        else plan.gaps
    )
    return plan.model_copy(update={"documentation_targets": targets, "gaps": gaps})


def describe_attribute(document_id: str) -> AttributeDocumentation:
    if document_id not in _ALLOWED:
        msg = "Attribute is not present in the pinned corpus"
        raise ValueError(msg)
    raw = files("mist_config_guardian_backend.impact").joinpath("knowledge_assets", "attributes.json").read_bytes()
    if len(raw) > _MAX_CORPUS_BYTES or sha256(raw).hexdigest() != CORPUS_HASH:
        msg = "Pinned documentation corpus failed integrity validation"
        raise ValueError(msg)
    corpus = json.loads(raw)
    row = AttributeDocumentation.model_validate(
        {
            **corpus["entries"][document_id],
            "corpus_hash": CORPUS_HASH,
            "source_hash": corpus["source_hash"],
            "source_version": corpus["version"],
        }
    )
    if row.id != document_id:
        raise ValueError
    return row
