"""Loader and validators for the frozen Guardian external contracts.

``docs/design/guardian-verification.yaml`` records the external facts the Guardian design depends on. Each decision
names its sources, when it was observed, its result and the SHA-256 of every fixture it was decided from. Later
tasks read the decisions, the DNS attribute semantics and the MCP evidence-kind allowlist through this module
rather than re-deriving them.
"""

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from mist_config_guardian_backend.snapshots.registry import get_definition

REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFICATION_PATH = REPO_ROOT / "docs" / "design" / "guardian-verification.yaml"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "guardian"
DNS_SEMANTICS_FIXTURE = "dns_attribute_semantics.json"
MCP_ALLOWLIST_FIXTURE = "mcp_allowlist.json"

# Every decision the design leaves to verification, with the results it may record.
RESULTS: Mapping[str, frozenset[str]] = {
    "device_event_ordering": frozenset({"sequence_field_available", "same_second_ambiguous"}),
    "sw_configured_emission": frozenset({"emitted", "not_emitted", "unknown"}),
    "dns_attribute_semantics": frozenset({"recorded"}),
    "mcp_evidence_kind_allowlist": frozenset({"frozen"}),
    "structured_output_capability": frozenset({"json_schema", "json_object", "unsupported", "inconclusive"}),
}
# A result that observed nothing may stand without a fixture, but it must say why.
UNOBSERVED_RESULTS = frozenset({"inconclusive"})
DECISION_FIELDS = ("id", "question", "result", "source", "observed_at", "fixtures", "notes")
# A setting the schema documents as both the device's own resolver and the DHCP default for its clients is
# management_and_client_resolution; the dns plug-in emits the union of both obligation sets for it.
DNS_SEMANTICS = frozenset(
    {"management_resolution", "client_resolution", "management_and_client_resolution", "unverified"}
)
DNS_DEVICE_TYPES = frozenset({"ap", "switch", "gateway", "mxedge"})
EVIDENCE_KINDS = frozenset({"service_health", "configuration", "reference"})


class ContractError(ValueError):
    """A frozen contract was missing, malformed or did not cover the request."""


class UnknownDnsAttributeError(ContractError):
    """No DNS semantics are recorded for an object type and attribute."""


class ToolNotAllowlistedError(ContractError):
    """An MCP tool, or its discriminating argument, is absent from the frozen allowlist."""


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def schema_sha256(schema: object) -> str:
    """Hash an MCP input schema serialized as sorted-key, compact UTF-8 JSON."""
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def load_verification(path: Path = VERIFICATION_PATH) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def decision(document: Mapping[str, Any], decision_id: str) -> dict[str, Any]:
    matches = [item for item in document.get("decisions") or [] if item.get("id") == decision_id]
    if len(matches) != 1:
        msg = f"Decision {decision_id!r} is not recorded exactly once"
        raise ContractError(msg)
    return matches[0]


def verification_errors(document: Mapping[str, Any]) -> list[str]:
    """Every reason the record cannot gate later tasks; empty when it can."""
    decisions = document.get("decisions")
    if not isinstance(decisions, list) or not all(isinstance(item, dict) for item in decisions):
        return ["decisions must be a list of mappings"]
    ids = [item.get("id") for item in decisions]
    errors = [f"decision {name!r} is missing" for name in RESULTS if name not in ids]
    errors += [f"decision {name!r} is recorded more than once" for name in RESULTS if ids.count(name) > 1]
    errors += [f"decision {name!r} is not a known decision" for name in ids if name not in RESULTS]
    for item in decisions:
        errors += _decision_errors(item)
    return errors


def _decision_errors(item: Mapping[str, Any]) -> list[str]:
    name = item.get("id")
    errors = [f"{name}: {field} is missing" for field in DECISION_FIELDS if item.get(field) in (None, "")]
    if name not in RESULTS or errors:
        return errors
    result = item["result"]
    if result not in RESULTS[name]:
        errors.append(f"{name}: result {result!r} is not one of {sorted(RESULTS[name])}")
    if not isinstance(item["source"], list) or not item["source"]:
        errors.append(f"{name}: source must list at least one source")
    try:
        if datetime.fromisoformat(str(item["observed_at"])).tzinfo is None:
            errors.append(f"{name}: observed_at must carry a timezone")
    except ValueError:
        errors.append(f"{name}: observed_at is not an ISO 8601 timestamp")
    fixtures = item["fixtures"]
    if not isinstance(fixtures, list):
        return [*errors, f"{name}: fixtures must be a list"]
    if not fixtures and result not in UNOBSERVED_RESULTS:
        errors.append(f"{name}: result {result!r} must cite at least one fixture")
    if result in UNOBSERVED_RESULTS and not item.get("reason"):
        errors.append(f"{name}: result {result!r} must give a reason")
    return errors + fixture_errors(name, fixtures)


def fixture_errors(owner: str, fixtures: list[Any]) -> list[str]:
    errors = []
    for fixture in fixtures:
        path = fixture.get("path") if isinstance(fixture, dict) else None
        recorded = fixture.get("sha256") if isinstance(fixture, dict) else None
        if not path or not recorded:
            errors.append(f"{owner}: every fixture needs a path and a sha256")
            continue
        target = REPO_ROOT / path
        if not target.is_file():
            errors.append(f"{owner}: fixture {path} does not exist")
        elif (actual := sha256_file(target)) != recorded:
            errors.append(f"{owner}: fixture {path} sha256 drifted (recorded {recorded}, actual {actual})")
    return errors


def dns_semantics_errors(table: Mapping[str, Any]) -> list[str]:
    """Every reason the DNS semantics table cannot be used; empty when it can."""
    errors = []
    claimed: set[tuple[str, str | None, tuple[str, ...]]] = set()
    for row in table.get("mappings") or []:
        name = f"{row.get('object_type')} {row.get('variant')} {row.get('attribute')}"
        errors += [f"{name}: {error}" for error in _dns_row_errors(row)]
        for path in row.get("paths") or []:
            identity = (str(row.get("object_type")), row.get("variant"), tuple(path))
            if path[:1] != [row.get("attribute")]:
                errors.append(f"{name}: path {path} does not start with the attribute")
            if identity in claimed:
                errors.append(f"{name}: path {path} carries more than one semantics")
            claimed.add(identity)
    return errors


def _dns_row_errors(row: Mapping[str, Any]) -> list[str]:
    errors = []
    scope, _, key = str(row.get("object_type")).partition(":")
    if get_definition(scope, key) is None:
        errors.append("object type is not in the snapshot registry")
    if (row.get("variant") is not None) != (row.get("object_type") == "site:devices"):
        errors.append("variant is required for site:devices and only there")
    semantics = row.get("semantics")
    if semantics not in DNS_SEMANTICS:
        errors.append(f"semantics {semantics!r} is not one of {sorted(DNS_SEMANTICS)}")
    device_types = row.get("device_types")
    if not isinstance(device_types, list) or (semantics == "unverified") != (not device_types):
        errors.append("device_types must be empty exactly when semantics are unverified")
    elif not set(device_types) <= DNS_DEVICE_TYPES:
        errors.append(f"device_types {device_types} are not all known")
    paths = row.get("paths") or []
    evidence = row.get("evidence") or []
    if not row.get("reason") or not paths or len(evidence) < len(paths):
        errors.append("every path needs cited evidence and the row needs a reason")
    if not all(str(item.get("pointer")).startswith("#/components/schemas/") for item in evidence):
        errors.append("evidence must cite schema pointers")
    return errors


def dns_mappings(
    object_type: str,
    attribute: str,
    *,
    variant: str | None = None,
    semantics: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Recorded DNS semantics for one ``<scope>:<registry key>`` attribute; unknown attributes are rejected.

    ``variant`` names the device type for ``site:devices``, whose schema depends on it.
    """
    table = semantics if semantics is not None else load_fixture(DNS_SEMANTICS_FIXTURE)
    rows = [
        row
        for row in table["mappings"]
        if row["object_type"] == object_type and row["attribute"] == attribute and row["variant"] == variant
    ]
    if not rows:
        msg = f"No DNS semantics are recorded for {object_type} {attribute!r} (variant {variant!r})"
        raise UnknownDnsAttributeError(msg)
    return rows


def evidence_kind(tool: str, arguments: Mapping[str, object], *, allowlist: Mapping[str, Any] | None = None) -> str:
    """The server-owned evidence kind of one MCP call; a tool or discriminator outside the allowlist is rejected."""
    table = allowlist if allowlist is not None else load_fixture(MCP_ALLOWLIST_FIXTURE)
    entry = table["tools"].get(tool)
    if entry is None:
        msg = f"MCP tool {tool!r} is not allowlisted"
        raise ToolNotAllowlistedError(msg)
    value = arguments.get(entry["discriminator"])
    kind = entry["kinds"].get(value) if isinstance(value, str) else None
    if kind is None:
        msg = f"MCP tool {tool!r} is not allowlisted for {entry['discriminator']}={value!r}"
        raise ToolNotAllowlistedError(msg)
    return kind
