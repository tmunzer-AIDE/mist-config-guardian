"""Guardian's versioned agent action schema, and the fingerprint a capability record is bound to.

One JSON object per turn: either one tool call or one report. This is the schema the setup-time probe asks a
provider to honor, and the schema the returned content is validated against, because some servers accept
``response_format`` and ignore it.

The agent loop owns the protocol and extends this schema. Every change to it bumps :data:`ACTION_SCHEMA_VERSION`,
which changes the fingerprint and therefore invalidates every stored capability record: a provider proved it can
produce the old shape, not the new one.
"""

import json
import re
from collections.abc import Mapping
from hashlib import sha256
from typing import Any, Final

from jsonschema import Draft202012Validator, ValidationError
from jsonschema.exceptions import best_match

from mist_config_guardian_backend.guardian.contracts import BANDS, MAX_SUMMARY_CHARS, MAX_TEXT_CHARS

ACTION_SCHEMA_VERSION: Final = "2"
ACTION_SCHEMA_NAME: Final = "guardian_action"
# What one report may carry, so a provider cannot answer with an unbounded list.
MAX_CITATIONS: Final = 20
MAX_REPORT_ITEMS: Final = 20

_CALL: Final[dict[str, Any]] = {
    "type": "object",
    "properties": {
        "action": {"const": "call"},
        "tool": {"type": "string", "minLength": 1, "maxLength": 64},
        "arguments": {"type": "object"},
        "purpose": {"type": "string", "maxLength": MAX_TEXT_CHARS},
    },
    "required": ["action", "tool", "arguments"],
    "additionalProperties": False,
}
_EVIDENCE_IDS: Final[dict[str, Any]] = {
    "type": "array",
    "items": {"type": "string", "pattern": r"^E[1-9][0-9]{0,5}$"},
    "maxItems": MAX_CITATIONS,
}
_FINDING: Final[dict[str, Any]] = {
    "type": "object",
    "properties": {
        "text": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_CHARS},
        "impact": {"enum": list(BANDS)},
        "evidence": _EVIDENCE_IDS,
    },
    "required": ["text", "impact"],
    "additionalProperties": False,
}
_IMPACTED_DEVICE: Final[dict[str, Any]] = {
    "type": "object",
    "properties": {
        # A provider may write a MAC in any of the usual separators; Guardian normalizes it before it is stored.
        "mac": {"type": "string", "minLength": 1, "maxLength": 32},
        "impact": {"enum": list(BANDS)},
        "evidence": _EVIDENCE_IDS,
    },
    "required": ["mac", "impact"],
    "additionalProperties": False,
}
_REPORT: Final[dict[str, Any]] = {
    "type": "object",
    "properties": {
        "action": {"const": "report"},
        "peak_impact": {"enum": list(BANDS)},
        "current_impact": {"enum": list(BANDS)},
        "confidence": {"enum": ["low", "medium"]},
        "summary": {"type": "string", "maxLength": MAX_SUMMARY_CHARS},
        "evidence": _EVIDENCE_IDS,
        "findings": {"type": "array", "items": _FINDING, "maxItems": MAX_REPORT_ITEMS},
        "impacted_devices": {"type": "array", "items": _IMPACTED_DEVICE, "maxItems": MAX_REPORT_ITEMS},
        "gaps": {
            "type": "array",
            "items": {"type": "string", "maxLength": MAX_TEXT_CHARS},
            "maxItems": MAX_REPORT_ITEMS,
        },
    },
    "required": ["action", "peak_impact", "current_impact", "confidence", "summary", "evidence"],
    "additionalProperties": False,
}
ACTION_SCHEMA: Final[dict[str, Any]] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "GuardianAction",
    "oneOf": [_CALL, _REPORT],
}


def strict_subset(schema: Mapping[str, Any]) -> bool:
    """Whether a schema is inside the provider's strict subset, which a root combinator puts it outside of.

    Guardian's action is one call or one report, so its root is a ``oneOf``. Asking a provider for strict mode on
    such a schema is refused or silently downgraded, and a capable provider is then recorded as ``json_object``
    (controller ruling R35). The gate for the capability record is the returned content, never the flag.
    """
    return not any(key in schema for key in ("oneOf", "anyOf", "allOf", "not"))


ACTION_SCHEMA_STRICT: Final = strict_subset(ACTION_SCHEMA)

# What the probe asks for. It is a report an investigation would reject on its merits, which is the point: the
# probe tests the shape a provider can produce, never the judgement it would make.
PROBE_INSTRUCTION: Final = (
    "You answer with exactly one JSON object matching the Guardian action schema, and nothing else: "
    "no prose, no code fence, no explanation."
)
PROBE_REQUEST: Final = (
    "Guardian action schema:\n{schema}\n\n"
    'Answer with the report action: action "report", peak_impact "none", current_impact "none", '
    'confidence "low", summary "capability probe" and an empty evidence array.'
)

_VALIDATOR = Draft202012Validator(ACTION_SCHEMA)
_SAFE_LOCATION = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,40}$")


def probe_request() -> str:
    """The user message of the probe, carrying the schema itself, for both the schema and object probes."""
    return PROBE_REQUEST.format(schema=json.dumps(ACTION_SCHEMA, separators=(",", ":")))


def validates_as_action(content: str) -> bool:
    """Whether returned content is one JSON action of the current schema. Prose and fenced JSON are not."""
    try:
        action = json.loads(content)
    except (TypeError, ValueError):
        return False
    return action_error(action) is None


def action_error(action: object) -> str | None:
    """Why one parsed answer is not an action of this schema, safe to show, or ``None`` when it is one.

    The location comes from the answer's own keys, which are untrusted, so only plain identifiers and indexes are
    repeated back; anything else becomes ``?``.
    """
    error = best_match(_VALIDATOR.iter_errors(action))
    if error is None:
        return None
    return f"The answer is not one call or one report: it does not match the schema at {_location(error)}."


def _location(error: ValidationError) -> str:
    parts = [
        str(part) if isinstance(part, int) or _SAFE_LOCATION.fullmatch(str(part)) else "?"
        for part in error.absolute_path
    ]
    return ".".join(parts) or "the answer itself"


def capability_fingerprint(*, base_url: str, model: str, schema_version: str = ACTION_SCHEMA_VERSION) -> str:
    """What a structured-output capability record is bound to: provider endpoint, model and schema version.

    No credential is part of this hash. A fingerprint is stored and shown, and a hash over key material would let
    a stored value be tested against guessed keys; the API key is also irrelevant to what a model can produce.
    """
    material = "\n".join((base_url.rstrip("/"), model, schema_version))
    return sha256(material.encode()).hexdigest()
