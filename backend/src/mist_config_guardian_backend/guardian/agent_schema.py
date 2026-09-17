"""Guardian's versioned agent action schema, and the fingerprint a capability record is bound to.

One JSON object per turn: either one tool call or one report. This is the schema the setup-time probe asks a
provider to honor, and the schema the returned content is validated against, because some servers accept
``response_format`` and ignore it.

The agent loop owns the protocol and extends this schema. Every change to it bumps :data:`ACTION_SCHEMA_VERSION`,
which changes the fingerprint and therefore invalidates every stored capability record: a provider proved it can
produce the old shape, not the new one.
"""

import json
from hashlib import sha256
from typing import Any, Final

from jsonschema import Draft202012Validator, ValidationError

from mist_config_guardian_backend.guardian.contracts import BANDS, MAX_SUMMARY_CHARS, MAX_TEXT_CHARS

ACTION_SCHEMA_VERSION: Final = "1"
ACTION_SCHEMA_NAME: Final = "guardian_action"

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
_REPORT: Final[dict[str, Any]] = {
    "type": "object",
    "properties": {
        "action": {"const": "report"},
        "peak_impact": {"enum": list(BANDS)},
        "current_impact": {"enum": list(BANDS)},
        "confidence": {"enum": ["low", "medium"]},
        "summary": {"type": "string", "maxLength": MAX_SUMMARY_CHARS},
        "evidence": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["action", "peak_impact", "current_impact", "confidence", "summary", "evidence"],
    "additionalProperties": False,
}
ACTION_SCHEMA: Final[dict[str, Any]] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "GuardianAction",
    "oneOf": [_CALL, _REPORT],
}

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


def probe_request() -> str:
    """The user message of the probe, carrying the schema itself, for both the schema and object probes."""
    return PROBE_REQUEST.format(schema=json.dumps(ACTION_SCHEMA, separators=(",", ":")))


def validates_as_action(content: str) -> bool:
    """Whether returned content is one JSON action of the current schema. Prose and fenced JSON are not."""
    try:
        action = json.loads(content)
    except (TypeError, ValueError):
        return False
    try:
        _VALIDATOR.validate(action)
    except ValidationError:
        return False
    return True


def capability_fingerprint(*, base_url: str, model: str, schema_version: str = ACTION_SCHEMA_VERSION) -> str:
    """What a structured-output capability record is bound to: provider endpoint, model and schema version.

    No credential is part of this hash. A fingerprint is stored and shown, and a hash over key material would let
    a stored value be tested against guessed keys; the API key is also irrelevant to what a model can produce.
    """
    material = "\n".join((base_url.rstrip("/"), model, schema_version))
    return sha256(material.encode()).hexdigest()
