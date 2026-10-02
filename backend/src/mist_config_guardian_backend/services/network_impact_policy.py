"""Conservative exclusions from network-service validation, not configuration history.

Unknown types and fields remain eligible. Location reporting and administration
can change without changing packet forwarding, radio service or client access.
"""

from collections.abc import Sequence

from mist_config_guardian_backend.models.webhook import ChangedObjectRef
from mist_config_guardian_backend.webhooks.audits import resolve_audit_target

EXCLUDED_OBJECTS: dict[str, str] = {
    "assetfilters": "Asset filters categorize BLE assets; they do not configure network service.",
    "assets": "Asset records describe tracked BLE assets; they do not configure network service.",
    "zones": "Location zones define reporting areas; they do not configure network service.",
    "rssizones": "RSSI zones define location reporting areas; they do not configure network service.",
    "alarmtemplates": "Alarm templates control notifications; they do not configure network service.",
    "webhooks": "Webhooks control event delivery; they do not configure network service.",
    "ssos": "Administrator SSO settings control portal access; they do not configure client network access.",
    "ssoroles": "Administrator SSO roles control portal permissions; they do not configure client network access.",
}

# Names of policy objects can be references, and site time zones/countries can
# affect schedules/regulatory RF settings. Never apply a global metadata list.
METADATA_FIELDS: dict[str, frozenset[str]] = {
    "devices": frozenset({"name", "notes"}),
    "sites": frozenset({"name", "notes", "address", "latlng"}),
    "data": frozenset({"name"}),
}


def object_exclusion(ref: ChangedObjectRef) -> str | None:
    if ref.object_type in EXCLUDED_OBJECTS:
        return EXCLUDED_OBJECTS[ref.object_type]
    if (
        ref.event == "updated"
        and ref.changed_fields
        and set(ref.changed_fields) <= METADATA_FIELDS.get(ref.object_type, frozenset())
    ):
        return "Only descriptive metadata changed; network settings are unchanged."
    return None


def exclusion_reason(objects: Sequence[ChangedObjectRef], message: str | None = None) -> str | None:
    """Exclude only when every changed object is demonstrably outside network service."""
    if objects:
        reasons = [object_exclusion(ref) for ref in objects]
        if all(reasons):
            return " ".join(dict.fromkeys(reason for reason in reasons if reason))
        return None
    # Older/unlinked audit records can still be classified by a resolved type.
    # An unrecognized message is never sufficient grounds for excluding impact.
    target = resolve_audit_target({"message": message}) if message else None
    return EXCLUDED_OBJECTS.get(target.definition.key) if target else None


def confirmed_changes() -> dict[str, object]:
    """Filter before pagination/counting: a receipt alone is not a captured difference."""
    return {"changed_objects.0": {"$exists": True}}


def excluded_expression() -> dict[str, object]:
    """Mongo equivalent of object_exclusion for accurate counts and severity filters."""
    refs = {"$ifNull": ["$changed_objects", []]}
    metadata = [
        {
            "$and": [
                {"$eq": ["$$ref.object_type", kind]},
                {"$eq": ["$$ref.event", "updated"]},
                {"$gt": [{"$size": {"$ifNull": ["$$ref.changed_fields", []]}}, 0]},
                {"$setIsSubset": [{"$ifNull": ["$$ref.changed_fields", []]}, sorted(fields)]},
            ]
        }
        for kind, fields in METADATA_FIELDS.items()
    ]
    return {
        "$and": [
            {"$gt": [{"$size": refs}, 0]},
            {
                "$allElementsTrue": [
                    {
                        "$map": {
                            "input": refs,
                            "as": "ref",
                            "in": {
                                "$or": [{"$in": ["$$ref.object_type", sorted(EXCLUDED_OBJECTS)]}, *metadata],
                            },
                        }
                    }
                ]
            },
        ]
    }


def eligible_query() -> dict[str, object]:
    return {"$expr": {"$not": [excluded_expression()]}}
