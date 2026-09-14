"""Generic UUID reference discovery."""

import re
from collections.abc import Mapping, Sequence

from mist_config_guardian_backend.models.snapshot import ObjectReference

_UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_NON_REFERENCE_FIELDS = {"id", "org_id", "site_id", "tag_uuid"}


def is_restore_reference(reference: ObjectReference) -> bool:
    """Return whether a stored UUID reference participates in restore behavior."""
    return "tag_uuid" not in reference.field_path.split(".")


def extract_uuid_references(configuration: Mapping[str, object]) -> list[ObjectReference]:
    """Find UUID values that may identify restorable configuration objects.

    ``tag_uuid`` identifies Mist inventory metadata, which is outside the
    restorable object registry. Treating it as a configuration dependency can
    accidentally match another object's UUID and expand an unrelated restore.
    """
    references: list[ObjectReference] = []

    def visit(value: object, path: str) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                key_name = str(key)
                child_path = f"{path}.{key_name}" if path else key_name
                if key_name not in _NON_REFERENCE_FIELDS:
                    visit(child, child_path)
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for index, child in enumerate(value):
                visit(child, f"{path}.{index}")
        elif isinstance(value, str) and _UUID_PATTERN.fullmatch(value):
            references.append(ObjectReference(target_mist_id=value, field_path=path))

    visit(configuration, "")
    return references
