"""UUID reference discovery keeps restore dependencies narrowly scoped."""

import pytest

from mist_config_guardian_backend.models.snapshot import ObjectReference
from mist_config_guardian_backend.snapshots.references import extract_uuid_references, is_restore_reference


@pytest.mark.parametrize(
    ("field_path", "expected"),
    [
        ("tag_uuid", False),
        ("site.tag_uuid", False),
        ("tag_uuid.0", False),
        ("device_tag_uuid", True),
        ("applies.site_ids.0", True),
    ],
)
def test_restore_reference_classification(field_path: str, expected) -> None:
    reference = ObjectReference(target_mist_id="target", field_path=field_path)

    assert is_restore_reference(reference) is expected


def test_inventory_tag_uuid_is_not_a_restore_dependency() -> None:
    map_id = "3e73277d-6c82-4fcd-aced-eb56fc95a957"

    references = extract_uuid_references(
        {
            "id": "00000000-0000-0000-1000-5c5b350e0001",
            "org_id": "8aa21779-1178-4357-b3e0-42c02b93b870",
            "site_id": "d6fb4f96-3ba4-4cf5-8af2-a8d7b85087ac",
            "tag_uuid": "8aa21779-1178-4357-b3e0-42c02b93b870",
            "inventory": {
                "tag_uuid": ["aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"],
            },
            "map_id": map_id,
        }
    )

    assert [(reference.field_path, reference.target_mist_id) for reference in references] == [("map_id", map_id)]
