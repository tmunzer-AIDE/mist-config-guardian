"""Snapshot registry and reference tests."""

import pytest

from mist_config_guardian_backend.snapshots.references import extract_uuid_references
from mist_config_guardian_backend.snapshots.registry import (
    READ_ONLY_URL_FIELDS,
    SITE_OBJECTS,
    get_definition,
    object_name,
)


def test_site_definition_requires_site_id() -> None:
    with pytest.raises(ValueError, match="site_id is required"):
        SITE_OBJECTS[0].path(org_id="org-1")


def test_object_name_uses_first_available_name_field() -> None:
    wlan = next(definition for definition in SITE_OBJECTS if definition.key == "wlans")

    assert object_name({"id": "object-id", "ssid": "Corporate"}, wlan) == "Corporate"


def test_reference_extraction_ignores_identity_fields() -> None:
    referenced_uuid = "11111111-2222-3333-4444-555555555555"
    own_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    references = extract_uuid_references(
        {
            "id": own_uuid,
            "site_id": own_uuid,
            "network_id": referenced_uuid,
            "rules": [{"wlan_id": referenced_uuid}],
        }
    )

    assert [(reference.target_mist_id, reference.field_path) for reference in references] == [
        (referenced_uuid, "network_id"),
        (referenced_uuid, "rules.0.wlan_id"),
    ]


def test_singletons_and_devices_have_fail_closed_restore_capabilities() -> None:
    org = get_definition("org", "data")
    site = get_definition("site", "info")
    devices = get_definition("site", "devices")

    assert org is not None
    assert org.supports_restore_action("update")
    assert not org.supports_restore_action("delete")
    assert site is not None
    assert not site.supports_restore_action("create")
    assert devices is not None
    assert not devices.supports_restore_action("delete")


def test_mist_image_urls_are_neither_configuration_nor_restore_payload_fields() -> None:
    devices = get_definition("site", "devices")

    assert devices is not None
    image_fields = {"image1_url", "image2_url", "image3_url", "thumbnail_url"}
    assert image_fields <= devices.ignored_fields
    assert image_fields <= devices.restore_excluded_fields


@pytest.mark.parametrize(
    ("scope", "object_type", "fields"),
    [(scope, object_type, fields) for (scope, object_type), fields in READ_ONLY_URL_FIELDS.items()],
)
def test_mist_read_only_urls_are_neither_configuration_nor_restore_payload_fields(
    scope: str,
    object_type: str,
    fields: frozenset[str],
) -> None:
    definition = get_definition(scope, object_type)

    assert definition is not None
    assert fields <= definition.ignored_fields
    assert fields <= definition.restore_excluded_fields


def test_writable_urls_remain_part_of_configuration_and_restore_payloads() -> None:
    org_webhook = get_definition("org", "webhooks")
    site_webhook = get_definition("site", "webhooks")
    virtual_beacon = get_definition("site", "vbeacons")

    assert org_webhook is not None
    assert site_webhook is not None
    assert virtual_beacon is not None
    for definition in (org_webhook, site_webhook, virtual_beacon):
        assert "url" not in definition.ignored_fields
        assert "url" not in definition.restore_excluded_fields
