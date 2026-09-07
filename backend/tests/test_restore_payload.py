"""Restore payload preparation tests."""

from mist_config_guardian_backend.services.restore_executor import prepare_restore_payload


def test_prepare_restore_payload_removes_server_fields_and_rewrites_ids() -> None:
    old_id = "11111111-2222-3333-4444-555555555555"
    new_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    configuration: dict[str, object] = {
        "id": "server-id",
        "name": "Corporate",
        "network_id": old_id,
        "rules": [{"target_ids": [old_id, "unchanged"]}],
    }

    payload = prepare_restore_payload(
        configuration,
        excluded_fields=frozenset({"id"}),
        id_map={old_id: new_id},
    )

    assert payload == {
        "name": "Corporate",
        "network_id": new_id,
        "rules": [{"target_ids": [new_id, "unchanged"]}],
    }
