"""Snapshot API redaction tests."""

from mist_config_guardian_backend.snapshots.secrets import redact_configuration


def test_redact_configuration_hides_nested_encrypted_values() -> None:
    configuration: dict[str, object] = {
        "name": "Corporate",
        "radius": {
            "password": {"$encrypted": "v1:ciphertext"},
            "servers": [{"secret": {"$encrypted": "v1:other"}}],
        },
    }

    assert redact_configuration(configuration) == {
        "name": "Corporate",
        "radius": {
            "password": "********",
            "servers": [{"secret": "********"}],
        },
    }
