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


def test_redaction_masks_a_marker_with_sibling_keys() -> None:
    """A protected value stays masked even when the marker gains siblings.

    Keying redaction off an exact single-key match would return ciphertext
    verbatim as soon as anything was stored next to the marker.
    """
    redacted = redact_configuration(
        {
            "psk": {"$encrypted": "v1:ciphertext", "$fingerprint": "abc123"},
            "nested": {"inner": {"$encrypted": "v1:other", "$fingerprint": "def456"}},
            "list": [{"$encrypted": "v1:third", "$fingerprint": "ghi789"}],
        }
    )

    assert redacted == {
        "psk": "********",
        "nested": {"inner": "********"},
        "list": ["********"],
    }
    assert "ciphertext" not in str(redacted)
    assert "abc123" not in str(redacted)
