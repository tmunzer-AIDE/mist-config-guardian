"""Mist SLE payload parsing tests."""

from mist_config_guardian_backend.integrations.mist_sle import extract_sle_value


def test_extract_sle_value_averages_valid_samples() -> None:
    payload = {
        "sle": {
            "samples": {
                "total": [100, None, 50, 0],
                "degraded": [10, None, 10, 0],
            }
        }
    }

    assert extract_sle_value(payload) == 85.0


def test_extract_sle_value_rejects_invalid_payload() -> None:
    assert extract_sle_value({"sle": {"samples": {"total": [], "degraded": []}}}) is None
    assert extract_sle_value("invalid") is None
