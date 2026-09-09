"""Mist SLE payload parsing tests."""

import pytest

from mist_config_guardian_backend.integrations.mist_sle import extract_sle_value


def test_extract_sle_value_preserves_the_mean_of_rates_used_by_existing_baselines() -> None:
    payload = {
        "sle": {
            "samples": {
                "total": [100, None, 50, 0],
                "degraded": [10, None, 10, 0],
            }
        }
    }

    assert extract_sle_value(payload) == 85


def test_extract_sle_value_rejects_invalid_payload() -> None:
    assert extract_sle_value({"sle": {"samples": {"total": [], "degraded": []}}}) is None
    with pytest.raises(ValueError, match="Missing SLE object"):
        extract_sle_value("invalid")


async def test_sle_requests_exact_24_hour_baseline_for_the_changed_device(httpx_mock):
    from datetime import UTC, datetime, timedelta  # noqa: PLC0415

    import httpx  # noqa: PLC0415

    from mist_config_guardian_backend.integrations.mist_sle import MistSleClient  # noqa: PLC0415
    from mist_config_guardian_backend.models.monitoring import DeviceType  # noqa: PLC0415
    from mist_config_guardian_backend.models.organization import MistCloudRegion  # noqa: PLC0415

    end = datetime(2026, 9, 9, 12, tzinfo=UTC)
    start = end - timedelta(hours=24)

    def respond(request):
        assert "/sle/ap/00000000-0000-0000-1000-aabbccddeeff/metric/" in request.url.path
        assert request.url.params["start"] == str(int(start.timestamp()))
        assert request.url.params["end"] == str(int(end.timestamp()))
        return httpx.Response(200, json={"sle": {"samples": {"total": [100], "degraded": [2]}}})

    httpx_mock.add_callback(respond, is_reusable=True)
    async with MistSleClient(token="read-token", region=MistCloudRegion.GLOBAL_01) as client:
        result = await client.capture(
            site_id="site-1", device_type=DeviceType.AP, device_mac="aa:bb:cc:dd:ee:ff", start=start, end=end
        )
    assert result.window_start == start
    assert result.window_end == end
    assert result.values["coverage"] == 98
    assert len(httpx_mock.get_requests()) == 7


async def test_scope_failure_preserves_http_status_without_disclosing_provider_error_body(httpx_mock):
    import httpx  # noqa: PLC0415

    from mist_config_guardian_backend.integrations.mist_sle import MistSleClient  # noqa: PLC0415
    from mist_config_guardian_backend.models.monitoring import DeviceType  # noqa: PLC0415
    from mist_config_guardian_backend.models.organization import MistCloudRegion  # noqa: PLC0415

    httpx_mock.add_callback(lambda _request: httpx.Response(404, json={"private": "do-not-return"}), is_reusable=True)
    async with MistSleClient(token="read-token", region=MistCloudRegion.GLOBAL_01) as client:
        result = await client.capture(site_id="site-1", device_type=DeviceType.GATEWAY, device_mac="aabbccddeeff")
    assert result.scope == "device"
    assert result.values == {}
    assert all("HTTP 404" in error for error in result.errors)
    assert "do-not-return" not in result.model_dump_json()


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"sle": {}},
        {"sle": {"samples": {"total": [1], "degraded": []}}},
        {"sle": {"samples": {"total": [1], "degraded": [None]}}},
        {"sle": {"samples": {"total": [1], "degraded": [2]}}},
        {"sle": {"samples": {"total": [True], "degraded": [0]}}},
        {"sle": {"samples": {"total": [float("inf")], "degraded": [0]}}},
    ],
)
def test_malformed_sle_is_not_classified_as_a_quiet_site(payload):
    with pytest.raises(ValueError, match="SLE"):
        extract_sle_value(payload)


@pytest.mark.parametrize(
    "buckets", [([], []), ([0, 0], [0, 0]), ([None, None], [None, None]), ([0, None], [None, None])]
)
async def test_quiet_site_response_is_no_data_rather_than_a_collection_error(buckets, httpx_mock):
    import httpx  # noqa: PLC0415

    from mist_config_guardian_backend.integrations.mist_sle import MistSleClient  # noqa: PLC0415
    from mist_config_guardian_backend.models.monitoring import DeviceType  # noqa: PLC0415
    from mist_config_guardian_backend.models.organization import MistCloudRegion  # noqa: PLC0415
    from mist_config_guardian_backend.services.impact_analysis import assess_impact  # noqa: PLC0415

    httpx_mock.add_callback(
        lambda _request: httpx.Response(
            200,
            json={
                "sle": {
                    "samples": {
                        "total": buckets[0],
                        "degraded": buckets[1],
                    }
                }
            },
        ),
        is_reusable=True,
    )
    async with MistSleClient(token="read-token", region=MistCloudRegion.GLOBAL_01) as client:
        observation = await client.capture(site_id="site-1", device_type=DeviceType.AP, device_mac="aabbccddeeff")
    assert observation.errors == []
    assert observation.values == {}  # No fabricated 100% success rates.
    assert set(observation.no_data) == {
        "time-to-connect",
        "successful-connect",
        "throughput",
        "roaming",
        "capacity",
        "coverage",
        "ap-health",
    }
    # Successful collection without measurements still cannot establish health.
    assessment = assess_impact(observation, observation, [])
    assert assessment.severity == "info"
    assert assessment.metric_deltas == {}


async def test_malformed_200_response_remains_a_collection_error(httpx_mock):
    import httpx  # noqa: PLC0415

    from mist_config_guardian_backend.integrations.mist_sle import MistSleClient  # noqa: PLC0415
    from mist_config_guardian_backend.models.monitoring import DeviceType  # noqa: PLC0415
    from mist_config_guardian_backend.models.organization import MistCloudRegion  # noqa: PLC0415

    httpx_mock.add_callback(lambda _request: httpx.Response(200, json={"unexpected": "body"}), is_reusable=True)
    async with MistSleClient(token="read-token", region=MistCloudRegion.GLOBAL_01) as client:
        observation = await client.capture(site_id="site-1", device_type=DeviceType.GATEWAY)
    assert observation.no_data == []
    assert observation.values == {}
    assert len(observation.errors) == 2
    assert all("invalid SLE response" in error for error in observation.errors)
