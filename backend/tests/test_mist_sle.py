"""Mist SLE payload parsing tests."""

import pytest

from mist_config_guardian_backend.integrations.mist_sle import extract_sle_value

AP_METRICS = ["time-to-connect", "successful-connect", "throughput", "roaming", "capacity", "coverage", "ap-health"]


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
        if request.url.path.endswith("/metrics"):
            return httpx.Response(200, json={"supported": AP_METRICS, "enabled": AP_METRICS})
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
    assert len(httpx_mock.get_requests()) == 8


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
        lambda request: (
            httpx.Response(200, json={"supported": AP_METRICS, "enabled": AP_METRICS})
            if request.url.path.endswith("/metrics")
            else httpx.Response(
                200,
                json={
                    "sle": {
                        "samples": {
                            "total": buckets[0],
                            "degraded": buckets[1],
                        }
                    }
                },
            )
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

    httpx_mock.add_callback(
        lambda request: (
            httpx.Response(
                200,
                json={
                    "supported": ["gateway-health", "wan-link-health"],
                    "enabled": ["gateway-health", "wan-link-health"],
                },
            )
            if request.url.path.endswith("/metrics")
            else httpx.Response(200, json={"unexpected": "body"})
        ),
        is_reusable=True,
    )
    async with MistSleClient(token="read-token", region=MistCloudRegion.GLOBAL_01) as client:
        observation = await client.capture(site_id="site-1", device_type=DeviceType.GATEWAY)
    assert observation.no_data == []
    assert observation.values == {}
    assert len(observation.errors) == 2
    assert all("invalid SLE response" in error for error in observation.errors)


@pytest.mark.parametrize("device_mac", [None, "aabbccddeeff"])
@pytest.mark.parametrize("underscore", [False, True])
@pytest.mark.parametrize("supports_new", [False, True])
async def test_switch_discovers_enabled_metrics_before_requesting_summaries(
    httpx_mock, device_mac, underscore, supports_new
):
    import httpx  # noqa: PLC0415

    from mist_config_guardian_backend.integrations.mist_sle import MistSleClient  # noqa: PLC0415
    from mist_config_guardian_backend.models.monitoring import DeviceType  # noqa: PLC0415
    from mist_config_guardian_backend.models.organization import MistCloudRegion  # noqa: PLC0415
    from mist_config_guardian_backend.services.impact_analysis import assess_impact  # noqa: PLC0415

    metrics = ["switch-throughput", "switch-health", "switch-stc"]
    spellings = [metric.replace("-", "_") if underscore else metric for metric in metrics]
    root = "/api/v1/sites/site-1/sle/" + (
        "switch/00000000-0000-0000-1000-aabbccddeeff" if device_mac else "site/site-1"
    )

    def respond(request):
        if request.url.path == f"{root}/metrics":
            supported = [*spellings, "switch-stc-new"] if supports_new else spellings
            return httpx.Response(200, json={"supported": supported, "enabled": spellings})
        assert request.url.path in [f"{root}/metric/{metric}/summary-trend" for metric in spellings]
        return httpx.Response(200, json={"sle": {"samples": {"total": [100], "degraded": [2]}}})

    httpx_mock.add_callback(respond, is_reusable=True)
    async with MistSleClient(token="read-token", region=MistCloudRegion.GLOBAL_02) as client:
        baseline = await client.capture(site_id="site-1", device_type=DeviceType.SWITCH, device_mac=device_mac)
        latest = await client.capture(site_id="site-1", device_type=DeviceType.SWITCH, device_mac=device_mac)
    assert baseline.errors == latest.errors == []
    assert baseline.values == dict.fromkeys(metrics, 98)
    assert baseline.no_data == []
    assert assess_impact(baseline, latest, []).severity == "none"
    assert len(httpx_mock.get_requests()) == 8


async def test_advertised_stc_new_is_collected_and_404_is_still_an_error(httpx_mock):
    import httpx  # noqa: PLC0415

    from mist_config_guardian_backend.integrations.mist_sle import MistSleClient  # noqa: PLC0415
    from mist_config_guardian_backend.models.monitoring import DeviceType  # noqa: PLC0415
    from mist_config_guardian_backend.models.organization import MistCloudRegion  # noqa: PLC0415

    def respond(request):
        if request.url.path.endswith("/metrics"):
            return httpx.Response(200, json={"supported": ["switch-stc-new"], "enabled": ["switch-stc-new"]})
        assert request.url.path.endswith("/metric/switch-stc-new/summary-trend")
        return httpx.Response(404, json={"secret": "must-not-be-disclosed"})

    httpx_mock.add_callback(respond, is_reusable=True)
    async with MistSleClient(token="read-token", region=MistCloudRegion.GLOBAL_02) as client:
        result = await client.capture(site_id="site-1", device_type=DeviceType.SWITCH, device_mac="aabbccddeeff")
    assert len(result.errors) == 1
    assert result.errors[0].startswith("switch-stc-new: HTTP 404 from the SLE endpoint")
    assert "/sle/switch/00000000-0000-0000-1000-aabbccddeeff/metric/switch-stc-new/summary-trend" in result.errors[0]
    assert result.no_data == []
    assert "must-not-be-disclosed" not in result.model_dump_json()


@pytest.mark.parametrize(
    ("status", "payload", "message"),
    [
        (404, {}, "HTTP 404"),
        (403, {"private": "must-not-be-disclosed"}, "HTTP 403"),
        (200, {}, "invalid"),
        (200, {"supported": ["switch-stc"], "enabled": "switch-stc"}, "invalid"),
        (200, {"supported": [None], "enabled": []}, "invalid"),
        (200, {"supported": [], "enabled": []}, "no supported"),
        (200, {"supported": ["switch-stc"], "enabled": []}, "no supported"),
        (200, {"supported": ["../../secrets"], "enabled": ["../../secrets"]}, "no supported"),
    ],
)
async def test_failed_or_empty_switch_discovery_cannot_imply_health(httpx_mock, status, payload, message):
    import httpx  # noqa: PLC0415

    from mist_config_guardian_backend.integrations.mist_sle import MistSleClient  # noqa: PLC0415
    from mist_config_guardian_backend.models.monitoring import DeviceType  # noqa: PLC0415
    from mist_config_guardian_backend.models.organization import MistCloudRegion  # noqa: PLC0415
    from mist_config_guardian_backend.services.impact_analysis import assess_impact  # noqa: PLC0415

    httpx_mock.add_callback(lambda _request: httpx.Response(status, json=payload))
    async with MistSleClient(token="read-token", region=MistCloudRegion.GLOBAL_02) as client:
        result = await client.capture(site_id="site-1", device_type=DeviceType.SWITCH)
    assert len(httpx_mock.get_requests()) == 1
    assert result.values == {}
    assert result.no_data == []
    assert len(result.errors) == 1
    assert message in result.errors[0]
    assert "must-not-be-disclosed" not in result.model_dump_json()
    assert assess_impact(result, result, []).severity == "info"


@pytest.mark.parametrize(("family", "metric"), [("ap", "ap-health"), ("gateway", "gateway-health")])
async def test_all_device_families_use_advertised_metric_names(httpx_mock, family, metric):
    import httpx  # noqa: PLC0415

    from mist_config_guardian_backend.integrations.mist_sle import MistSleClient  # noqa: PLC0415
    from mist_config_guardian_backend.models.monitoring import DeviceType  # noqa: PLC0415
    from mist_config_guardian_backend.models.organization import MistCloudRegion  # noqa: PLC0415

    spelling = metric.replace("-", "_")

    def respond(request):
        if request.url.path.endswith("/metrics"):
            return httpx.Response(200, json={"supported": [spelling], "enabled": [spelling]})
        assert request.url.path.endswith(f"/metric/{spelling}/summary-trend")
        return httpx.Response(200, json={"sle": {"samples": {"total": [10], "degraded": [1]}}})

    httpx_mock.add_callback(respond, is_reusable=True)
    async with MistSleClient(token="read-token", region=MistCloudRegion.GLOBAL_02) as client:
        observation = await client.capture(site_id="site-1", device_type=DeviceType(family), device_mac="aabbccddeeff")
    assert observation.values == {metric: 90}
    assert observation.errors == []
    assert len(httpx_mock.get_requests()) == 2
