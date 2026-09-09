"""Mist SLE payload parsing tests."""

from mist_config_guardian_backend.integrations.mist_sle import extract_sle_value


def test_extract_sle_value_weights_valid_samples_by_traffic() -> None:
    payload = {
        "sle": {
            "samples": {
                "total": [100, None, 50, 0],
                "degraded": [10, None, 10, 0],
            }
        }
    }

    assert extract_sle_value(payload) == 86.67


def test_extract_sle_value_rejects_invalid_payload() -> None:
    assert extract_sle_value({"sle": {"samples": {"total": [], "degraded": []}}}) is None
    assert extract_sle_value("invalid") is None


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
