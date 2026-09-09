"""Read-only Mist SLE observation client."""

import asyncio
from contextlib import AbstractAsyncContextManager
from datetime import datetime, timedelta
from types import TracebackType
from typing import Self

import httpx

from mist_config_guardian_backend.integrations.mist import REGION_HOSTS
from mist_config_guardian_backend.integrations.mist_telemetry import device_id
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.monitoring import DeviceType, SleObservation
from mist_config_guardian_backend.models.organization import MistCloudRegion

_METRICS: dict[DeviceType, tuple[str, ...]] = {
    DeviceType.AP: (
        "time-to-connect",
        "successful-connect",
        "throughput",
        "roaming",
        "capacity",
        "coverage",
        "ap-health",
    ),
    DeviceType.SWITCH: (
        "switch-throughput",
        "switch-health",
        "switch-stc",
        "switch-stc-new",
    ),
    DeviceType.GATEWAY: ("gateway-health", "wan-link-health"),
}


class MistSleClient(AbstractAsyncContextManager["MistSleClient"]):
    """Capture site SLE success rates using a read-only service token."""

    def __init__(self, *, token: str, region: MistCloudRegion) -> None:
        self._client = httpx.AsyncClient(
            base_url=REGION_HOSTS[region],
            headers={"Authorization": f"Token {token}"},
            timeout=30,
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self._client.aclose()

    async def capture(
        self,
        *,
        site_id: str,
        device_type: DeviceType,
        start: datetime | None = None,
        end: datetime | None = None,
        device_mac: str | None = None,
    ) -> SleObservation:
        """Capture all relevant site-level metrics concurrently."""
        end = end or utc_now()
        start = start or end - timedelta(hours=1)
        scope = device_type.value if device_mac else "site"
        scope_id = device_id(device_mac) if device_mac else site_id
        tasks = [
            self._fetch_metric(
                metric,
                f"/api/v1/sites/{site_id}/sle/{scope}/{scope_id}/metric/{metric}/summary-trend",
                start=start,
                end=end,
            )
            for metric in _METRICS[device_type]
        ]
        results = await asyncio.gather(*tasks)
        values = {metric: value for metric, value, _error in results if value is not None}
        errors = [error for _metric, _value, error in results if error is not None]
        return SleObservation(values=values, errors=errors, window_start=start, window_end=end)

    async def _fetch_metric(
        self,
        metric: str,
        path: str,
        *,
        start: datetime,
        end: datetime,
    ) -> tuple[str, float | None, str | None]:
        params = {"start": str(int(start.timestamp())), "end": str(int(end.timestamp()))}
        try:
            response = await self._client.get(path, params=params)
            response.raise_for_status()
            value = extract_sle_value(response.json())
        except (httpx.HTTPError, ValueError):
            return metric, None, f"{metric}: unavailable"
        return metric, value, None if value is not None else f"{metric}: no data"


def extract_sle_value(payload: object) -> float | None:
    """Compute average success rate from valid total/degraded buckets."""
    if not isinstance(payload, dict):
        return None
    sle = payload.get("sle")
    if not isinstance(sle, dict):
        return None
    samples = sle.get("samples")
    if not isinstance(samples, dict):
        return None
    totals = samples.get("total")
    degraded = samples.get("degraded")
    if not isinstance(totals, list) or not isinstance(degraded, list):
        return None
    total_samples = 0.0
    failed_samples = 0.0
    for total, failed in zip(totals, degraded, strict=False):
        if (
            isinstance(total, (int, float))
            and not isinstance(total, bool)
            and isinstance(failed, (int, float))
            and not isinstance(failed, bool)
            and total > 0
            and 0 <= failed <= total
        ):
            total_samples += total
            failed_samples += failed
    return None if not total_samples else round((total_samples - failed_samples) / total_samples * 100, 2)
