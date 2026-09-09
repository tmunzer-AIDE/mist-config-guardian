"""Read-only Mist SLE observation client."""

import asyncio
from contextlib import AbstractAsyncContextManager
from types import TracebackType
from typing import Self

import httpx

from mist_config_guardian_backend.integrations.mist import REGION_HOSTS
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
        end: str | None = None,
    ) -> SleObservation:
        """Capture all relevant site-level metrics concurrently."""
        tasks = [self._fetch_metric(site_id, metric, end=end) for metric in _METRICS[device_type]]
        results = await asyncio.gather(*tasks)
        values = {metric: value for metric, value, _error in results if value is not None}
        errors = [error for _metric, _value, error in results if error is not None]
        return SleObservation(values=values, errors=errors)

    async def _fetch_metric(
        self,
        site_id: str,
        metric: str,
        *,
        end: str | None,
    ) -> tuple[str, float | None, str | None]:
        path = f"/api/v1/sites/{site_id}/sle/site/{site_id}/metric/{metric}/summary-trend"
        params = {"duration": "1h"}
        if end:
            params["end"] = end
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
    rates: list[float] = []
    for total, failed in zip(totals, degraded, strict=False):
        if (
            isinstance(total, (int, float))
            and not isinstance(total, bool)
            and isinstance(failed, (int, float))
            and not isinstance(failed, bool)
            and total > 0
        ):
            rates.append((total - failed) / total * 100)
    return None if not rates else round(sum(rates) / len(rates), 2)
