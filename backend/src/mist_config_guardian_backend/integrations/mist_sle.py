"""Read-only Mist SLE observation client."""

import asyncio
import math
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
        "failed-to-connect",
        "successful-connect",
        "throughput",
        "roaming",
        "capacity",
        "coverage",
        "ap-availability",
        "ap-health",
    ),
    DeviceType.SWITCH: (
        "switch-bandwidth",
        "switch-throughput",
        "switch-health",
        "switch-stc",
        "switch-stc-new",
    ),
    DeviceType.GATEWAY: ("gateway-health", "wan-link-health", "gateway-bandwidth", "application-health"),
}


class SlePayloadError(ValueError):
    """The provider returned an invalid SLE measurement structure."""


class MistSleClient(AbstractAsyncContextManager["MistSleClient"]):
    """Capture site or device SLE success rates using a read-only service token."""

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
        """Capture relevant metrics for the selected site or device scope."""
        end = end or utc_now()
        start = start or end - timedelta(hours=1)
        scope = device_type.value if device_mac else "site"
        scope_id = device_id(device_mac) if device_mac else site_id
        base_path = f"/api/v1/sites/{site_id}/sle/{scope}/{scope_id}"
        # Discover the exact scope's enabled metrics for every device family.
        metrics, error = await self._discover_metrics(base_path, device_type)
        if error:
            return SleObservation(
                errors=[error], window_start=start, window_end=end, scope="device" if device_mac else "site"
            )
        tasks = [
            self._fetch_metric(
                metric,
                f"{base_path}/metric/{api_metric}/summary-trend",
                start=start,
                end=end,
            )
            for metric, api_metric in metrics
        ]
        results = await asyncio.gather(*tasks)
        values = {metric: value for metric, value, _error in results if value is not None}
        errors = [error for _metric, _value, error in results if error is not None]
        return SleObservation(
            values=values,
            no_data=[metric for metric, value, error in results if value is None and error is None],
            errors=errors,
            window_start=start,
            window_end=end,
            scope="device" if device_mac else "site",
        )

    async def _discover_metrics(
        self, base_path: str, device_type: DeviceType
    ) -> tuple[list[tuple[str, str]], str | None]:
        """Use only supported, enabled metrics; preserve API spelling in URLs."""
        try:
            response = await self._client.get(f"{base_path}/metrics")
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict) or any(
                not isinstance(payload.get(key), list) or any(not isinstance(value, str) for value in payload[key])
                for key in ("supported", "enabled")
            ):
                return [], "metric discovery: invalid SLE metrics response"
            available = set(payload["supported"]) & set(payload["enabled"])
            # Published examples use underscores; other deployments advertise
            # hyphens. Keep stored keys stable without guessing the request URL.
            metrics = []
            for metric in _METRICS[device_type]:
                for spelling in (metric, metric.replace("-", "_")):
                    if spelling in available:
                        metrics.append((metric, spelling))
                        break
            if not metrics:
                return [], f"metric discovery: no supported and enabled {device_type.value} SLE metrics"
        except httpx.HTTPStatusError as exc:
            return (
                [],
                (
                    f"metric discovery: HTTP {exc.response.status_code} from the SLE metrics endpoint "
                    f"({base_path}/metrics)"
                ),
            )
        except (httpx.HTTPError, ValueError):
            return [], "metric discovery: unavailable"
        return metrics, None

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
        except SlePayloadError:
            return metric, None, f"{metric}: invalid SLE response"
        except httpx.HTTPStatusError as exc:
            return metric, None, f"{metric}: HTTP {exc.response.status_code} from the SLE endpoint ({path})"
        except (httpx.HTTPError, ValueError):
            return metric, None, f"{metric}: unavailable"
        return metric, value, None


def extract_sle_value(payload: object) -> float | None:
    """Average bucket rates; None means a valid response with no sampled events.

    Invalid shapes or counters raise ValueError so they cannot be mistaken for
    a quiet site. Paired null buckets and zero totals carry no sampled traffic.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("sle"), dict):
        msg = "Missing SLE object"
        raise SlePayloadError(msg)
    samples = payload["sle"].get("samples")
    if not isinstance(samples, dict):
        msg = "Missing SLE samples"
        raise SlePayloadError(msg)
    totals, degraded = samples.get("total"), samples.get("degraded")
    if not isinstance(totals, list) or not isinstance(degraded, list) or len(totals) != len(degraded):
        msg = "Invalid SLE sample arrays"
        raise SlePayloadError(msg)
    rates: list[float] = []
    for total, failed in zip(totals, degraded, strict=True):
        if failed is None and (
            total is None or (isinstance(total, (int, float)) and not isinstance(total, bool) and total == 0)
        ):
            continue
        if not _valid_sample(total, failed):
            msg = "Invalid SLE sample counters"
            raise SlePayloadError(msg)
        if total > 0:
            rates.append((total - failed) / total * 100)
    return None if not rates else round(sum(rates) / len(rates), 2)


def _valid_sample(total: object, failed: object) -> bool:
    return (
        isinstance(total, (int, float))
        and not isinstance(total, bool)
        and math.isfinite(total)
        and isinstance(failed, (int, float))
        and not isinstance(failed, bool)
        and math.isfinite(failed)
        and 0 <= failed <= total
    )
