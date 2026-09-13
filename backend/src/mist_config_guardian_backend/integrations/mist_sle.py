"""Read-only Mist SLE observation client."""

import asyncio
import math
from collections.abc import Sequence
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

    async def capture(  # noqa: PLR0913 - scope, window and anchor are all caller-chosen
        self,
        *,
        site_id: str,
        device_type: DeviceType,
        start: datetime | None = None,
        end: datetime | None = None,
        device_mac: str | None = None,
        anchor: timedelta | None = None,
    ) -> SleObservation:
        """Capture relevant metrics for the selected site or device scope.

        ``anchor`` narrows the reported ``values`` to the tail of the window
        while the returned trend still spans all of it. A 24-hour baseline mean
        is not comparable to a post-change window measured in minutes, so the
        baseline anchors on its final hour; post-change polls pass no anchor and
        keep averaging everything they measured since the change.
        """
        end = end or utc_now()
        start = start or end - timedelta(hours=1)
        scope = device_type.value if device_mac else "site"
        scope_id = device_id(device_mac) if device_mac else site_id
        base_path = f"/api/v1/sites/{site_id}/sle/{scope}/{scope_id}"
        # Discover the exact scope's enabled metrics for every device family.
        metrics, error = await self._discover_metrics(base_path, device_type)
        if error:
            return SleObservation(
                errors=[error],
                window_start=start,
                window_end=end,
                scope="device" if device_mac else "site",
                scope_id=scope_id,
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
        anchored = [
            (metric, anchor_value(series, start, end, anchor), series, error) for metric, series, error in results
        ]
        values = {metric: value for metric, value, _series, _error in anchored if value is not None}
        errors = [error for _metric, _value, _series, error in anchored if error is not None]
        # Report the narrowed window only where the tail actually carried
        # traffic. A metric whose final hour was quiet widened back to the whole
        # window, and calling that a last-hour baseline would misdescribe it.
        narrowed = anchor is not None and any(
            mean_of_series(anchor_tail(series, start, end, anchor)) is not None
            for _metric, _value, series, error in anchored
            if error is None
        )
        return SleObservation(
            scope_id=scope_id,
            requested_metrics=[metric for metric, _api_metric in metrics],
            metric_errors={metric: error for metric, _value, _series, error in anchored if error is not None},
            values=values,
            trend={metric: series for metric, _value, series, error in anchored if error is None and series},
            baseline_window="last-hour" if narrowed else "full-window",
            no_data=[metric for metric, value, _series, error in anchored if value is None and error is None],
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
    ) -> tuple[str, list[float | None], str | None]:
        params = {"start": str(int(start.timestamp())), "end": str(int(end.timestamp()))}
        try:
            response = await self._client.get(path, params=params)
            response.raise_for_status()
            series = extract_sle_series(response.json())
        except SlePayloadError:
            return metric, [], f"{metric}: invalid SLE response"
        except httpx.HTTPStatusError as exc:
            return metric, [], f"{metric}: HTTP {exc.response.status_code} from the SLE endpoint ({path})"
        except (httpx.HTTPError, ValueError):
            return metric, [], f"{metric}: unavailable"
        return metric, series, None


def extract_sle_series(payload: object) -> list[float | None]:
    """Per-bucket success rates; ``None`` marks a bucket with no sampled events.

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
    series: list[float | None] = []
    for total, failed in zip(totals, degraded, strict=True):
        if failed is None and (
            total is None or (isinstance(total, (int, float)) and not isinstance(total, bool) and total == 0)
        ):
            series.append(None)
            continue
        if not _valid_sample(total, failed):
            msg = "Invalid SLE sample counters"
            raise SlePayloadError(msg)
        series.append((total - failed) / total * 100 if total > 0 else None)
    return series


def extract_sle_value(payload: object) -> float | None:
    """Average bucket rates; None means a valid response with no sampled events."""
    return mean_of_series(extract_sle_series(payload))


def mean_of_series(series: Sequence[float | None]) -> float | None:
    """Mean of the sampled buckets, matching existing stored baselines."""
    rates = [rate for rate in series if rate is not None]
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


def anchor_value(
    series: Sequence[float | None],
    start: datetime,
    end: datetime,
    anchor: timedelta | None,
) -> float | None:
    """Mean of the buckets inside ``anchor`` of ``end``, else of the whole window.

    Only an *unsampled* tail widens to the full window; a measured 0% is a total
    outage and is reported as one. Testing the mean for None rather than for
    truthiness is what keeps those two apart.
    """
    tail = anchor_tail(series, start, end, anchor)
    value = mean_of_series(tail)
    return value if value is not None else mean_of_series(series)


def anchor_tail(
    series: Sequence[float | None],
    start: datetime,
    end: datetime,
    anchor: timedelta | None,
) -> Sequence[float | None]:
    """The trailing buckets covering ``anchor``, or the whole series."""
    if anchor is None or not series:
        return series
    span = (end - start).total_seconds()
    if span <= 0 or anchor.total_seconds() >= span:
        return series
    bucket = span / len(series)
    return series[-max(1, math.ceil(anchor.total_seconds() / bucket)) :]
