"""Aggregate operational health for every runtime dependency.

The Settings "Service health" tab renders one row per component. Every probe is
individually timeout-bounded and never propagates an exception: a broken
dependency has to show up as a failed component, never as a failed request.
"""

import asyncio
import contextlib
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from typing import Protocol

import httpx
import redis.asyncio as redis_asyncio
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.config import Settings

# The region host table lives in the Mist integration. It is imported rather
# than duplicated; see the note in the workstream report about promoting it to a
# public helper.
from mist_config_guardian_backend.integrations.mist import region_base_url
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.monitoring import MonitoringSession
from mist_config_guardian_backend.models.organization import MistCloudRegion, Organization
from mist_config_guardian_backend.models.snapshot import ObjectVersion
from mist_config_guardian_backend.worker import celery_app

_CHECK_TIMEOUT_SECONDS = 2.0
_PROBE_TIMEOUT_SECONDS = 1.5
_WORKER_PING_TIMEOUT_SECONDS = 1.0
_CRITICAL_COMPONENTS = frozenset({"api", "database"})
_BYTES_PER_UNIT = 1024.0
_COMPONENTS: tuple[tuple[str, str], ...] = (
    ("api", "API"),
    ("database", "MongoDB"),
    ("queue", "Redis / Celery broker"),
    ("workers", "Workers"),
    ("timeseries", "InfluxDB"),
    ("storage", "Retention and storage"),
    ("mist", "Mist reachability"),
)


class ComponentStatus(StrEnum):
    """Health of one component, and of the aggregate."""

    OK = "ok"
    DEGRADED = "degraded"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ComponentHealth:
    """One row of the service health table."""

    key: str
    label: str
    status: ComponentStatus
    detail: str
    latency_ms: int | None = None


@dataclass(frozen=True, slots=True)
class OperationalHealthReport:
    """Aggregate health across every component."""

    status: ComponentStatus
    checked_at: datetime
    components: tuple[ComponentHealth, ...]


@dataclass(frozen=True, slots=True)
class StorageUsage:
    """Retention and storage footprint of the configuration archive."""

    version_count: int
    monitoring_session_count: int
    data_size_bytes: int
    retention_days: int | None


class HealthProbes(Protocol):
    """Side-effecting dependency probes, substituted wholesale in tests."""

    async def ping_database(self) -> None:
        """Round-trip a MongoDB ping, raising when it is unavailable."""

    async def ping_queue(self) -> None:
        """Round-trip a Redis ping on the Celery broker, raising when unavailable."""

    async def count_workers(self) -> int:
        """Return how many Celery workers answered a control ping."""

    async def ping_timeseries(self) -> None:
        """Round-trip an InfluxDB ping, raising when it is unavailable."""

    async def storage_usage(self) -> StorageUsage:
        """Return archive counts, on-disk size, and the narrowest retention window."""

    async def cloud_regions(self) -> list[MistCloudRegion]:
        """Return every distinct Mist cloud region configured across organizations."""

    async def ping_mist_region(self, region: MistCloudRegion) -> None:
        """Probe one Mist region host without credentials, raising when unreachable."""


class RuntimeHealthProbes:
    """Probes backed by the process's real MongoDB, Redis, Celery, and HTTP clients."""

    def __init__(self, settings: Settings, mongo_client: AsyncMongoClient | None) -> None:
        self._settings = settings
        self._mongo_client = mongo_client

    def _require_client(self) -> AsyncMongoClient:
        if self._mongo_client is None:
            msg = "MongoDB client is not initialized"
            raise RuntimeError(msg)
        return self._mongo_client

    async def ping_database(self) -> None:
        """Round-trip a MongoDB ping."""
        await self._require_client().admin.command("ping")

    async def ping_queue(self) -> None:
        """Round-trip a Redis ping on the configured Celery broker."""
        client = redis_asyncio.from_url(
            self._settings.celery_broker_url,
            socket_connect_timeout=_PROBE_TIMEOUT_SECONDS,
            socket_timeout=_PROBE_TIMEOUT_SECONDS,
        )
        try:
            await client.ping()
        finally:
            await client.aclose()

    async def count_workers(self) -> int:
        """Ping Celery workers on a worker thread because the control call blocks."""

        def _ping() -> int:
            replies = celery_app.control.inspect(timeout=_WORKER_PING_TIMEOUT_SECONDS).ping()
            return len(replies or {})

        return await asyncio.to_thread(_ping)

    async def ping_timeseries(self) -> None:
        """Round-trip the InfluxDB liveness endpoint."""
        async with httpx.AsyncClient(timeout=_PROBE_TIMEOUT_SECONDS) as client:
            response = await client.get(f"{self._settings.influxdb_url.rstrip('/')}/ping")
            response.raise_for_status()

    async def storage_usage(self) -> StorageUsage:
        """Read archive counts, database size, and the narrowest retention window."""
        database = self._require_client()[self._settings.mongodb_db_name]
        stats = await database.command("dbStats")
        versions = await ObjectVersion.get_pymongo_collection().estimated_document_count()
        sessions = await MonitoringSession.get_pymongo_collection().estimated_document_count()
        narrowest = await Organization.find_all().sort("+configuration_retention_days").limit(1).to_list()
        return StorageUsage(
            version_count=int(versions),
            monitoring_session_count=int(sessions),
            data_size_bytes=int(stats.get("dataSize", 0) or 0),
            retention_days=narrowest[0].configuration_retention_days if narrowest else None,
        )

    async def cloud_regions(self) -> list[MistCloudRegion]:
        """Return every distinct configured Mist cloud region."""
        values = await Organization.get_pymongo_collection().distinct("cloud_region")
        regions: set[MistCloudRegion] = set()
        for value in values:
            with contextlib.suppress(ValueError):
                regions.add(MistCloudRegion(str(value)))
        return sorted(regions)

    async def ping_mist_region(self, region: MistCloudRegion) -> None:
        """Probe a Mist region host anonymously; any HTTP answer proves reachability."""
        async with httpx.AsyncClient(timeout=_PROBE_TIMEOUT_SECONDS) as client:
            await client.get(f"{region_base_url(region)}/api/v1/const/countries")


class OperationalHealthService:
    """Collect every component health row into one aggregate report."""

    def __init__(self, settings: Settings, probes: HealthProbes) -> None:
        self._settings = settings
        self._probes = probes

    async def collect(self) -> OperationalHealthReport:
        """Run every component check concurrently and aggregate the outcome."""
        checks: tuple[Callable[[], Awaitable[ComponentHealth]], ...] = (
            self._check_api,
            self._check_database,
            self._check_queue,
            self._check_workers,
            self._check_timeseries,
            self._check_storage,
            self._check_mist,
        )
        results = await asyncio.gather(
            *(self._guarded(key, label, check) for (key, label), check in zip(_COMPONENTS, checks, strict=True)),
            return_exceptions=True,
        )
        components = tuple(
            result
            if isinstance(result, ComponentHealth)
            else ComponentHealth(
                key=key,
                label=label,
                status=ComponentStatus.FAILED,
                detail=_failure_detail(result),
            )
            for (key, label), result in zip(_COMPONENTS, results, strict=True)
        )
        return OperationalHealthReport(
            status=overall_status(components),
            checked_at=utc_now(),
            components=components,
        )

    async def _guarded(
        self,
        key: str,
        label: str,
        check: Callable[[], Awaitable[ComponentHealth]],
    ) -> ComponentHealth:
        started = time.perf_counter()
        try:
            async with asyncio.timeout(_CHECK_TIMEOUT_SECONDS):
                component = await check()
        except Exception as error:  # noqa: BLE001 - a broken dependency degrades, never 500s
            return ComponentHealth(
                key=key,
                label=label,
                status=ComponentStatus.FAILED,
                detail=_failure_detail(error),
                latency_ms=_elapsed_ms(started),
            )
        if component.latency_ms is None:
            return replace(component, latency_ms=_elapsed_ms(started))
        return component

    async def _check_api(self) -> ComponentHealth:
        return ComponentHealth(
            key="api",
            label="API",
            status=ComponentStatus.OK,
            detail=f"Serving version {self._settings.app_version}",
        )

    async def _check_database(self) -> ComponentHealth:
        await self._probes.ping_database()
        return ComponentHealth(
            key="database",
            label="MongoDB",
            status=ComponentStatus.OK,
            detail="Ping acknowledged",
        )

    async def _check_queue(self) -> ComponentHealth:
        await self._probes.ping_queue()
        return ComponentHealth(
            key="queue",
            label="Redis / Celery broker",
            status=ComponentStatus.OK,
            detail="Broker reachable",
        )

    async def _check_workers(self) -> ComponentHealth:
        online = await self._probes.count_workers()
        if online <= 0:
            return ComponentHealth(
                key="workers",
                label="Workers",
                status=ComponentStatus.DEGRADED,
                detail="No worker answered the control ping",
            )
        return ComponentHealth(
            key="workers",
            label="Workers",
            status=ComponentStatus.OK,
            detail=f"{online} online",
        )

    async def _check_timeseries(self) -> ComponentHealth:
        if not self._settings.influxdb_token.get_secret_value():
            return ComponentHealth(
                key="timeseries",
                label="InfluxDB",
                status=ComponentStatus.DEGRADED,
                detail="Not configured",
            )
        await self._probes.ping_timeseries()
        return ComponentHealth(
            key="timeseries",
            label="InfluxDB",
            status=ComponentStatus.OK,
            detail="Ping acknowledged",
        )

    async def _check_storage(self) -> ComponentHealth:
        usage = await self._probes.storage_usage()
        parts = [
            f"{usage.version_count:,} versions",
            f"{usage.monitoring_session_count:,} monitoring sessions",
            _human_bytes(usage.data_size_bytes),
        ]
        if usage.retention_days is not None:
            parts.append(f"{usage.retention_days}-day retention")
        return ComponentHealth(
            key="storage",
            label="Retention and storage",
            status=ComponentStatus.OK,
            detail=" · ".join(parts),
        )

    async def _check_mist(self) -> ComponentHealth:
        regions = await self._probes.cloud_regions()
        if not regions:
            return ComponentHealth(
                key="mist",
                label="Mist reachability",
                status=ComponentStatus.OK,
                detail="No organization configured",
            )
        reachable = await asyncio.gather(*(self._reachable(region) for region in regions))
        online = [region for region, ok in zip(regions, reachable, strict=True) if ok]
        offline = [region for region, ok in zip(regions, reachable, strict=True) if not ok]
        detail = " · ".join(
            [f"{region.value} reachable" for region in online] + [f"{region.value} unreachable" for region in offline]
        )
        if not online:
            status = ComponentStatus.FAILED
        elif offline:
            status = ComponentStatus.DEGRADED
        else:
            status = ComponentStatus.OK
        return ComponentHealth(key="mist", label="Mist reachability", status=status, detail=detail)

    async def _reachable(self, region: MistCloudRegion) -> bool:
        try:
            async with asyncio.timeout(_PROBE_TIMEOUT_SECONDS):
                await self._probes.ping_mist_region(region)
        except Exception:  # noqa: BLE001 - unreachable is an outcome, not an error
            return False
        else:
            return True


def overall_status(components: Sequence[ComponentHealth]) -> ComponentStatus:
    """Fold component statuses into the aggregate status."""
    if any(item.status is ComponentStatus.FAILED and item.key in _CRITICAL_COMPONENTS for item in components):
        return ComponentStatus.FAILED
    if any(item.status is not ComponentStatus.OK for item in components):
        return ComponentStatus.DEGRADED
    return ComponentStatus.OK


def _failure_detail(error: BaseException) -> str:
    """Describe a probe failure without leaking connection strings or secrets."""
    if isinstance(error, TimeoutError):
        return f"Timed out after {_CHECK_TIMEOUT_SECONDS:g}s"
    return f"Unavailable ({type(error).__name__})"


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def _human_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < _BYTES_PER_UNIT or unit == "GB":
            return f"{value:.0f} {unit}"
        value /= _BYTES_PER_UNIT
    return f"{value:.0f} GB"
