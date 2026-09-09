"""Aggregate operational health service and API tests."""

import asyncio

import httpx
import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.api.dependencies import get_current_user
from mist_config_guardian_backend.api.routes.system_health import get_operational_health_service
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.main import create_app
from mist_config_guardian_backend.models.organization import MistCloudRegion
from mist_config_guardian_backend.models.user import User, UserRole
from mist_config_guardian_backend.services import operational_health
from mist_config_guardian_backend.services.operational_health import (
    ComponentHealth,
    ComponentStatus,
    OperationalHealthService,
    RuntimeHealthProbes,
    StorageUsage,
    overall_status,
)


class _FakeProbes:
    """Probe double whose every dependency can be made slow, broken, or healthy."""

    def __init__(self) -> None:
        self.database_error: Exception | None = None
        self.database_delay = 0.0
        self.queue_error: Exception | None = None
        self.timeseries_error: Exception | None = None
        self.storage_error: Exception | None = None
        self.workers = 2
        self.regions: list[MistCloudRegion] = [MistCloudRegion.GLOBAL_01]
        self.unreachable: set[MistCloudRegion] = set()
        self.usage = StorageUsage(
            version_count=1284,
            monitoring_session_count=96,
            data_size_bytes=432_013_312,
            retention_days=365,
        )

    async def ping_database(self) -> None:
        if self.database_delay:
            await asyncio.sleep(self.database_delay)
        if self.database_error is not None:
            raise self.database_error

    async def ping_queue(self) -> None:
        if self.queue_error is not None:
            raise self.queue_error

    async def count_workers(self) -> int:
        return self.workers

    async def ping_timeseries(self) -> None:
        if self.timeseries_error is not None:
            raise self.timeseries_error

    async def storage_usage(self) -> StorageUsage:
        if self.storage_error is not None:
            raise self.storage_error
        return self.usage

    async def cloud_regions(self) -> list[MistCloudRegion]:
        return list(self.regions)

    async def ping_mist_region(self, region: MistCloudRegion) -> None:
        if region in self.unreachable:
            msg = "connection refused"
            raise ConnectionError(msg)


def _settings(*, influx_configured: bool = True) -> Settings:
    return Settings(
        environment="test",
        database_enabled=False,
        influxdb_token="influx-token" if influx_configured else "",
    )


def _service(probes: _FakeProbes, *, influx_configured: bool = True) -> OperationalHealthService:
    return OperationalHealthService(_settings(influx_configured=influx_configured), probes)


def _by_key(report: operational_health.OperationalHealthReport) -> dict[str, ComponentHealth]:
    return {component.key: component for component in report.components}


def _viewer() -> User:
    return User.model_construct(
        id=PydanticObjectId(),
        email="viewer@example.com",
        display_name="Viewer",
        password_hash="unused",
        role=UserRole.VIEWER,
        is_active=True,
    )


# ------------------------------------------------------------------ aggregate


async def test_healthy_stack_reports_every_component_ok() -> None:
    report = await _service(_FakeProbes()).collect()

    assert report.status is ComponentStatus.OK
    assert [component.key for component in report.components] == [
        "api",
        "database",
        "queue",
        "workers",
        "timeseries",
        "storage",
        "mist",
    ]
    components = _by_key(report)
    assert components["api"].detail == "Serving version 0.2.2"
    assert components["workers"].detail == "2 online"
    assert components["storage"].detail == "1,284 versions · 96 monitoring sessions · 412 MB · 365-day retention"
    assert components["mist"].detail == "global_01 reachable"
    assert all(component.latency_ms is not None for component in report.components)


async def test_failed_database_fails_the_aggregate() -> None:
    probes = _FakeProbes()
    probes.database_error = ConnectionRefusedError("mongodb://user:secret@db:27017 refused")

    report = await _service(probes).collect()
    components = _by_key(report)

    assert report.status is ComponentStatus.FAILED
    assert components["database"].status is ComponentStatus.FAILED
    assert components["database"].detail == "Unavailable (ConnectionRefusedError)"
    assert "secret" not in components["database"].detail


async def test_failed_queue_only_degrades_the_aggregate() -> None:
    probes = _FakeProbes()
    probes.queue_error = OSError("broker down")

    report = await _service(probes).collect()

    assert report.status is ComponentStatus.DEGRADED
    assert _by_key(report)["queue"].status is ComponentStatus.FAILED
    assert _by_key(report)["database"].status is ComponentStatus.OK


async def test_no_worker_reply_is_degraded_not_failed() -> None:
    probes = _FakeProbes()
    probes.workers = 0

    report = await _service(probes).collect()
    workers = _by_key(report)["workers"]

    assert report.status is ComponentStatus.DEGRADED
    assert workers.status is ComponentStatus.DEGRADED
    assert workers.detail == "No worker answered the control ping"


async def test_unconfigured_influxdb_is_degraded_and_never_probed() -> None:
    probes = _FakeProbes()
    probes.timeseries_error = RuntimeError("must not be called")

    report = await _service(probes, influx_configured=False).collect()
    timeseries = _by_key(report)["timeseries"]

    assert timeseries.status is ComponentStatus.DEGRADED
    assert timeseries.detail == "Not configured"
    assert report.status is ComponentStatus.DEGRADED


async def test_a_probe_that_raises_becomes_a_failed_component() -> None:
    probes = _FakeProbes()
    probes.storage_error = RuntimeError("dbStats exploded")

    report = await _service(probes).collect()
    storage = _by_key(report)["storage"]

    assert storage.status is ComponentStatus.FAILED
    assert storage.detail == "Unavailable (RuntimeError)"
    assert report.status is ComponentStatus.DEGRADED


async def test_partially_reachable_mist_regions_are_degraded() -> None:
    probes = _FakeProbes()
    probes.regions = [MistCloudRegion.GLOBAL_01, MistCloudRegion.EMEA_01]
    probes.unreachable = {MistCloudRegion.EMEA_01}

    report = await _service(probes).collect()
    mist = _by_key(report)["mist"]

    assert mist.status is ComponentStatus.DEGRADED
    assert mist.detail == "global_01 reachable · emea_01 unreachable"


async def test_all_regions_unreachable_fails_only_that_component() -> None:
    probes = _FakeProbes()
    probes.unreachable = {MistCloudRegion.GLOBAL_01}

    report = await _service(probes).collect()

    assert _by_key(report)["mist"].status is ComponentStatus.FAILED
    assert report.status is ComponentStatus.DEGRADED


async def test_no_organization_leaves_mist_reachability_ok() -> None:
    probes = _FakeProbes()
    probes.regions = []

    report = await _service(probes).collect()
    mist = _by_key(report)["mist"]

    assert mist.status is ComponentStatus.OK
    assert mist.detail == "No organization configured"


async def test_a_slow_probe_is_bounded_by_the_check_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(operational_health, "_CHECK_TIMEOUT_SECONDS", 0.02)
    probes = _FakeProbes()
    probes.database_delay = 0.5

    report = await asyncio.wait_for(_service(probes).collect(), timeout=2)
    database = _by_key(report)["database"]

    assert database.status is ComponentStatus.FAILED
    assert database.detail.startswith("Timed out after")
    assert report.status is ComponentStatus.FAILED


def test_overall_status_folds_component_statuses() -> None:
    ok = ComponentHealth(key="api", label="API", status=ComponentStatus.OK, detail="")
    degraded = ComponentHealth(key="workers", label="Workers", status=ComponentStatus.DEGRADED, detail="")
    non_critical_failure = ComponentHealth(key="queue", label="Queue", status=ComponentStatus.FAILED, detail="")
    critical_failure = ComponentHealth(key="database", label="MongoDB", status=ComponentStatus.FAILED, detail="")

    assert overall_status([ok]) is ComponentStatus.OK
    assert overall_status([ok, degraded]) is ComponentStatus.DEGRADED
    assert overall_status([ok, non_critical_failure]) is ComponentStatus.DEGRADED
    assert overall_status([ok, critical_failure]) is ComponentStatus.FAILED


# ------------------------------------------------------------------------ api


async def test_viewer_can_read_the_health_aggregate() -> None:
    probes = _FakeProbes()
    probes.workers = 0
    app = create_app(Settings(environment="test", database_enabled=False))
    app.dependency_overrides[get_current_user] = _viewer
    app.dependency_overrides[get_operational_health_service] = lambda: _service(probes)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/system/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "degraded"
    assert payload["checked_at"]
    assert {component["key"] for component in payload["components"]} == {
        "api",
        "database",
        "queue",
        "workers",
        "timeseries",
        "storage",
        "mist",
    }


async def test_broken_dependencies_never_produce_a_server_error() -> None:
    probes = _FakeProbes()
    probes.database_error = RuntimeError("boom")
    probes.queue_error = RuntimeError("boom")
    probes.storage_error = RuntimeError("boom")
    probes.timeseries_error = RuntimeError("boom")
    probes.unreachable = {MistCloudRegion.GLOBAL_01}
    app = create_app(Settings(environment="test", database_enabled=False))
    app.dependency_overrides[get_current_user] = _viewer
    app.dependency_overrides[get_operational_health_service] = lambda: _service(probes)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/system/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "failed"
    statuses = {component["key"]: component["status"] for component in payload["components"]}
    assert statuses["api"] == "ok"
    assert statuses["database"] == "failed"
    assert statuses["mist"] == "failed"


async def test_health_aggregate_requires_authentication() -> None:
    app = create_app(Settings(environment="test", database_enabled=False))

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/system/health")

    assert response.status_code == 401


async def test_liveness_and_readiness_are_untouched() -> None:
    settings = Settings(environment="test", database_enabled=False)
    app = create_app(settings)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        health = await client.get("/api/v1/health")
        ready = await client.get("/api/v1/ready")

    assert health.json() == {"status": "ok", "name": "Mist Config Guardian", "version": settings.app_version}
    assert ready.json() == {"status": "ready"}


async def test_runtime_probes_refuse_to_run_without_an_initialized_mongo_client() -> None:
    probes = RuntimeHealthProbes(_settings(), None)

    with pytest.raises(RuntimeError, match="MongoDB client is not initialized"):
        await probes.ping_database()
    with pytest.raises(RuntimeError, match="MongoDB client is not initialized"):
        await probes.storage_usage()

    service = OperationalHealthService(_settings(), probes)
    database = await service._guarded("database", "MongoDB", service._check_database)  # noqa: SLF001

    assert database.status is ComponentStatus.FAILED
    assert database.detail == "Unavailable (RuntimeError)"


@pytest.mark.parametrize(
    ("size", "expected"),
    [(512, "512 B"), (2048, "2 KB"), (432_013_312, "412 MB"), (5_368_709_120, "5 GB")],
)
async def test_storage_detail_scales_the_size_unit(size: int, expected: str) -> None:
    probes = _FakeProbes()
    probes.usage = StorageUsage(
        version_count=1,
        monitoring_session_count=0,
        data_size_bytes=size,
        retention_days=None,
    )

    report = await _service(probes).collect()

    assert _by_key(report)["storage"].detail == f"1 versions · 0 monitoring sessions · {expected}"
