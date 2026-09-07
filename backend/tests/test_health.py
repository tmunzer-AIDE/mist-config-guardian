"""Health endpoint tests."""

import httpx

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.main import create_app


async def test_health_returns_application_identity() -> None:
    app = create_app(Settings(environment="test", database_enabled=False))

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "name": "Mist Config Guardian",
        "version": "0.1.0",
    }


async def test_ready_returns_success() -> None:
    app = create_app(Settings(environment="test", database_enabled=False))

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}
