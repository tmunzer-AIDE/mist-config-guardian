"""Historical browsing is read-only on the server, not only in the browser."""

import httpx

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.main import create_app

AS_OF = {"X-Config-Guardian-As-Of": "2026-09-01T00:00:00Z"}


def _client() -> httpx.AsyncClient:
    app = create_app(Settings(environment="test", database_enabled=False))
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def test_a_write_under_a_historical_context_is_refused_before_anything_else() -> None:
    """The refusal precedes authentication: no write is attempted at all."""
    async with _client() as client:
        response = await client.post(
            "/api/v1/auth/login",
            data={"username": "x@example.com", "password": "irrelevant"},
            headers=AS_OF,
        )

    assert response.status_code == 409
    assert response.json() == {"detail": "Write operations are disabled while viewing a historical point in time"}


async def test_every_unsafe_method_is_covered() -> None:
    """A route added later is covered without declaring anything."""
    async with _client() as client:
        for method in ("post", "put", "patch", "delete"):
            response = await client.request(method, "/api/v1/organizations", headers=AS_OF)
            assert response.status_code == 409, method


async def test_reads_under_a_historical_context_pass_through() -> None:
    async with _client() as client:
        response = await client.get("/api/v1/health", headers=AS_OF)

    assert response.status_code == 200


async def test_a_write_without_the_header_reaches_the_route() -> None:
    async with _client() as client:
        response = await client.post("/api/v1/organizations")

    assert response.status_code == 401
