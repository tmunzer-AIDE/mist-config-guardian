"""Historical browsing is read-only on the server, not only in the browser."""

import httpx
from starlette.responses import JSONResponse
from starlette.types import Receive, Scope, Send

from mist_config_guardian_backend.api.middleware import HistoricalContextGuard
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.main import create_app

AS_OF = {"X-Config-Guardian-As-Of": "2026-09-01T00:00:00Z"}
ORGANIZATION = "/api/v1/organizations/65f0aa11bb22cc33dd44ee55"


def _client() -> httpx.AsyncClient:
    app = create_app(Settings(environment="test", database_enabled=False))
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def test_a_write_to_organization_state_is_refused_before_anything_else() -> None:
    """The refusal precedes authentication: no write is attempted at all."""
    async with _client() as client:
        response = await client.post(f"{ORGANIZATION}/snapshots", headers=AS_OF)

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


async def _reached(scope: Scope, receive: Receive, send: Send) -> None:
    """Stand in for the application: anything that gets here was not refused."""
    await JSONResponse({"reached": scope["path"]})(scope, receive, send)


def _guarded_client() -> httpx.AsyncClient:
    guard = HistoricalContextGuard(_reached, prefix="/api/v1")
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=guard), base_url="http://test")


async def test_session_and_notification_hygiene_are_not_history() -> None:
    """Only organization state is guarded.

    Signing out, acknowledging a notification, or changing one's own password
    derives nothing from the past. Refusing them would leave a server session
    live behind a client that believes it signed out, and a badge that cannot
    be cleared.
    """
    async with _guarded_client() as client:
        for path in (
            "/api/v1/auth/logout",
            "/api/v1/auth/login",
            f"{ORGANIZATION}/notifications/read-all",
            f"{ORGANIZATION}/notifications/65f0aa11bb22cc33dd44ee56/read",
            "/api/v1/account/password",
            "/api/v1/users/65f0aa11bb22cc33dd44ee56/deactivate",
        ):
            response = await client.post(path, headers=AS_OF)
            assert response.status_code == 200, path
            assert response.json() == {"reached": path}

        for path in (
            "/api/v1/organizations",
            f"{ORGANIZATION}",
            f"{ORGANIZATION}/snapshots",
            f"{ORGANIZATION}/restores/65f0aa11bb22cc33dd44ee56/execute",
        ):
            response = await client.post(path, headers=AS_OF)
            assert response.status_code == 409, path


async def test_a_write_without_the_header_reaches_the_route() -> None:
    async with _client() as client:
        response = await client.post("/api/v1/organizations")

    assert response.status_code == 401
