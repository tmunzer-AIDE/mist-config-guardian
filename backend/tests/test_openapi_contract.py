"""Tests for the published OpenAPI contract."""

from typing import Any

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.main import create_app


def _document() -> dict[str, Any]:
    return create_app(Settings(environment="test", database_enabled=False)).openapi()


def test_document_describes_both_ways_a_client_authenticates() -> None:
    """A browser session is as valid as a bearer token and must be documented."""
    schemes = _document()["components"]["securitySchemes"]

    assert set(schemes) == {"OAuth2PasswordBearer", "SessionCookie", "CsrfToken"}
    assert schemes["SessionCookie"] == {
        "type": "apiKey",
        "in": "cookie",
        "name": "cg_session",
        "description": (
            "Browser session issued by `POST /auth/login`. Unsafe methods must also send the "
            "`cg_csrf` cookie value in the `X-CSRF-Token` header."
        ),
    }
    assert schemes["CsrfToken"]["in"] == "header"
    assert schemes["CsrfToken"]["name"] == "X-CSRF-Token"


def test_authenticated_operations_offer_the_cookie_alternative() -> None:
    """Every bearer-protected operation also accepts a cookie session."""
    paths = _document()["paths"]

    bearer_operations = [
        (path, method, operation)
        for path, methods in paths.items()
        for method, operation in methods.items()
        if any("OAuth2PasswordBearer" in requirement for requirement in operation.get("security", []))
    ]

    assert bearer_operations, "expected authenticated operations in the document"
    for path, method, operation in bearer_operations:
        alternatives = operation["security"]
        assert any("SessionCookie" in requirement for requirement in alternatives), (
            f"{method.upper()} {path} does not document the cookie session"
        )


def test_public_operations_are_not_marked_authenticated() -> None:
    """Liveness, readiness, login, and the webhook receiver stay unauthenticated."""
    paths = _document()["paths"]

    for path, method in [
        ("/api/v1/health", "get"),
        ("/api/v1/ready", "get"),
        ("/api/v1/auth/login", "post"),
        ("/api/v1/auth/bootstrap", "post"),
    ]:
        assert "security" not in paths[path][method], f"{method.upper()} {path} should be public"


def test_generating_the_document_twice_does_not_duplicate_requirements() -> None:
    """The customization is idempotent, because FastAPI caches and reuses it."""
    app = create_app(Settings(environment="test", database_enabled=False))

    first = app.openapi()["paths"]["/api/v1/organizations"]["get"]["security"]
    second = app.openapi()["paths"]["/api/v1/organizations"]["get"]["security"]

    assert first == second
    assert len(second) == 2


def test_every_tag_used_by_a_route_is_described() -> None:
    """A tag without a description leaves a section of the contract unexplained."""
    document = _document()
    described = {tag["name"] for tag in document["tags"]}
    used = {
        tag
        for methods in document["paths"].values()
        for operation in methods.values()
        for tag in operation.get("tags", [])
    }

    assert used - described == set()
