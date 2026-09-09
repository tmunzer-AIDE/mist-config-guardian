"""The authorization model, asserted route by route.

Roles are easy to get wrong in a way no functional test notices: an endpoint
that demands an administrator still works perfectly for an administrator. This
walks every registered route and pins the minimum role it actually requires, so
adding a route with the wrong one fails here rather than in production.
"""

from collections.abc import Iterable, Iterator

from fastapi.routing import APIRoute

from mist_config_guardian_backend.api.dependencies import (
    get_current_user,
    require_administrator,
    require_operator,
    require_viewer,
)
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.main import create_app

# "authenticated" means a signed-in user of any role: the endpoint identifies
# the caller but imposes no role floor.
_ROLE_BY_DEPENDENCY = {
    get_current_user: "authenticated",
    require_viewer: "viewer",
    require_operator: "operator",
    require_administrator: "administrator",
}

# Endpoints reachable without a session: liveness, sign-in, invitation
# redemption, and the signature-authenticated webhook receiver.
PUBLIC = {
    ("GET", "/api/v1/health"),
    ("GET", "/api/v1/ready"),
    ("GET", "/api/v1/auth/bootstrap"),
    ("POST", "/api/v1/auth/bootstrap"),
    ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/auth/login/mfa"),
    ("POST", "/api/v1/auth/logout"),
    ("POST", "/api/v1/auth/passkey/options"),
    ("POST", "/api/v1/auth/passkey/verify"),
    ("POST", "/api/v1/users/accept-invitation"),
    ("POST", "/api/v1/webhooks/mist/{organization_id}"),
}

# Signed in, but deliberately role-agnostic.
AUTHENTICATED_ONLY = {("GET", "/api/v1/auth/me")}


def _required_role(route: APIRoute) -> str | None:
    """Return the minimum role a route requires, or None when it is public."""
    seen: set[str] = set()

    def walk(dependant: object) -> None:
        call = getattr(dependant, "call", None)
        if call in _ROLE_BY_DEPENDENCY:
            seen.add(_ROLE_BY_DEPENDENCY[call])
        for child in getattr(dependant, "dependencies", []):
            walk(child)

    walk(route.dependant)
    if not seen:
        return None
    # A route may nest several role dependencies; the strictest one governs.
    for role in ("administrator", "operator", "viewer", "authenticated"):
        if role in seen:
            return role
    return None


def _flatten(routes: Iterable[object]) -> Iterator[APIRoute]:
    """Yield every APIRoute, descending through included sub-routers.

    FastAPI wraps an included router rather than splicing its routes into the
    parent list, so a shallow walk of ``app.routes`` finds almost nothing.
    """
    for route in routes:
        if isinstance(route, APIRoute):
            yield route
            continue
        nested = getattr(route, "original_router", None)
        if nested is not None:
            yield from _flatten(nested.routes)


def _routes() -> list[tuple[str, str, str | None]]:
    settings = Settings(environment="test", database_enabled=False)
    app = create_app(settings)
    # A route reports its own path; the versioned prefix comes from the mount.
    prefix = settings.api_v1_prefix
    return sorted(
        (method, route.path if route.path.startswith(prefix) else prefix + route.path, _required_role(route))
        for route in _flatten(app.routes)
        for method in sorted(route.methods - {"HEAD", "OPTIONS"})
    )


def test_every_route_states_a_role_or_is_deliberately_public() -> None:
    """A route with no role and no entry in PUBLIC is an unguarded endpoint."""
    unguarded = {(method, path) for method, path, role in _routes() if role is None}

    assert unguarded <= PUBLIC, f"unguarded endpoints not declared public: {sorted(unguarded - PUBLIC)}"


def test_only_the_identity_endpoint_is_role_agnostic() -> None:
    """Anything else that merely identifies the caller has skipped a role check."""
    agnostic = {(method, path) for method, path, role in _routes() if role == "authenticated"}

    assert agnostic == AUTHENTICATED_ONLY


def test_reading_history_monitoring_and_organizations_is_open_to_viewers() -> None:
    """The product model gives viewers read access; it once required an admin."""
    roles = {(method, path): role for method, path, role in _routes()}

    for method, path in [
        ("GET", "/api/v1/organizations"),
        ("GET", "/api/v1/organizations/{organization_id}"),
        ("GET", "/api/v1/organizations/{organization_id}/objects"),
        ("GET", "/api/v1/organizations/{organization_id}/objects/{logical_object_id}/versions"),
        ("GET", "/api/v1/organizations/{organization_id}/monitoring"),
        ("GET", "/api/v1/organizations/{organization_id}/monitoring/{session_id}"),
        ("GET", "/api/v1/organizations/{organization_id}/snapshots"),
    ]:
        assert roles.get((method, path)) == "viewer", f"{method} {path} should be readable by a viewer"


def test_running_a_snapshot_is_an_operator_action() -> None:
    """Operators run manual backups; they do not administer credentials."""
    roles = {(method, path): role for method, path, role in _routes()}

    assert roles.get(("POST", "/api/v1/organizations/{organization_id}/snapshots")) == "operator"


def test_credential_and_onboarding_changes_require_an_administrator() -> None:
    """Anything touching credentials, schedules, or onboarding stays restricted."""
    roles = {(method, path): role for method, path, role in _routes()}

    for method, path in [
        ("POST", "/api/v1/organizations"),
        ("PATCH", "/api/v1/organizations/{organization_id}"),
        ("PUT", "/api/v1/organizations/{organization_id}/service-token"),
        ("POST", "/api/v1/organizations/{organization_id}/verify"),
        ("POST", "/api/v1/organizations/{organization_id}/webhook-secret/rotate"),
        ("GET", "/api/v1/users"),
        ("POST", "/api/v1/users"),
        ("GET", "/api/v1/ai/settings"),
        ("PUT", "/api/v1/ai/settings"),
    ]:
        assert roles.get((method, path)) == "administrator", f"{method} {path} should require an administrator"


def test_account_endpoints_are_open_to_every_signed_in_role() -> None:
    """Every user manages their own account, whatever their role."""
    account = [(method, path, role) for method, path, role in _routes() if path.startswith("/api/v1/account")]

    assert account, "expected account endpoints"
    for method, path, role in account:
        assert role == "viewer", f"{method} {path} should be reachable by any signed-in user"
