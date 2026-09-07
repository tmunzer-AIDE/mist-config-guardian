"""Descriptive metadata for the generated OpenAPI document.

The generated document is the API contract other teams and the browser
application are written against, so the prose here is part of the deliverable
rather than decoration: it records the authorization model, the two credential
kinds, and the rules a client cannot infer from the schemas alone.
"""

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mist_config_guardian_backend.config import Settings

DESCRIPTION = """
Configuration history, point-in-time recovery, and post-change impact
monitoring for Juniper Mist.

## Authentication

Two mechanisms reach the same endpoints.

* **Browser sessions.** `POST /auth/login` sets an httpOnly session cookie and a
  readable CSRF cookie. Every unsafe request must echo the CSRF cookie in the
  `X-CSRF-Token` header. Sessions are revocable and appear under `/account/sessions`.
* **Bearer tokens.** The same login returns a short-lived access token for
  command-line and integration clients, sent as `Authorization: Bearer <token>`.

Accounts with an enrolled second factor receive an MFA challenge instead of a
session and must complete `POST /auth/login/mfa` before one is issued.

## Authorization

Three application roles nest: **viewer** reads history, changes, monitoring, and
health; **operator** additionally builds restore plans and runs snapshots;
**administrator** manages organizations, credentials, users, AI configuration,
and executes restores.

## Two kinds of Mist credential

The stored per-organization **service token is read-only** and is used only for
unattended backup, reconciliation, and monitoring. Every Mist **write** —
including a restore and its compensation — requires a freshly authenticated
administrator's delegated credential supplied with the request, so the change is
attributable to that administrator in Mist's own audit trail. The application
never escalates the service token and never falls back to it for a write.

## Point-in-time browsing

A client viewing a reconstructed past state sends `X-Config-Guardian-As-Of`.
Endpoints that write refuse such requests with `409`, so historical browsing
cannot produce a write derived from reconstructed state.

## Secrets

Values Mist returns as secrets are encrypted at rest and replaced with a mask in
every response, diff, export, log, notification, and AI prompt. A protected
value carries a keyed fingerprint so a comparison can tell an unchanged secret
from a changed one without revealing either.
"""

TAGS: list[dict[str, str]] = [
    {
        "name": "System",
        "description": "Liveness, readiness, and the aggregate operational health of every dependency.",
    },
    {
        "name": "Authentication",
        "description": "Sign-in, the second-factor challenge, passkey ceremonies, bootstrap, and sign-out.",
    },
    {
        "name": "Account",
        "description": (
            "The signed-in account's own profile, password, second factor, passkeys, and sessions. "
            "Available to every role for its own account."
        ),
    },
    {
        "name": "User Administration",
        "description": (
            "Invitations, role assignment, and activation. The last active administrator cannot be "
            "demoted or deactivated."
        ),
    },
    {
        "name": "Organizations",
        "description": (
            "Onboarding, read-only service-token verification and replacement, schedules, retention, "
            "and webhook secrets. A rotated webhook secret is returned exactly once."
        ),
    },
    {
        "name": "Overview",
        "description": "One purpose-built read model backing the Overview page and the navigation badges.",
    },
    {
        "name": "Snapshots",
        "description": "Initial, manual, and reconciliation snapshot runs with their coverage manifests.",
    },
    {
        "name": "Webhooks",
        "description": (
            "The public Mist webhook receiver. Deliveries are signature-verified and persisted before "
            "acknowledgement, then processed idempotently."
        ),
    },
    {
        "name": "Change Groups",
        "description": (
            "Administrator actions correlated by organization and audit identifier, with the object "
            "versions they produced, the devices they touched, and their measured impact."
        ),
    },
    {
        "name": "Configuration History",
        "description": (
            "Stable objects, their immutable version timelines, and deterministic structured comparison "
            "between any two versions."
        ),
    },
    {
        "name": "Point In Time",
        "description": "Timeline markers and reconstruction of an organization or site as it existed at an instant.",
    },
    {"name": "Search", "description": "Search across configuration objects, actors, audit identifiers, and sites."},
    {
        "name": "Restores",
        "description": (
            "Dependency-ordered restore planning, authorized execution, per-action progress, "
            "post-restore verification, and compensation after a failure."
        ),
    },
    {
        "name": "Approvals",
        "description": (
            "Two-person approval for restores that trigger organization policy. A requester cannot "
            "approve their own request, and any change to the plan invalidates the approval."
        ),
    },
    {
        "name": "Impact Monitoring",
        "description": (
            "Per-device monitoring windows with baseline and post-change service-level evidence, "
            "incidents, and confidence."
        ),
    },
    {"name": "Notifications", "description": "The in-application notification feed, unread counts, and read state."},
    {
        "name": "AI Assist",
        "description": (
            "Optional provider configuration and secret-safe diff summaries. Deterministic analysis is "
            "unaffected when AI is disabled or unreachable."
        ),
    },
    {"name": "Application Settings", "description": "Deployment-wide settings managed by local administrators."},
]


def apply_security_schemes(document: dict[str, Any], settings: "Settings") -> dict[str, object]:
    """Describe the cookie session alongside the bearer scheme FastAPI infers.

    FastAPI only discovers the bearer scheme, because that is the one expressed
    as a dependency. Cookie sessions are resolved from the request inside
    ``get_current_user``, so they are invisible to the generator and have to be
    declared here or the published contract would understate how a browser
    authenticates.
    """
    components = document.setdefault("components", {})
    schemes = components.setdefault("securitySchemes", {})
    schemes["SessionCookie"] = {
        "type": "apiKey",
        "in": "cookie",
        "name": settings.session_cookie_name,
        "description": (
            "Browser session issued by `POST /auth/login`. Unsafe methods must also send the "
            f"`{settings.csrf_cookie_name}` cookie value in the `{settings.csrf_header_name}` header."
        ),
    }
    schemes["CsrfToken"] = {
        "type": "apiKey",
        "in": "header",
        "name": settings.csrf_header_name,
        "description": "Double-submit CSRF token. Required on every unsafe method of a cookie session.",
    }

    # Every operation that already accepts the bearer scheme also accepts a
    # cookie session, so advertise both alternatives rather than only the one
    # the generator could see.
    for operations in document.get("paths", {}).values():
        for operation in operations.values():
            security = operation.get("security")
            if not security or not any("OAuth2PasswordBearer" in requirement for requirement in security):
                continue
            if not any("SessionCookie" in requirement for requirement in security):
                security.append({"SessionCookie": [], "CsrfToken": []})
    return document
