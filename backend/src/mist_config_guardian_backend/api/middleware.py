"""ASGI middleware applied to every route."""

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

AS_OF_HEADER = b"x-config-guardian-as-of"
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
HISTORICAL_WRITE_DETAIL = "Write operations are disabled while viewing a historical point in time"


class HistoricalContextGuard:
    """Refuse a change to an organization's state while the client is browsing its past.

    The browser shell sends the as-of header whenever the time-travel bar is
    not at "now". The refusal lives here rather than in a per-route
    dependency: a dependency protects only the routes that remember to declare
    it, and the one that existed was declared by none. Answering before routing
    also means the rule covers organization routes added later.

    Only organization state is guarded. Signing out, acknowledging a
    notification, or changing one's own password is not a write derived from a
    reconstructed past, and refusing them would leave a server session live
    behind a client that believes it signed out.
    """

    def __init__(self, app: ASGIApp, *, prefix: str) -> None:
        self.app = app
        self._organizations = f"{prefix.rstrip('/')}/organizations"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Answer 409 for an unsafe method against organization state under the as-of header."""
        if (
            scope["type"] == "http"
            and scope["method"] in _UNSAFE_METHODS
            and self._guards(scope["path"])
            and _carries_as_of(scope)
        ):
            response = JSONResponse({"detail": HISTORICAL_WRITE_DETAIL}, status_code=409)
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)

    def _guards(self, path: str) -> bool:
        """Organization routes, except the notification feed, which is per member and not history."""
        if path != self._organizations and not path.startswith(self._organizations + "/"):
            return False
        segments = path[len(self._organizations) :].strip("/").split("/")
        # /organizations/{id}/notifications[/...]
        return segments[1:2] != ["notifications"]


def _carries_as_of(scope: Scope) -> bool:
    return any(name == AS_OF_HEADER and value.strip() for name, value in scope.get("headers", []))
