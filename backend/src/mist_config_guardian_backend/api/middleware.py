"""ASGI middleware applied to every route."""

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

AS_OF_HEADER = b"x-config-guardian-as-of"
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
HISTORICAL_WRITE_DETAIL = "Write operations are disabled while viewing a historical point in time"


class HistoricalContextGuard:
    """Refuse any write submitted while the client is browsing a past point in time.

    The browser shell sends the as-of header whenever the time-travel bar is
    not at "now". The refusal has to live here rather than in a per-route
    dependency: a dependency protects only the routes that remember to declare
    it, and the one that existed was declared by none. Answering before routing
    also means the rule covers routes added later without anyone thinking of it.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Answer 409 for an unsafe method carrying the as-of header."""
        if scope["type"] == "http" and scope["method"] in _UNSAFE_METHODS and _carries_as_of(scope):
            response = JSONResponse({"detail": HISTORICAL_WRITE_DETAIL}, status_code=409)
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


def _carries_as_of(scope: Scope) -> bool:
    return any(name == AS_OF_HEADER and value.strip() for name, value in scope.get("headers", []))
