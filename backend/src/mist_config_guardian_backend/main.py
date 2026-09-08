"""FastAPI application entry point."""

from typing import Any

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.types import Lifespan

from mist_config_guardian_backend.api.middleware import HistoricalContextGuard
from mist_config_guardian_backend.api.openapi import DESCRIPTION, TAGS, apply_security_schemes
from mist_config_guardian_backend.api.router import router
from mist_config_guardian_backend.config import Settings, get_settings
from mist_config_guardian_backend.database import DatabaseManager, create_lifespan


class ConfigGuardianApp(FastAPI):
    """FastAPI application that publishes a fully described API contract.

    The generator only discovers security schemes expressed as dependencies. The
    cookie session is resolved from the request inside ``get_current_user``, so
    it is invisible to the generator and is described here instead; leaving it
    out would understate how a browser authenticates.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        lifespan: Lifespan["ConfigGuardianApp"],
    ) -> None:
        self._app_settings = settings
        super().__init__(
            title=settings.app_name,
            version=settings.app_version,
            summary="Configuration history, point-in-time recovery, and impact monitoring for Juniper Mist.",
            description=DESCRIPTION,
            openapi_tags=TAGS,
            debug=settings.debug,
            docs_url="/docs" if settings.environment != "production" else None,
            redoc_url=None,
            lifespan=lifespan,
        )

    def openapi(self) -> dict[str, Any]:
        """Return the generated document with the cookie session described."""
        # apply_security_schemes is idempotent and mutates the cached document
        # in place, so repeated calls stay cheap and cannot duplicate entries.
        return apply_security_schemes(super().openapi(), self._app_settings)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application with explicit settings for testability."""
    app_settings = settings or get_settings()
    app = ConfigGuardianApp(app_settings, lifespan=create_lifespan(app_settings))
    app.state.database = DatabaseManager(app_settings)
    # Outermost, so a historical write is refused before it reaches anything.
    app.add_middleware(HistoricalContextGuard)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=app_settings.parsed_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(router, prefix=app_settings.api_v1_prefix)
    return app


app = create_app()


def run() -> None:
    """Run the development server."""
    uvicorn.run(
        "mist_config_guardian_backend.main:app",
        host="0.0.0.0",  # noqa: S104
        port=8000,
        reload=get_settings().debug,
    )
