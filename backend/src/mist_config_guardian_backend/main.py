"""FastAPI application entry point."""

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from mist_config_guardian_backend.api.router import router
from mist_config_guardian_backend.config import Settings, get_settings
from mist_config_guardian_backend.database import DatabaseManager, create_lifespan


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application with explicit settings for testability."""
    app_settings = settings or get_settings()
    app = FastAPI(
        title=app_settings.app_name,
        version=app_settings.app_version,
        debug=app_settings.debug,
        docs_url="/docs" if app_settings.environment != "production" else None,
        redoc_url=None,
        lifespan=create_lifespan(app_settings),
    )
    app.state.database = DatabaseManager(app_settings)
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
