# Mist Config Guardian backend

FastAPI API and Celery workers for configuration history, point-in-time restore,
and post-change impact monitoring.

## Development

```bash
uv sync
uv run pytest
uv run ruff check .
uv run ty check src
uv run mist-config-guardian
```