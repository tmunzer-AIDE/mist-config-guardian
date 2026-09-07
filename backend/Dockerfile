FROM python:3.13-slim AS runtime

COPY --from=ghcr.io/astral-sh/uv:0.11.25 /uv /usr/local/bin/uv

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

RUN useradd --create-home --uid 10001 guardian
USER guardian

EXPOSE 8000

CMD ["uvicorn", "mist_config_guardian_backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
