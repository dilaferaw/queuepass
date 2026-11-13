# Queuepass

FastAPI-based event ticketing backend with reserved seating, TTL'd seat holds, JWT auth with Redis-backed revocation, and Celery background jobs.

## Prerequisites

- `uv`
- `podman` or `docker` with Compose support

## Setup

```bash
podman compose up -d
cp .env.example .env
uv sync
uv run alembic upgrade head
uv run fastapi dev src/queuepass/main.py
```

`docker compose up -d` is equivalent if you are using Docker instead of Podman.

## Endpoints

- `GET /health` — dependency health check
- `GET /docs` — OpenAPI docs

## Tests

```bash
uv run pytest
```

Future business features live under `src/queuepass/modules/`.
