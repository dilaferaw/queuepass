from fastapi import FastAPI

from queuepass.core.config import settings
from queuepass.core.db import check_db
from queuepass.core.redis import check_redis
from queuepass.modules.auth.router import router as auth_router
from queuepass.modules.events.router import router as events_router

app = FastAPI(title=settings.APP_NAME, debug=settings.DEBUG)

# Auth routes live under ``/api/v1/auth`` (prefix from settings, tag for
# Swagger grouping). Version in the URL is a deliberate choice for a public
# API: a future incompatible change ships as ``/api/v2/auth`` without breaking
# old clients mid-ticketing-season.
app.include_router(
    auth_router,
    prefix=f"{settings.API_V1_PREFIX}/auth",
    tags=["auth"],
)
# Events routes live under ``/api/v1/events`` (Increment 3: create + read the
# Event/TicketType/Section/Seat domain). Prefix from settings keeps the
# versioning consistent with the auth module.
app.include_router(
    events_router,
    prefix=f"{settings.API_V1_PREFIX}/events",
    tags=["events"],
)


@app.get("/health")
async def health() -> dict[str, object]:
    db_ok = await check_db()
    redis_checks = await check_redis()

    status = "ok" if db_ok and all(redis_checks.values()) else "degraded"

    return {
        "status": status,
        "checks": {
            "db": db_ok,
            "revocation": redis_checks["revocation"],
            "locks": redis_checks["locks"],
        },
    }
