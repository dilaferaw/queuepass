from fastapi import FastAPI

from queuepass.core.config import settings
from queuepass.core.db import check_db
from queuepass.core.redis import check_redis

app = FastAPI(title=settings.APP_NAME, debug=settings.DEBUG)


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
