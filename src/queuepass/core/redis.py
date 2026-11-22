from redis.asyncio import Redis

from queuepass.core.config import settings

revocation_redis = Redis.from_url(settings.REDIS_REVOCATION_URL, decode_responses=True)
locks_redis = Redis.from_url(settings.REDIS_LOCKS_URL, decode_responses=True)


async def get_revocation_redis() -> Redis:
    """FastAPI dependency that hands out the revocation client (DB 0).

    ``Depends`` needs a callable; this thin wrapper is the callable. Returning
    the module-level client (rather than constructing one per request) is
    fine — ``Redis.from_url`` is lazy and the client is safe to share across
    the event loop, which uvicorn runs as a single loop per worker.
    """
    return revocation_redis


async def check_redis() -> dict[str, bool]:
    revocation = False
    locks = False

    try:
        revocation = bool(await revocation_redis.ping())
    except Exception:
        revocation = False

    try:
        locks = bool(await locks_redis.ping())
    except Exception:
        locks = False

    return {"revocation": revocation, "locks": locks}
