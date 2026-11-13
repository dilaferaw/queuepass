from redis.asyncio import Redis

from queuepass.core.config import settings

revocation_redis = Redis.from_url(settings.REDIS_REVOCATION_URL, decode_responses=True)
locks_redis = Redis.from_url(settings.REDIS_LOCKS_URL, decode_responses=True)


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
