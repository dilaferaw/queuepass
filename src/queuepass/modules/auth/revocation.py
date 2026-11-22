"""Redis-backed JWT revocation store.

Application layer, not ``core/``: auth owns user sessions, and Increment 10
(admin-triggered fraud revocation) will import from this module rather than
reaching into a shared util.

Two independent patterns, each covering a case the other cannot:

* **JTI denylist** — single-token logout. Store ``revoked_jti:<jti>`` for the
  remainder of the token's lifetime. Memory cost O(number of logged-out
  tokens still within their original TTL).
* **User cutoff** — logout-everywhere. Store ``user_cutoff:<user_id>`` as the
  epoch second of the logout; any token whose ``iat`` predates that epoch is
  rejected. Memory cost O(number of users who logged out everywhere and are
  still within one JWT lifetime of that logout).

The store does I/O only. Policy (which user, what TTL, when) lives in
``AuthService`` — the store does not read ``JWT_EXPIRE_MINUTES`` or anything
else about tokens.

Keys are literals here rather than in ``core/config.py``: one place, easy to
grep, and they are not operator-tunable knobs.
"""

from redis.asyncio import Redis

_JTI_PREFIX = "revoked_jti:"
_CUTOFF_PREFIX = "user_cutoff:"


class RevocationStore:
    """Redis-backed JWT revocation. Two key patterns:

      - JTI denylist (single-token logout): SETEX ``revoked_jti:<jti>`` <ttl> 1
      - User cutoff (logout-all):            SETEX ``user_cutoff:<user_id>`` <ttl> <epoch>

    ``user_id`` is the canonical hyphenated ``str(UUID)`` — matching the ``sub``
    claim of the access token, so the same string flows from token to Redis
    key without re-parsing on the read path.
    """

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def revoke_jti(self, jti: str, ttl_seconds: int) -> None:
        """Mark ``jti`` revoked for ``ttl_seconds``.

        No-op when ``ttl_seconds <= 0``: the token is already past its ``exp``,
        so the ``exp`` check alone rejects it. Storing it would only waste
        memory until eviction, and ``SETEX`` with a non-positive TTL errors on
        the server — this guard turns both problems into a no-op.
        """
        if ttl_seconds <= 0:
            return
        await self._redis.setex(f"{_JTI_PREFIX}{jti}", ttl_seconds, "1")

    async def is_jti_revoked(self, jti: str) -> bool:
        return bool(await self._redis.exists(f"{_JTI_PREFIX}{jti}"))

    async def set_user_cutoff(
        self, user_id: str, cutoff_epoch: int, ttl_seconds: int
    ) -> None:
        """Record ``cutoff_epoch`` as ``user_id``'s invalidation horizon.

        Any token whose ``iat < cutoff_epoch`` must be rejected on its next
        authenticated request. No-op when ``ttl_seconds <= 0`` (same reasoning
        as ``revoke_jti``).
        """
        if ttl_seconds <= 0:
            return
        await self._redis.setex(
            f"{_CUTOFF_PREFIX}{user_id}", ttl_seconds, str(cutoff_epoch)
        )

    async def get_user_cutoff(self, user_id: str) -> int | None:
        raw = await self._redis.get(f"{_CUTOFF_PREFIX}{user_id}")
        if raw is None:
            return None
        return int(raw)
