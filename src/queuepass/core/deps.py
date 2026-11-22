"""Cross-cutting FastAPI dependencies.

Increment 1 note — this is the ONE place where ``core`` imports a feature
module (``modules.auth``). ``get_current_user`` is a cross-module concern:
any authenticated endpoint in any future module will need it, so putting the
implementation here means we do not fan out imports of the auth module.
Per the increment spec ("deps is glue"), we allow this and do not generalise
yet. If a second core dependency needs auth, we will promote it to
``modules/auth/deps.py`` — but not today.
"""

import uuid

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from redis.asyncio import Redis
from sqlmodel.ext.asyncio.session import AsyncSession

from queuepass.core.config import settings
from queuepass.core.db import get_session
from queuepass.core.redis import get_revocation_redis
from queuepass.core.security import decode_token
from queuepass.modules.auth.models import User
from queuepass.modules.auth.repository import UserRepository
from queuepass.modules.auth.revocation import RevocationStore

# ``tokenUrl`` only exists so Swagger UI's "Authorize" button knows where to
# POST credentials. The path itself must match ``router.py``'s login route,
# so derive it from settings.API_V1_PREFIX rather than hardcoding — a future
# prefix bump (``/api/v2``) then updates both sides at once.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_PREFIX}/auth/login")


async def get_revocation_store(
    redis: Redis = Depends(get_revocation_redis),
) -> RevocationStore:
    """Compose a ``RevocationStore`` bound to the DB 0 client.

    The store is stateless — a new instance per request costs nothing, and it
    keeps the dependency graph explicit (no hidden singleton to reset between
    tests).
    """
    return RevocationStore(redis)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_session),
    revocation: RevocationStore = Depends(get_revocation_store),
) -> User:
    """Resolve the bearer token to an active ``User`` row.

    Failure modes are all collapsed to the same 401 + WWW-Authenticate header:
      * token absent (handled by OAuth2PasswordBearer before we run),
      * signature invalid / token malformed,
      * token expired,
      * ``type`` claim is not ``"access"`` (future refresh token misuse),
      * ``sub`` cannot be parsed as an int,
      * user row does not exist (deleted between issuance and now),
      * user is inactive (deactivated).

    Collapsing them prevents an attacker from learning *why* their token was
    rejected, which would otherwise leak e.g. whether a given user id exists.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        # HTTP spec (RFC 7235) requires this header on 401 so clients know to
        # re-authenticate rather than retry blindly.
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_token(token)
    except Exception:
        # Deliberately catch broadly: PyJWT's exception hierarchy is wider
        # than a single class (ExpiredSignatureError, InvalidSignatureError,
        # DecodeError, InvalidAlgorithmError, ...). All map to 401.
        # ``from None`` suppresses the chained PyJWT exception from the client-
        # facing traceback — internal decoder details are not the client's
        # business and would otherwise leak which failure path we hit.
        raise credentials_exception from None

    # ``type`` is a business claim, not something PyJWT can enforce — verify it
    # ourselves so a future refresh token cannot be used as an access token.
    if payload.get("type") != "access":
        raise credentials_exception

    # Extract the revocation-relevant claims. Narrowing to ``str``/``int``
    # simultaneously rejects malformed tokens and satisfies mypy strict — a
    # crafted token without ``jti``/``iat`` should hit the same 401 as a
    # deleted user, not a 500.
    jti = payload.get("jti")
    sub = payload.get("sub")
    iat = payload.get("iat")
    if not isinstance(jti, str) or not isinstance(sub, str) or not isinstance(iat, int):
        raise credentials_exception

    # Revocation checks run before the DB lookup — they are the whole point of
    # this feature, and a revoked token should not cost a Postgres round-trip.
    #   * JTI denylist catches single-token logout.
    #   * User cutoff catches logout-everywhere; ``iat < cutoff`` means "issued
    #     before the user invalidated all sessions". Compare against ``iat``
    #     (issue time), not ``exp`` (expiry): comparing against ``exp`` would let
    #     through tokens issued *after* the cutoff whose expiry predates it.
    if await revocation.is_jti_revoked(jti):
        raise credentials_exception

    cutoff = await revocation.get_user_cutoff(sub)
    if cutoff is not None and iat < cutoff:
        raise credentials_exception

    # ``sub`` is the uuid4 as a string (see ``core.security.create_access_token``).
    # A forged or garbled token whose ``sub`` is not UUID-shaped raises
    # ``ValueError`` here and is rejected with the same 401 — no info about why.
    try:
        user_id = uuid.UUID(sub)
    except (KeyError, TypeError, ValueError):
        raise credentials_exception from None

    user = await UserRepository(session).get_by_id(user_id)
    if user is None or not user.is_active:
        raise credentials_exception

    return user
