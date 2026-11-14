"""Pure security primitives: password hashing and JWT encode/decode.

Deliberately pure: no database access, no FastAPI imports, no global mutable
state beyond the password-hasher singleton. That makes this module trivially
unit-testable (see ``tests/unit/test_security.py``) and safe to reuse from
future CLI tools, Celery tasks, or gRPC handlers.
"""

import uuid
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
from pwdlib import PasswordHash

from queuepass.core.config import settings

# A single module-level hasher instance. Constructing ``PasswordHash.recommended()``
# per call would re-run argon2 parameter auto-detection every time — wasteful
# and a potential DoS surface. Argon2 params are stable for the process lifetime.
_password_hash = PasswordHash.recommended()


# A pre-computed hash of a fixed, throwaway string. Used by ``AuthService.authenticate``
# to run the same argon2 workload when the supplied email does not exist. Without
# this, a missing email returns in microseconds while a wrong password takes
# ~10-50ms (argon2 cost), which leaks account existence via response timing.
# Not exported; services import it from here only when they need it.
DUMMY_PASSWORD_HASH = _password_hash.hash("timing-equalizer-not-a-real-password")


def hash_password(plain: str) -> str:
    """Hash a plaintext password with argon2id.

    Returns a PHC-formatted string that embeds the algorithm, parameters,
    salt, and digest — e.g. ``$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>``.
    Self-contained: you do not need to store the salt separately.
    """
    return _password_hash.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Constant-time password check.

    Delegates to pwdlib, which uses argon2-cffi's ``verify`` — that routine
    performs the comparison with ``secrets.compare_digest`` internally. Never
    do ``plain == hashed`` yourself: string comparison short-circuits on the
    first differing byte and leaks password length/prefix via timing.
    """
    return _password_hash.verify(plain, hashed)


def create_access_token(user_id: uuid.UUID, *, expires_minutes: int | None = None) -> str:
    """Mint a signed access JWT for ``user_id``.

    Claims we set (all mandatory for our flow):
      * ``sub`` — user id as a string. Now that ids are UUIDs, this is
        ``str(uuid)`` (canonical hyphenated form). Still a *string* on the wire
        — RFC 7519 StringOrURI compliance is unchanged.
      * ``iat`` — issued-at, epoch seconds. Enables future "invalidate tokens
        issued before T0" logic in Increment 2 (user cutoff).
      * ``exp`` — expiry, epoch seconds. Standard JWT rule: server rejects
        after this moment (with optional clock-skew leeway).
      * ``jti`` — unique token id. Increment 2 will add JTIs to a Redis
        denylist on logout; without a unique id there is nothing to revoke.
      * ``type`` — "access". Reserved so future refresh tokens can carry
        ``type="refresh"`` and be rejected by the access-token verifier.

    ``expires_minutes`` is keyword-only and optional — tests pass ``-1`` to
    craft already-expired tokens; production callers omit it and get the
    configured TTL.
    """
    now = datetime.now(UTC)
    ttl = timedelta(
        minutes=settings.JWT_EXPIRE_MINUTES if expires_minutes is None else expires_minutes
    )
    payload = {
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "exp": int((now + ttl).timestamp()),
        "jti": uuid4().hex,
        "type": "access",
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict[str, object]:
    """Verify and decode a JWT. Raises on any failure.

    ``algorithms=[...]`` is pinned to exactly one algorithm. This is the
    alg-confusion defense: without pinning, an attacker can present a token
    with ``alg="none"`` (or ``alg="HS256"`` when we expect RS256) and, on
    naive verifiers, have it accepted. Pinning closes that hole outright.

    Signature, ``exp``, and (optionally) ``nbf``/``iat`` are validated by PyJWT.
    Callers that need business checks (``type == "access"``, user exists, active)
    do them on the returned dict.
    """
    return jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
    )
