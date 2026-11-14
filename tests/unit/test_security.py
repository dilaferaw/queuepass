"""Unit tests for ``core/security``.

No DB, no FastAPI. Every assertion here exercises a pure function against
real pyjwt/pwdlib, so a green run means the primitives we build the whole
auth flow on are behaving as we expect — independently of whether the DB
wiring is correct.
"""

import base64
import json

import jwt
import pytest

from queuepass.core.config import settings
from queuepass.core.security import (
    create_access_token,
    decode_token,
    hash_password,
    verify_password,
)


def test_password_hash_roundtrip() -> None:
    # The most basic property: what we store verifies against the original
    # password. If this fails, no login can succeed.
    hashed = hash_password("hunter2!")
    assert verify_password("hunter2!", hashed) is True


def test_password_hash_wrong_password() -> None:
    hashed = hash_password("hunter2!")
    assert verify_password("hunter3!", hashed) is False


def test_password_hash_salted() -> None:
    # Argon2 embeds a fresh random salt per hash, so hashing the same password
    # twice yields different PHC strings. Both must still verify.
    first = hash_password("hunter2!")
    second = hash_password("hunter2!")
    assert first != second
    assert verify_password("hunter2!", first) is True
    assert verify_password("hunter2!", second) is True


def test_jwt_encode_decode_roundtrip() -> None:
    token = create_access_token(42)
    claims = decode_token(token)

    # RFC 7519: ``sub`` is a StringOrURI. Assert the type explicitly — this is
    # exactly the bug most JWT tutorials hit on their first interop test.
    assert claims["sub"] == "42"
    assert isinstance(claims["sub"], str)
    assert claims["type"] == "access"


def test_jwt_expired_raises() -> None:
    # ``expires_minutes=-1`` puts exp in the past, so PyJWT's exp check fires.
    token = create_access_token(1, expires_minutes=-1)
    with pytest.raises(jwt.ExpiredSignatureError):
        decode_token(token)


def test_jwt_wrong_secret_raises() -> None:
    # Sign with a totally different key; decode with the configured key must
    # fail signature verification. This is what stops someone forging tokens
    # by reading a leaked claims structure but not the secret.
    now = 1_700_000_000
    forged = jwt.encode(
        {
            "sub": "1",
            "iat": now,
            "exp": now + 3600,
            "jti": "forged",
            "type": "access",
        },
        # Any HMAC key >=32 bytes — deliberately DIFFERENT from settings.JWT_SECRET_KEY
        # so signature verification fails, but long enough that PyJWT does not
        # emit its InsecureKeyLengthWarning.
        "a-different-secret-key-that-is-32-bytes-long-at-least", 
        algorithm="HS256",
    )
    with pytest.raises(jwt.InvalidTokenError):
        decode_token(forged)


def test_jwt_alg_confusion_rejected() -> None:
    # Algorithm-confusion attack: build an unsigned (alg=none) token and check
    # that decode_token rejects it. Our pinning of algorithms=["HS256"] is what
    # makes this fail closed instead of accepting the token as valid.
    def b64(part: dict[str, object]) -> str:
        raw = json.dumps(part, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = b64({"alg": "none", "typ": "JWT"})
    payload = b64(
        {
            "sub": "1",
            "iat": 1_700_000_000,
            "exp": 4_000_000_000,
            "jti": "x",
            "type": "access",
        }
    )
    unsigned = f"{header}.{payload}."

    with pytest.raises(jwt.InvalidTokenError):
        decode_token(unsigned)


def test_jwt_type_claim_is_access() -> None:
    assert decode_token(create_access_token(7))["type"] == "access"


def test_jwt_jti_present_and_unique() -> None:
    # Uniqueness of jti is the precondition for Increment 2's logout/revoke:
    # without it, revoking "this token" is meaningless.
    first = decode_token(create_access_token(1))["jti"]
    second = decode_token(create_access_token(1))["jti"]
    assert isinstance(first, str) and first
    assert isinstance(second, str) and second
    assert first != second


def test_jwt_uses_configured_algorithm() -> None:
    # Redundant with the roundtrip test, but pins the invariant that the
    # algorithm comes from settings — a change to JWT_ALGORITHM should not
    # silently be ignored by the encode side.
    token = create_access_token(1)
    header = jwt.get_unverified_header(token)
    assert header["alg"] == settings.JWT_ALGORITHM
