"""End-to-end auth tests — real app over ASGI, real Postgres.

These are the contract tests: they prove the wiring (router → service → repo →
DB) matches what the spec (§6) and DoD (§9) promise. The correctness of the
rules themselves is covered by ``tests/unit/test_auth_service.py``; here we
care that HTTP statuses, bodies, and the JWT pipeline behave on the wire.

The users table is truncated before every e2e test by the autouse fixture in
``tests/conftest.py`` — see the comment there.
"""

import uuid
from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta

import jwt
from httpx import AsyncClient

from queuepass.core.config import settings

# --- helpers -----------------------------------------------------------------


def _register_body(
    *,
    email: str,
    username: str,
    password: str = "hunter2!",
    first_name: str = "Alice",
    last_name: str = "Liddell",
    birthdate: str = "2000-01-01",
) -> dict[str, str]:
    """Build a well-formed ``UserCreate`` JSON body.

    Centralised so that if a future field becomes required at registration,
    exactly one helper needs updating — not every test that POSTs /register.
    """
    return {
        "email": email,
        "username": username,
        "password": password,
        "first_name": first_name,
        "last_name": last_name,
        "birthdate": birthdate,
    }


def _make_expired_token(user_id: uuid.UUID) -> str:
    # We cannot mint an already-expired token through the service (it reads the
    # real TTL), so forge one directly here. Signed with the real key so the
    # only thing wrong with it is ``exp`` — this isolates the expiry path.
    # ``sub`` is str(uuid) per RFC 7519 StringOrURI (same shape as production).
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "iat": int((now - timedelta(hours=2)).timestamp()),
        "exp": int((now - timedelta(hours=1)).timestamp()),
        "jti": "expired-for-test",
        "type": "access",
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


# --- register ----------------------------------------------------------------


async def test_register_returns_201_and_user(
    client: AsyncClient,
    unique_email: Callable[[], str],
    unique_username: Callable[[], str],
) -> None:
    response = await client.post(
        "/api/v1/auth/register",
        json=_register_body(email=unique_email(), username=unique_username()),
    )
    assert response.status_code == 201

    body = response.json()
    # The public projection must be safe: no password material, ever.
    assert "password_hash" not in body
    assert "password" not in body
    # And the fields the client needs must be there — including the new
    # required ones and the derived ``age``.
    assert {
        "id",
        "email",
        "username",
        "first_name",
        "last_name",
        "birthdate",
        "age",
        "is_active",
        "created_at",
    } <= body.keys()
    assert body["first_name"] == "Alice"
    assert body["last_name"] == "Liddell"
    assert body["birthdate"] == "2000-01-01"
    assert body["is_active"] is True
    # Age is derived, not stored. Sanity-check it: born 2000-01-01, so
    # definitely 24+ by now. (If this ever fails, either the epoch of the test
    # environment is wrong or the age math is broken.)
    assert isinstance(body["age"], int)
    assert body["age"] >= 24


async def test_register_duplicate_email_409(
    client: AsyncClient,
    registered_user: dict[str, object],
) -> None:
    # Reuse the fixture's email but pick a fresh username — the email collision
    # is the only thing this test isolates.
    response = await client.post(
        "/api/v1/auth/register",
        json=_register_body(
            email=str(registered_user["email"]),
            username="someone-else",
        ),
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "Email already registered"


async def test_register_duplicate_username_409(
    client: AsyncClient,
    registered_user: dict[str, object],
) -> None:
    response = await client.post(
        "/api/v1/auth/register",
        json=_register_body(
            email="someone-else@example.com",
            username=str(registered_user["username"]),
        ),
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "Username already taken"


async def test_register_short_password_422(
    client: AsyncClient,
    unique_email: Callable[[], str],
    unique_username: Callable[[], str],
) -> None:
    # ``min_length=8`` on ``UserCreate`` — FastAPI/pydantic returns 422 before
    # the router is invoked, so this is testing the schema, not the endpoint.
    response = await client.post(
        "/api/v1/auth/register",
        json=_register_body(
            email=unique_email(),
            username=unique_username(),
            password="short",
        ),
    )
    assert response.status_code == 422


async def test_register_invalid_email_422(
    client: AsyncClient,
    unique_username: Callable[[], str],
) -> None:
    # EmailStr validation — same 422-before-handler story.
    response = await client.post(
        "/api/v1/auth/register",
        json=_register_body(email="not-an-email", username=unique_username()),
    )
    assert response.status_code == 422


async def test_register_future_birthdate_422(
    client: AsyncClient,
    unique_email: Callable[[], str],
    unique_username: Callable[[], str],
) -> None:
    # ``UserCreate._birthdate_not_in_future`` rejects nonsense birthdates.
    # Tomorrow is a convenient, always-in-the-future choice — avoids the
    # calendar-math edge cases of "next month" / "next year".
    tomorrow = (date.today() + timedelta(days=1)).isoformat()
    response = await client.post(
        "/api/v1/auth/register",
        json=_register_body(
            email=unique_email(),
            username=unique_username(),
            birthdate=tomorrow,
        ),
    )
    assert response.status_code == 422


# --- login -------------------------------------------------------------------


async def test_login_returns_token(
    client: AsyncClient,
    registered_user: dict[str, object],
) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        data={
            "username": registered_user["email"],
            "password": registered_user["password"],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]


async def test_login_wrong_password_401(
    client: AsyncClient,
    registered_user: dict[str, object],
) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        data={"username": registered_user["email"], "password": "wrong"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect email or password"


async def test_login_unknown_email_401(client: AsyncClient) -> None:
    # Same status AND same detail string as wrong-password — user-enumeration
    # defense at the HTTP layer, mirroring the service-level guarantee.
    response = await client.post(
        "/api/v1/auth/login",
        data={"username": "nobody@example.com", "password": "hunter2!"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect email or password"


# --- me ----------------------------------------------------------------------


async def test_me_with_valid_token_200(
    client: AsyncClient,
    registered_user: dict[str, object],
    auth_headers: dict[str, str],
) -> None:
    response = await client.get("/api/v1/auth/me", headers=auth_headers)
    assert response.status_code == 200

    body = response.json()
    assert "password_hash" not in body
    assert body["email"] == registered_user["email"]
    assert body["username"] == registered_user["username"]
    assert body["first_name"] == registered_user["first_name"]
    assert body["last_name"] == registered_user["last_name"]
    assert body["birthdate"] == registered_user["birthdate"]
    assert isinstance(body["age"], int)


async def test_me_without_token_401(client: AsyncClient) -> None:
    # OAuth2PasswordBearer short-circuits with 401 when Authorization is absent.
    response = await client.get("/api/v1/auth/me")
    assert response.status_code == 401


async def test_me_with_garbage_token_401(client: AsyncClient) -> None:
    response = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer not-a-real-jwt"},
    )
    assert response.status_code == 401


async def test_me_with_expired_token_401(
    client: AsyncClient,
    registered_user: dict[str, object],
) -> None:
    # ``registered_user["id"]`` is the JSON string form of the UUID; convert
    # back to a ``uuid.UUID`` so this helper stays type-honest. The conversion
    # also documents the wire contract: ids on the API are UUID strings.
    token = _make_expired_token(uuid.UUID(str(registered_user["id"])))
    response = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
