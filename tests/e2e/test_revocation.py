"""E2E tests for JWT revocation — real Redis (DB 0), real app.

Each test runs against the ASGI-transport client from ``conftest``; the
autouse ``_flush_revocation_redis_between_e2e_tests`` fixture empties DB 0
before and after each test, so revocation state cannot leak between tests.

Nothing here touches DB 1 (locks) or DB 2 (Celery) — revocation is DB 0 only.
"""

import asyncio
import uuid
from collections.abc import Callable

from httpx import AsyncClient

from queuepass.core.redis import revocation_redis
from queuepass.core.security import create_access_token


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _login(client: AsyncClient, email: str, password: str) -> str:
    r = await client.post(
        "/api/v1/auth/login",
        data={"username": email, "password": password},
    )
    assert r.status_code == 200, r.text
    return str(r.json()["access_token"])


async def test_logout_returns_204(client: AsyncClient, auth_headers: dict[str, str]) -> None:
    r = await client.post("/api/v1/auth/logout", headers=auth_headers)
    assert r.status_code == 204, r.text


async def test_logout_immediately_rejects_next_request(
    client: AsyncClient, auth_headers: dict[str, str]
) -> None:
    await client.post("/api/v1/auth/logout", headers=auth_headers)
    r = await client.get("/api/v1/auth/me", headers=auth_headers)
    assert r.status_code == 401


async def test_logout_is_idempotent(
    client: AsyncClient, auth_headers: dict[str, str]
) -> None:
    assert (await client.post("/api/v1/auth/logout", headers=auth_headers)).status_code == 204
    assert (await client.post("/api/v1/auth/logout", headers=auth_headers)).status_code == 204
    assert (await client.get("/api/v1/auth/me", headers=auth_headers)).status_code == 401


async def test_logout_with_expired_token_returns_204(
    client: AsyncClient, registered_user: dict[str, object]
) -> None:
    # A client retrying a logout it already succeeded at should not receive a
    # 401 that forces it to distinguish "expired" from "malformed". We accept
    # the expired case as an idempotent 204.
    user_id = uuid.UUID(str(registered_user["id"]))
    token = create_access_token(user_id, expires_minutes=-1)
    r = await client.post("/api/v1/auth/logout", headers=_bearer(token))
    assert r.status_code == 204, r.text


async def test_logout_with_garbage_token_returns_401(client: AsyncClient) -> None:
    r = await client.post("/api/v1/auth/logout", headers=_bearer("not-a-jwt"))
    assert r.status_code == 401


async def test_logout_without_token_returns_401(client: AsyncClient) -> None:
    r = await client.post("/api/v1/auth/logout")
    assert r.status_code == 401


async def test_logout_does_not_affect_other_sessions(
    client: AsyncClient, registered_user: dict[str, object]
) -> None:
    email = str(registered_user["email"])
    pw = str(registered_user["password"])
    a = await _login(client, email, pw)
    b = await _login(client, email, pw)
    assert (await client.post("/api/v1/auth/logout", headers=_bearer(a))).status_code == 204
    assert (await client.get("/api/v1/auth/me", headers=_bearer(a))).status_code == 401
    assert (await client.get("/api/v1/auth/me", headers=_bearer(b))).status_code == 200


async def test_logout_all_kills_all_previous_tokens(
    client: AsyncClient, registered_user: dict[str, object]
) -> None:
    email = str(registered_user["email"])
    pw = str(registered_user["password"])
    a = await _login(client, email, pw)
    b = await _login(client, email, pw)
    assert (await client.post("/api/v1/auth/logout-all", headers=_bearer(a))).status_code == 204
    assert (await client.get("/api/v1/auth/me", headers=_bearer(a))).status_code == 401
    assert (await client.get("/api/v1/auth/me", headers=_bearer(b))).status_code == 401


async def test_logout_all_requires_valid_token(client: AsyncClient) -> None:
    assert (await client.post("/api/v1/auth/logout-all")).status_code == 401


async def test_new_login_after_logout_all_works(
    client: AsyncClient, registered_user: dict[str, object]
) -> None:
    email = str(registered_user["email"])
    pw = str(registered_user["password"])
    a = await _login(client, email, pw)
    await client.post("/api/v1/auth/logout-all", headers=_bearer(a))
    # ``iat`` has 1-second resolution. Sleeping past the cutoff second avoids
    # a fresh login landing on the same epoch as the cutoff itself (where
    # ``iat < cutoff`` would be false, but ``iat == cutoff`` is also fine —
    # we only sleep to be defensive against clock slop).
    await asyncio.sleep(1.1)
    fresh = await _login(client, email, pw)
    assert (await client.get("/api/v1/auth/me", headers=_bearer(fresh))).status_code == 200


async def test_logout_all_does_not_affect_other_users(
    client: AsyncClient,
    registered_user: dict[str, object],
    unique_email: Callable[[], str],
    unique_username: Callable[[], str],
) -> None:
    # Second user, registered via the real endpoint (not the shared fixture,
    # which returns its credentials but only for user A).
    other_email = unique_email()
    other_username = unique_username()
    other_password = "hunter2!"
    r = await client.post(
        "/api/v1/auth/register",
        json={
            "email": other_email,
            "username": other_username,
            "password": other_password,
            "first_name": "Bob",
            "last_name": "Smith",
            "birthdate": "1990-05-05",
        },
    )
    assert r.status_code == 201, r.text

    a = await _login(client, str(registered_user["email"]), str(registered_user["password"]))
    b = await _login(client, other_email, other_password)
    await client.post("/api/v1/auth/logout-all", headers=_bearer(a))
    assert (await client.get("/api/v1/auth/me", headers=_bearer(a))).status_code == 401
    assert (await client.get("/api/v1/auth/me", headers=_bearer(b))).status_code == 200


async def test_revoked_key_uses_uuid_string(
    client: AsyncClient,
    registered_user: dict[str, object],
    auth_headers: dict[str, str],
) -> None:
    # Lock in the on-wire key shape: the cutoff key embeds ``str(user.id)``
    # (canonical hyphenated UUID), matching the token's ``sub`` claim.
    user_id = str(registered_user["id"])
    await client.post("/api/v1/auth/logout-all", headers=auth_headers)
    value = await revocation_redis.get(f"user_cutoff:{user_id}")
    assert value is not None, f"expected user_cutoff:{user_id} in DB 0"
