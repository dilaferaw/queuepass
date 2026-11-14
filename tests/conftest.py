"""Pytest fixtures shared across unit and e2e tests.

The two categories use different strategies:
  * Unit tests never touch the DB — they inject in-memory fakes.
  * E2E tests hit the real FastAPI app over httpx/ASGI, which talks to the
    real Postgres container from docker-compose.

Anything DB-shaped here is therefore guarded so unit tests do not pay its cost.
"""

from collections.abc import AsyncIterator, Callable
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from queuepass.core.config import settings
from queuepass.main import app

# --- pure helpers -----------------------------------------------------------
# Random suffixes avoid cross-test collisions (and collisions with rows left
# over from a previous ``pytest`` session that crashed before cleanup). Tests
# use these by request, not automatically.


@pytest.fixture
def unique_email() -> Callable[[], str]:
    def _make() -> str:
        return f"user_{uuid4().hex[:8]}@example.com"

    return _make


@pytest.fixture
def unique_username() -> Callable[[], str]:
    def _make() -> str:
        return f"user_{uuid4().hex[:8]}"

    return _make


# --- HTTP client -------------------------------------------------------------


@pytest_asyncio.fixture
async def client() -> AsyncIterator[AsyncClient]:
    """ASGI-transport client: no real socket, but a full request/response cycle."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as async_client:
        yield async_client


# --- DB cleanup --------------------------------------------------------------
# Autouse, but gated to e2e. Unit tests run in-process against fakes and would
# only pay latency for a TRUNCATE they do not need. Location matters: spec §8
# forbids new files outside the target tree, so this lives in the shared
# conftest and filters by test path, rather than in tests/e2e/conftest.py.


@pytest_asyncio.fixture(autouse=True)
async def _clean_users_between_e2e_tests(request: pytest.FixtureRequest) -> AsyncIterator[None]:
    if "/tests/e2e/" not in str(request.node.path):
        yield
        return

    # TRUNCATE ... RESTART IDENTITY CASCADE gives us:
    #  * empty users table at test start,
    #  * ``id`` counter reset so tests asserting on ids are stable,
    #  * CASCADE so future FK tables (events, tickets) get wiped too —
    #    intentional: e2e tests share one DB and must not leak state.
    #
    # Why a fresh engine with NullPool instead of the module-level
    # ``async_session_factory``: pytest-asyncio creates a NEW event loop per
    # test. The module-level engine's pool caches connections that were created
    # on the PREVIOUS loop; handing one to the next test raises
    # ``RuntimeError: got Future attached to a different loop``. NullPool keeps
    # zero connections alive between calls, so each TRUNCATE opens, uses, and
    # closes a connection on the CURRENT loop. This is the standard recipe for
    # pytest-asyncio + SQLAlchemy-async. ``engine.begin()`` commits on exit, so
    # the TRUNCATE is durable (plain ``connect()`` would roll it back).
    engine = create_async_engine(settings.DATABASE_URL, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.execute(text("TRUNCATE users RESTART IDENTITY CASCADE"))
    finally:
        await engine.dispose()

    yield


# --- composed fixtures -------------------------------------------------------


@pytest_asyncio.fixture
async def registered_user(
    client: AsyncClient,
    unique_email: Callable[[], str],
    unique_username: Callable[[], str],
) -> dict[str, object]:
    """Create one user via the real /register endpoint and return its credentials.

    Returns a plain dict (not the response body) so tests can hold the plaintext
    password — the API never returns it. ``id`` is included so tests that need to
    mint tokens for this user (e.g. expiry test) do not have to look it up again.
    ``first_name``/``last_name``/``birthdate`` mirror what UserCreate requires;
    ``birthdate`` is fixed (2000-01-01) so any age assertion in tests is stable
    for the next several decades.
    """
    email = unique_email()
    username = unique_username()
    password = "hunter2!"
    first_name = "Alice"
    last_name = "Liddell"
    birthdate = "2000-01-01"

    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "username": username,
            "password": password,
            "first_name": first_name,
            "last_name": last_name,
            "birthdate": birthdate,
        },
    )
    assert response.status_code == 201, response.text

    return {
        "id": response.json()["id"],
        "email": email,
        "username": username,
        "password": password,
        "first_name": first_name,
        "last_name": last_name,
        "birthdate": birthdate,
    }


@pytest_asyncio.fixture
async def auth_headers(
    client: AsyncClient, registered_user: dict[str, object]
) -> dict[str, str]:
    """Log the ``registered_user`` in and return ``{"Authorization": "Bearer ..."}``.

    The OAuth2 password form field is named ``username`` but carries the email
    — this matches how real clients (and our own DoD curl) call /login.
    """
    response = await client.post(
        "/api/v1/auth/login",
        data={
            "username": registered_user["email"],
            "password": registered_user["password"],
        },
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}
