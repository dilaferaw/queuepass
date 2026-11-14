"""Unit tests for ``AuthService`` — pure logic, no DB, no FastAPI.

The point of this file is to prove the layered design actually buys us
testability. ``FakeUserRepository`` is a 15-line dict-backed fake; it is the
only "infrastructure" these tests need. If the service ever regresses to
importing ``fastapi`` or a ``Session``, the fake would not compile/work —
which is the discipline we want.

The fake structurally implements ``UserRepositoryProtocol`` from
``repository.py``; no inheritance, no monkeypatching.
"""

import uuid
from collections.abc import Iterator
from datetime import date

import pytest

from queuepass.core.security import decode_token, verify_password
from queuepass.modules.auth.models import User
from queuepass.modules.auth.service import (
    AuthService,
    EmailTakenError,
    InvalidCredentialsError,
    UsernameTakenError,
)


class FakeUserRepository:
    """In-memory ``UserRepositoryProtocol`` implementation for unit tests."""

    def __init__(self) -> None:
        # Keyed by UUID, mirroring the concrete repo. No ``_next_id`` counter:
        # ``User.id`` is a ``default_factory=uuid4`` field, so it is already
        # populated when the service constructs the User. The fake just stores
        # the object as-is — no flush/refresh simulation needed.
        self._users: dict[uuid.UUID, User] = {}

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        return self._users.get(user_id)

    async def get_by_email(self, email: str) -> User | None:
        for user in self._users.values():
            if user.email == email:
                return user
        return None

    async def get_by_username(self, username: str) -> User | None:
        for user in self._users.values():
            if user.username == username:
                return user
        return None

    async def add(self, user: User) -> User:
        # With UUID ids, ``user.id`` is already set at construction. We only
        # need to store the object — the real repo's flush+refresh only adds
        # server-default columns like ``created_at``, which the fake does not
        # simulate (default_factory handles them here too).
        self._users[user.id] = user
        return user


@pytest.fixture
def service() -> Iterator[AuthService]:
    yield AuthService(FakeUserRepository())


# Shared values for the required keyword-only fields. Pulled out so each test
# body can stay focused on the assertion it is actually making, rather than
# repeating boilerplate.
_DOB = date(1990, 1, 1)
_EXTRA = {
    "first_name": "Alice",
    "last_name": "Liddell",
    "birthdate": _DOB,
}


# --- register ----------------------------------------------------------------


async def test_register_success(service: AuthService) -> None:
    user = await service.register("a@b.co", "alice", "hunter2!", **_EXTRA)
    assert user.id is not None
    assert user.email == "a@b.co"
    assert user.username == "alice"
    assert user.first_name == "Alice"
    assert user.last_name == "Liddell"
    assert user.birthdate == _DOB
    # Critical invariant: the persisted hash must NOT be the plaintext.
    assert user.password_hash != "hunter2!"
    # And it must be a real hash that verifies against the plaintext.
    assert verify_password("hunter2!", user.password_hash) is True


async def test_register_duplicate_email_raises_email_taken(service: AuthService) -> None:
    await service.register("a@b.co", "alice", "hunter2!", **_EXTRA)
    with pytest.raises(EmailTakenError):
        await service.register("a@b.co", "bob", "hunter2!", **_EXTRA)


async def test_register_duplicate_username_raises_username_taken(
    service: AuthService,
) -> None:
    await service.register("a@b.co", "alice", "hunter2!", **_EXTRA)
    with pytest.raises(UsernameTakenError):
        await service.register("c@d.co", "alice", "hunter2!", **_EXTRA)


async def test_register_email_lowercased(service: AuthService) -> None:
    # Mixed-case input is normalised at the service boundary, so callers can
    # query by the lowercased form afterwards.
    user = await service.register("Foo@BAR.com", "alice", "hunter2!", **_EXTRA)
    assert user.email == "foo@bar.com"


# --- authenticate ------------------------------------------------------------


async def test_authenticate_success(service: AuthService) -> None:
    await service.register("a@b.co", "alice", "hunter2!", **_EXTRA)
    user = await service.authenticate("a@b.co", "hunter2!")
    assert user.id is not None

    token = service.issue_token(user)
    claims = decode_token(token)
    assert claims["sub"] == str(user.id)


async def test_authenticate_wrong_password_raises_invalid_credentials(
    service: AuthService,
) -> None:
    await service.register("a@b.co", "alice", "hunter2!", **_EXTRA)
    with pytest.raises(InvalidCredentialsError):
        await service.authenticate("a@b.co", "not-the-password")


async def test_authenticate_unknown_email_raises_invalid_credentials(
    service: AuthService,
) -> None:
    # User-enumeration defense: same exception class as wrong-password. If
    # these diverged, an attacker could distinguish registered emails from
    # unregistered ones by which error the API raises.
    with pytest.raises(InvalidCredentialsError):
        await service.authenticate("nobody@x.co", "hunter2!")


async def test_authenticate_inactive_user_raises_invalid_credentials(
    service: AuthService,
) -> None:
    user = await service.register("a@b.co", "alice", "hunter2!", **_EXTRA)
    user.is_active = False
    with pytest.raises(InvalidCredentialsError):
        await service.authenticate("a@b.co", "hunter2!")
