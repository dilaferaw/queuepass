"""Data-access layer for ``User``.

Strict contract per the increment spec:
  * This is the ONLY place that issues SQL against ``users``.
  * No business logic — no hashing, no validation, no exception raising.
    Those live in ``service.py``.

The protocol ``UserRepositoryProtocol`` is what ``AuthService`` depends on. It
exists so that ``tests/unit/test_auth_service.py`` can drop in an in-memory
fake and mypy still checks the fake against the real contract. The concrete
``UserRepository`` structurally satisfies the protocol — no inheritance needed.
"""

import uuid
from typing import Protocol

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from queuepass.modules.auth.models import User


class UserRepositoryProtocol(Protocol):
    """Structural type the service depends on.

    Deliberately async-only and CRUD-minimal. Adding a method here forces every
    fake/test double to implement it, which is exactly the feedback we want.
    """

    async def get_by_id(self, user_id: uuid.UUID) -> User | None: ...
    async def get_by_email(self, email: str) -> User | None: ...
    async def get_by_username(self, username: str) -> User | None: ...
    async def add(self, user: User) -> User: ...


class UserRepository:
    """SQLModel-backed implementation. Injected with a request-scoped session."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        # ``session.exec`` is SQLModel's extension over SQLAlchemy's AsyncSession:
        # it accepts a ``select(User)`` and returns a ``ScalarResult`` whose
        # ``.first()`` yields a ``User`` instance (not a Row tuple).
        result = await self.session.exec(select(User).where(User.id == user_id))
        return result.first()

    async def get_by_email(self, email: str) -> User | None:
        # Caller is responsible for lowercasing before calling us — we do not
        # normalise here, so the SQL stays a trivial equality and the DB index
        # on ``email`` is usable as-is.
        result = await self.session.exec(select(User).where(User.email == email))
        return result.first()

    async def get_by_username(self, username: str) -> User | None:
        result = await self.session.exec(select(User).where(User.username == username))
        return result.first()

    async def add(self, user: User) -> User:
        """Persist and return the now-populated row.

        ``flush`` emits the INSERT but leaves the transaction open — commit is
        the session owner's job (FastAPI's request scope commits on success via
        the endpoint's implicit session lifecycle). ``refresh`` pulls back the
        server-generated columns: ``id``, ``created_at``, ``updated_at``.
        """
        self.session.add(user)
        await self.session.flush()
        await self.session.refresh(user)
        return user
