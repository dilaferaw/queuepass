"""Database engine, session factory, and base class.

Increment 1 note: the base class used to be SQLAlchemy's ``DeclarativeBase``.
It is now SQLModel, because the project asked for SQLModel as the model layer
in Increment 1. SQLModel is a thin layer over SQLAlchemy + Pydantic: the
resulting classes are real SQLAlchemy mapped classes AND Pydantic models,
so the same ``User`` object can be used as a row, as a request-body target,
and as a response model without duplicated field lists.

We keep the alias ``Base = SQLModel`` because ``migrations/env.py`` imports
``Base`` and uses ``Base.metadata`` to feed Alembic's autogenerate. Aliasing
means we did not have to rewrite that file's import.
"""

from collections.abc import AsyncIterator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession as SQLModelAsyncSession

from queuepass.core.config import settings

# SQLModel itself is the declarative base. All feature models subclass
# ``SQLModel`` with ``table=True``. Exposing it as ``Base`` keeps the
# existing ``from queuepass.core.db import Base`` contract intact.
Base = SQLModel


# ``create_async_engine`` is unchanged — SQLModel does not wrap the engine.
# ``echo=settings.DEBUG`` prints every SQL statement in dev; off in prod.
engine = create_async_engine(settings.DATABASE_URL, echo=settings.DEBUG)


# ``class_=SQLModelAsyncSession`` is the important line. It replaces SQLAlchemy's
# default ``AsyncSession`` with SQLModel's subclass, which adds ``.exec()``
# (accepts a ``select()`` and returns rows as model instances). ``expire_on_commit=False``
# keeps attribute values usable after ``commit()`` — without this, accessing
# ``user.id`` after the request-scoped commit would raise DetachedInstanceError.
async_session_factory = async_sessionmaker(
    engine,
    class_=SQLModelAsyncSession,
    expire_on_commit=False,
)


async def get_session() -> AsyncIterator[SQLModelAsyncSession]:
    """One unit of work per request: yield a session, commit on success, rollback on error.

    Why commit here and not in ``UserRepository.add`` (which only flushes)?
    Transactions are infrastructure, not business logic. Committing at the
    request boundary keeps every repository call inside the same atomic scope,
    so a future flow that touches multiple repos (e.g. register + create a
    welcome row) can still fail as a whole. Flush-in-repo + commit-at-session
    is the standard SQLAlchemy FastAPI pattern.

    The SQL trace that motivated this fix (during Increment 1 verification):
    without the ``commit()`` below, every ``POST /auth/register`` emitted its
    INSERT and then closed the session, which issued a ROLLBACK. The endpoint
    still returned 201 because the response was serialised from in-memory ORM
    state — but the row never reached the DB.

    The ``except`` branch rolls back on any exception. Without it, a request
    that failed after partial flushes would commit whatever had already been
    flushed, which is exactly what transactions exist to prevent.

    ``expire_on_commit=False`` on the session factory keeps ORM attributes
    usable after ``commit()`` — needed because FastAPI serialises the
    ``response_model`` (which reads attributes off the returned ORM instance)
    before this dependency's teardown returns.
    """
    async with async_session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        else:
            await session.commit()


async def check_db() -> bool:
    """Cheap liveness probe for the /health endpoint."""
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
