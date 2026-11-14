"""SQLModel table for users.

Why SQLModel instead of hand-written SQLAlchemy declarative: fields are declared
once and yield both the DB column AND the Pydantic validation. The router can
therefore return a ``User`` directly (fastapi serialises it via ``UserPublic``)
without us maintaining a parallel ``UserOut`` model.

The one area where SQLModel still needs raw SQLAlchemy is ``server_default``:
SQLModel's ``Field`` has no equivalent, so ``created_at``/``updated_at`` use
``sa_column=Column(..., server_default=func.now())``. To keep the ORM happy when
we construct a ``User`` before the flush, we ALSO give the fields Python-level
``default_factory`` — otherwise Pydantic would require them at __init__ time.
"""

import uuid
from datetime import UTC, date, datetime

from sqlalchemy import Column, Date, DateTime, String, func
from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    """Persisted user row.

    Column choices worth knowing:
      * ``email`` — String(320) is the max realistic email length (64 local +
        @ + 255 domain). ``unique=True`` gives us an application-level duplicate
        check; the DB enforces it too. We lowercase on write (in service.py), so
        the unique index is case-insensitive only by virtue of that invariant —
        no CITEXT/functional index needed for the MVP.
      * ``username`` — String(50). Same uniqueness story.
      * ``first_name`` / ``last_name`` — String(100). Required at register.
        Not unique (two users can share a name).
      * ``birthdate`` — Date, NOT an ``age`` int. Why: age derived from a
        stored birthdate auto-updates (no drift, no nightly cron), and lets
        a future ticket-purchase check answer "will this user be N by the
        event date?" — which a stored integer age cannot. No 18+ check is
        applied here; policy varies per event and belongs at ticket purchase
        (later increment).
      * ``password_hash`` — String(255) fits an argon2id PHC string comfortably
        (~97 chars today; leaves headroom for parameter bumps).
      * ``is_admin`` — reserved for Increment 10; there are NO endpoints that
        read it in Increment 1, only the column.
      * ``created_at``/``updated_at`` — timezone-aware timestamps. ``onupdate``
        is a SQL expression evaluated by the DB on UPDATE, so it works even for
        bulk UPDATEs that skip the ORM.

    ``id`` is a uuid4 generated Python-side via ``default_factory``, so it is
    NEVER ``None`` — unlike an auto-increment int PK, whose value only exists
    after INSERT. Consequences:
      * ``service.issue_token`` no longer needs an ``if user.id is None`` guard;
        the id is populated before the object is even stored.
      * The unit-test fake can key a dict by ``user.id`` immediately after the
        service constructs the user — no flush/refresh dance required.
      * ``register`` returns a fully-formed UUID id (matching what the client
        will see on every future request).

    Why **uuid4**: 122 random bits is the maximum uniqueness available short of
    a 128-bit counter — exactly what the increment asked for. Tradeoffs noted
    but not acted on: uuid7 sorts better for index locality at scale, and a
    DB-side ``gen_random_uuid()`` avoids Python-side generation, but both add
    complexity for benefits we do not need at this stage.

    Why **Python-side** rather than server-side default: the fake repo in unit
    tests then gets a real UUID without simulating PG, and the concrete repo's
    ``flush()+refresh()`` is a no-op with respect to ``id`` (the value we sent
    is the value the DB returns).
    """

    __tablename__ = "users"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)

    email: str = Field(
        sa_column=Column(String(320), unique=True, index=True, nullable=False),
    )
    username: str = Field(
        sa_column=Column(String(50), unique=True, index=True, nullable=False),
    )

    first_name: str = Field(sa_column=Column(String(100), nullable=False))
    last_name: str = Field(sa_column=Column(String(100), nullable=False))
    # ``Date`` maps to PostgreSQL ``DATE`` and yields a ``datetime.date``
    # in Python. Non-nullable: registration requires it (see schemas.py
    # ``UserCreate``).
    birthdate: date = Field(sa_column=Column(Date, nullable=False))

    password_hash: str = Field(
        sa_column=Column(String(255), nullable=False),
    )

    is_active: bool = Field(default=True)
    # Reserved for Increment 10 (admin UI). Deliberately never referenced by
    # any Increment 1 endpoint.
    is_admin: bool = Field(default=False)

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True), server_default=func.now(), nullable=False),
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(
            DateTime(timezone=True),
            server_default=func.now(),
            onupdate=func.now(),
            nullable=False,
        ),
    )

    def __repr__(self) -> str:
        # Never include ``password_hash`` in __repr__: logs, exception traces,
        # and REPL output all use __repr__, and a hashed password in a log is
        # still a credential-shaped secret worth keeping out of disk.
        return (
            f"User(id={self.id!r}, email={self.email!r}, "
            f"name={self.first_name} {self.last_name!r}, "
            f"username={self.username!r})"
        )
