"""Unit tests for ``EventService`` against a real DB session with rollback-per-test.

Why real SQL instead of in-memory fakes here (unlike ``test_auth_service.py``):
``EventRepository``, ``TicketTypeRepository``, ``SectionRepository``, and
``SeatRepository`` are pure SQL wrappers with zero branching logic. The
interesting behaviour of ``EventService`` is multi-table orchestration, FK
wiring across four tables, and transactional rollback when a flush fails —
which real PostgreSQL exercises faithfully while a dict fake would only re-implement.
"""
from collections.abc import AsyncIterator
from copy import deepcopy
from datetime import UTC, date, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlmodel.ext.asyncio.session import AsyncSession

from queuepass.core.db import async_session_factory
from queuepass.modules.auth.models import User
from queuepass.modules.auth.repository import UserRepository
from queuepass.modules.events.models import Event, Seat
from queuepass.modules.events.repository import (
    EventRepository,
    SeatRepository,
    SectionRepository,
    TicketTypeRepository,
)
from queuepass.modules.events.schemas import EventCreate
from queuepass.modules.events.service import (
    EventConflictError,
    EventService,
    EventValidationError,
)


@pytest_asyncio.fixture(autouse=True)
async def db_session_with_rollback() -> AsyncIterator[AsyncSession]:
    """Open a real DB session for each test and always roll back at teardown.

    No test in this module ever commits, so the database stays completely clean
    even though we exercise real SQL, FKs, and constraints.
    """
    async with async_session_factory() as session:
        try:
            yield session
        finally:
            await session.rollback()


@pytest_asyncio.fixture
async def organizer(db_session_with_rollback: AsyncSession) -> User:
    """Insert a transient organizer ``User`` inside the test's uncommitted transaction."""
    user = User(
        email=f"org_{uuid4().hex[:8]}@example.com",
        username=f"org_{uuid4().hex[:8]}",
        password_hash="not-a-real-hash",
        first_name="Grace",
        last_name="Hopper",
        birthdate=date(1990, 1, 1),
    )
    return await UserRepository(db_session_with_rollback).add(user)


@pytest.fixture
def event_service(db_session_with_rollback: AsyncSession) -> EventService:
    """Compose ``EventService`` with the four repositories bound to the rollback session."""
    return EventService(
        events=EventRepository(db_session_with_rollback),
        ticket_types=TicketTypeRepository(db_session_with_rollback),
        sections=SectionRepository(db_session_with_rollback),
        seats=SeatRepository(db_session_with_rollback),
    )


async def test_create_happy_path(
    event_service: EventService,
    organizer: User,
    sample_event_payload: dict[str, object],
) -> None:
    payload = EventCreate.model_validate(sample_event_payload)
    created = await event_service.create(organizer.id, payload)

    assert created.id is not None
    assert len(created.ticket_types) == 2
    assert len(created.sections) == 2

    tt_by_name = {tt.name: tt for tt in created.ticket_types}
    section_by_name = {s.name: s for s in created.sections}

    assert section_by_name["Floor"].ticket_type_id == tt_by_name["Standard"].id
    assert section_by_name["Balcony"].ticket_type_id == tt_by_name["VIP"].id

    total_seats = sum(len(s.seats) for s in created.sections)
    assert total_seats == 6


async def test_create_duplicate_ticket_type_names_raises_conflict(
    event_service: EventService,
    organizer: User,
    sample_event_payload: dict[str, object],
) -> None:
    raw = deepcopy(sample_event_payload)
    raw["ticket_types"] = [
        {"name": "Standard", "price_cents": 2500, "currency": "USD"},
        {"name": "Standard", "price_cents": 5000, "currency": "USD"},
    ]
    raw["sections"][1]["ticket_type_name"] = "Standard"  # type: ignore[index]
    payload = EventCreate.model_validate(raw)

    with pytest.raises(EventConflictError, match="duplicate ticket type names"):
        await event_service.create(organizer.id, payload)


async def test_create_duplicate_section_names_raises_conflict(
    event_service: EventService,
    organizer: User,
    sample_event_payload: dict[str, object],
) -> None:
    raw = deepcopy(sample_event_payload)
    raw["sections"][1]["name"] = "Floor"  # type: ignore[index]
    payload = EventCreate.model_validate(raw)

    with pytest.raises(EventConflictError, match="duplicate section names"):
        await event_service.create(organizer.id, payload)


async def test_create_section_unknown_ticket_type_raises_validation(
    event_service: EventService,
    organizer: User,
    sample_event_payload: dict[str, object],
) -> None:
    raw = deepcopy(sample_event_payload)
    raw["sections"][0]["ticket_type_name"] = "NonExistentTier"  # type: ignore[index]
    payload = EventCreate.model_validate(raw)

    with pytest.raises(EventValidationError, match="unknown ticket type"):
        await event_service.create(organizer.id, payload)


async def test_create_duplicate_seats_in_section_raises_conflict(
    event_service: EventService,
    organizer: User,
    sample_event_payload: dict[str, object],
) -> None:
    raw = deepcopy(sample_event_payload)
    raw["sections"][0]["seats"].append({"row_label": "A", "seat_number": 1})  # type: ignore[index]
    payload = EventCreate.model_validate(raw)

    with pytest.raises(EventConflictError, match="duplicate seat in section 'Floor'"):
        await event_service.create(organizer.id, payload)


async def test_create_starts_in_past_raises_validation(
    event_service: EventService,
    organizer: User,
    sample_event_payload: dict[str, object],
) -> None:
    raw = deepcopy(sample_event_payload)
    past_start = datetime.now(UTC) - timedelta(days=1)
    raw["starts_at"] = past_start.isoformat()
    raw["ends_at"] = (past_start + timedelta(hours=2)).isoformat()
    payload = EventCreate.model_validate(raw)

    with pytest.raises(EventValidationError, match="starts_at must be in the future"):
        await event_service.create(organizer.id, payload)


async def test_create_organizer_id_set_from_argument(
    event_service: EventService,
    organizer: User,
    sample_event_payload: dict[str, object],
) -> None:
    payload = EventCreate.model_validate(sample_event_payload)
    created = await event_service.create(organizer.id, payload)

    assert created.organizer_id == organizer.id


async def test_create_rolls_back_on_duplicate_seat(
    db_session_with_rollback: AsyncSession,
    organizer: User,
    sample_event_payload: dict[str, object],
) -> None:
    """Atomicity proof: a duplicate seat fails creation and leaves ``events`` count unchanged.

    Exercises both the service-level guard (``EventConflictError``) and the
    DB-level ``uq_seats_section_id_row_label_seat_number`` ``IntegrityError``
    at flush after ``Event``, ``TicketType``, and ``Section`` rows have already
    been flushed in the same transaction.
    """
    before_count = (
        await db_session_with_rollback.exec(select(func.count()).select_from(Event))
    ).one()

    # Path A: service catches the duplicate seat before flushing.
    raw = deepcopy(sample_event_payload)
    raw["sections"][0]["seats"].append({"row_label": "A", "seat_number": 1})  # type: ignore[index]
    payload = EventCreate.model_validate(raw)

    service = EventService(
        events=EventRepository(db_session_with_rollback),
        ticket_types=TicketTypeRepository(db_session_with_rollback),
        sections=SectionRepository(db_session_with_rollback),
        seats=SeatRepository(db_session_with_rollback),
    )
    with pytest.raises((EventConflictError, IntegrityError)):
        await service.create(organizer.id, payload)

    after_service_guard = (
        await db_session_with_rollback.exec(select(func.count()).select_from(Event))
    ).one()
    assert after_service_guard == before_count

    # Path B: force a duplicate seat at the DB flush stage (after Event, TicketTypes,
    # and Sections have already been flushed) to prove transactional rollback
    # wipes the parent rows too.
    class _DupInjectingSeatRepo(SeatRepository):
        async def add_many(self, seats: list[Seat]) -> list[Seat]:
            dup = Seat(
                section_id=seats[0].section_id,
                row_label=seats[0].row_label,
                seat_number=seats[0].seat_number,
            )
            return await super().add_many([*seats, dup])

    service_hitting_db = EventService(
        events=EventRepository(db_session_with_rollback),
        ticket_types=TicketTypeRepository(db_session_with_rollback),
        sections=SectionRepository(db_session_with_rollback),
        seats=_DupInjectingSeatRepo(db_session_with_rollback),
    )
    valid_payload = EventCreate.model_validate(sample_event_payload)
    with pytest.raises((EventConflictError, IntegrityError)):
        await service_hitting_db.create(organizer.id, valid_payload)

    await db_session_with_rollback.rollback()
    after_rollback = (
        await db_session_with_rollback.exec(select(func.count()).select_from(Event))
    ).one()
    assert after_rollback == before_count
