"""Data-access layer for the events domain.

Four repositories — one per table. Deliberately **no Protocol classes** here
(unlike ``UserRepositoryProtocol`` in the auth module): these are pure SQL
wrappers with no branching logic, so a fake adds cost without value. The
events service is tested against a real DB with rollback-per-test (see
``tests/unit/test_event_service.py``) because its *orchestration* is what
matters and that is best exercised against real SQL.

Every repository takes an ``AsyncSession`` and only issues SQL. No validation,
no orchestration, no exception mapping — those live in ``service.py``.
"""
import uuid

from sqlalchemy.orm import selectinload
from sqlmodel import col, select
from sqlmodel.ext.asyncio.session import AsyncSession

from queuepass.modules.events.models import Event, Seat, Section, TicketType


class EventRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, event: Event) -> Event:
        """Flush the parent row so the transaction can insert its children."""
        self.session.add(event)
        await self.session.flush()
        return event

    async def get_by_id(self, event_id: uuid.UUID) -> Event | None:
        result = await self.session.exec(select(Event).where(Event.id == event_id))
        return result.first()

    async def get_with_nested(self, event_id: uuid.UUID) -> Event | None:
        """Load an event with ticket_types, sections, and sections' seats.

        Uses ``selectinload`` (separate SELECT per relationship) rather than
        ``joinedload`` (JOIN) because Event has TWO one-to-many children
        (ticket_types, sections) and each section has a further one-to-many
        (seats). Joining all three into a single query produces a cartesian
        product (ticket_types x sections x seats) — the result set explodes
        and every row is partially duplicated. The normal nonempty case uses
        four SELECTs: one for the event and one each for its ticket types,
        sections, and the seats under those sections. Large collections can
        be split into batches, but there is no per-section seat query.
        """
        stmt = (
            select(Event)
            .where(Event.id == event_id)
            # SQLModel types ``Relationship`` attributes as plain ``list[T]``
            # rather than SQLAlchemy's ``Mapped[list[T]]``, so mypy strict
            # does not see that class-level access yields a ``QueryableAttribute``.
            .options(
                selectinload(Event.ticket_types),  # type: ignore[arg-type]
                selectinload(Event.sections).selectinload(  # type: ignore[arg-type]
                    Section.seats  # type: ignore[arg-type]
                ),
            )
        )
        result = await self.session.exec(stmt)
        return result.first()

    async def list(self, limit: int, offset: int) -> list[Event]:
        """Page by creation time, using the UUID only to break timestamp ties."""
        stmt = select(Event).order_by(col(Event.created_at), col(Event.id))
        result = await self.session.exec(stmt.limit(limit).offset(offset))
        return list(result.all())


class TicketTypeRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add_many(self, tts: list[TicketType]) -> list[TicketType]:
        """Stage the ORM objects together and flush once for the batch."""
        self.session.add_all(tts)
        await self.session.flush()
        return tts

    async def list_by_event(self, event_id: uuid.UUID) -> list[TicketType]:
        result = await self.session.exec(
            select(TicketType).where(TicketType.event_id == event_id)
        )
        return list(result.all())


class SectionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add_many(self, sections: list[Section]) -> list[Section]:
        self.session.add_all(sections)
        await self.session.flush()
        return sections

    async def list_by_event(self, event_id: uuid.UUID) -> list[Section]:
        result = await self.session.exec(
            select(Section).where(Section.event_id == event_id)
        )
        return list(result.all())


class SeatRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add_many(self, seats: list[Seat]) -> list[Seat]:
        self.session.add_all(seats)
        await self.session.flush()
        return seats

    async def list_by_section(self, section_id: uuid.UUID) -> list[Seat]:
        result = await self.session.exec(select(Seat).where(Seat.section_id == section_id))
        return list(result.all())
