"""Event-creation orchestration and domain exceptions.

Rules the service owns:
  * ``starts_at`` must be in the future (policy, not shape).
  * Uniqueness of ticket-type names / section names within the payload.
  * Every ``section.ticket_type_name`` must match a ticket type in the same
    payload.
  * Seats are unique within each section.

Rules the service does NOT own:
  * ``starts_at < ends_at`` — structural, lives in ``EventCreate`` via
    ``@model_validator`` (malformed request -> 422).
  * Column bounds (max lengths, ge=0) — shape, lives in Pydantic.
  * SQL — repository.
  * HTTP status codes — router.

Transaction discipline: the service NEVER calls ``commit()``. Repositories
flush (so we can read freshly-assigned UUIDs for FK wiring) and
``core.db.get_session`` commits on success / rolls back on error at the
request boundary. If any ``flush`` raises (constraint violation), the whole
nested creation rolls back atomically in teardown — no service-side
transaction-management code required. Do NOT wrap ``commit`` in
``try/except`` here; that pattern mangles error semantics and duplicates
what the session already does.
"""
import uuid
from datetime import UTC, datetime

from queuepass.modules.events.models import Event, Seat, Section, TicketType
from queuepass.modules.events.repository import (
    EventRepository,
    SeatRepository,
    SectionRepository,
    TicketTypeRepository,
)
from queuepass.modules.events.schemas import EventCreate

# --- module-local exceptions ------------------------------------------------

class EventError(Exception):
    """Base for all events-domain failures."""


class EventNotFound(EventError):
    """GET /events/{id} on a missing event."""


class EventValidationError(EventError):
    """The payload is well-formed but violates a business rule.

    Mapped to HTTP 400 (not 422 — the payload passed Pydantic; the rule is
    policy, not shape).
    """


class EventConflictError(EventError):
    """The payload collides with existing data or with itself (duplicate
    names / seats).

    Mapped to HTTP 409.
    """


class EventService:
    """Orchestrates nested event creation.

    Four repositories are injected via keyword-only constructor arguments so
    every call site reads like ``EventService(events=..., ticket_types=...)``
    and it is obvious which repo is which.
    """

    def __init__(
        self,
        *,
        events: EventRepository,
        ticket_types: TicketTypeRepository,
        sections: SectionRepository,
        seats: SeatRepository,
    ) -> None:
        self._events = events
        self._ticket_types = ticket_types
        self._sections = sections
        self._seats = seats

    async def create(self, organizer_id: uuid.UUID, payload: EventCreate) -> Event:
        """Create an event with its full nested tree atomically.

        Steps are ordered so we can fail fast on policy violations before any
        INSERT touches the DB.
        """
        # 1. Policy: the event must be in the future. Not a Pydantic rule
        #    because admins may later need to backfill past events.
        if payload.starts_at <= datetime.now(UTC):
            raise EventValidationError("starts_at must be in the future")

        # 2. Uniqueness: ticket-type names within the payload. Compare set
        #    length to list length — set collapses duplicates, so a mismatch
        #    means a collision.
        tt_names = [tt.name for tt in payload.ticket_types]
        if len(set(tt_names)) != len(tt_names):
            raise EventConflictError("duplicate ticket type names")

        # 3. Uniqueness: section names within the payload.
        section_names = [s.name for s in payload.sections]
        if len(set(section_names)) != len(section_names):
            raise EventConflictError("duplicate section names")

        # 4. Referential integrity within the payload: every section must
        #    reference a ticket type that is also in the payload (by name).
        tt_name_set = set(tt_names)
        for s in payload.sections:
            if s.ticket_type_name not in tt_name_set:
                raise EventValidationError(
                    f"section '{s.name}' references unknown ticket type "
                    f"'{s.ticket_type_name}'"
                )

        # 5. Uniqueness: seats within each section. A section's seat identity
        #    is the pair (row_label, seat_number).
        for s in payload.sections:
            seat_keys = {(seat.row_label, seat.seat_number) for seat in s.seats}
            if len(seat_keys) != len(s.seats):
                raise EventConflictError(f"duplicate seat in section '{s.name}'")

        # 6. Persist in FK order: event -> ticket types -> sections -> seats.
        #    ``payload.model_dump(exclude={...})`` lets us splat the non-nested
        #    fields straight into the Event constructor.
        event = await self._events.add(
            Event(
                organizer_id=organizer_id,
                **payload.model_dump(exclude={"ticket_types", "sections"}),
            )
        )

        inserted_tts = await self._ticket_types.add_many(
            [TicketType(event_id=event.id, **tt.model_dump()) for tt in payload.ticket_types]
        )
        tt_map = {tt.name: tt for tt in inserted_tts}

        section_models = [
            Section(
                event_id=event.id,
                name=s.name,
                ticket_type_id=tt_map[s.ticket_type_name].id,
            )
            for s in payload.sections
        ]
        inserted_sections = await self._sections.add_many(section_models)

        # Pair payload sections with their inserted models by position —
        # ``add_many`` preserves order and both lists are built from the same
        # ``payload.sections`` list.
        for payload_section, section_model in zip(
            payload.sections, inserted_sections, strict=True
        ):
            await self._seats.add_many(
                [
                    Seat(section_id=section_model.id, **seat.model_dump())
                    for seat in payload_section.seats
                ]
            )

        # 7. Re-read with eager loading to give the caller a fully-populated
        #    object (Event + ticket_types + sections + seats).
        loaded = await self._events.get_with_nested(event.id)
        if loaded is None:
            raise EventNotFound(str(event.id))
        return loaded

    async def get_detail(self, event_id: uuid.UUID) -> Event:
        """Load an event with nested collections or raise ``EventNotFound``."""
        event = await self._events.get_with_nested(event_id)
        if event is None:
            raise EventNotFound(str(event_id))
        return event

    async def list(self, limit: int, offset: int) -> list[Event]:
        """Page through events. Delegates straight to the repo."""
        return await self._events.list(limit, offset)
