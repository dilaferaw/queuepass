"""Pydantic schemas for the events module.

Follows the auth module pattern exactly: Pydantic ``BaseModel`` (NOT
SQLModel) for request/response shapes, so a schema never accidentally becomes
a table. ``ConfigDict(from_attributes=True)`` lets FastAPI validate a SQLModel
ORM instance into the response schema directly.

Nested-creation shape (the interesting bit):
``EventCreate`` carries its own ``ticket_types`` and ``sections`` inline,
because a client creating a new event has no IDs to reference yet — the
ticket types do not exist when the request is sent. The inner
``SectionCreate`` therefore references its ticket type by **name**
(``ticket_type_name``), not by id. The service resolves name -> id after the
ticket types are inserted. This is the general "refer-by-name during creation,
refer-by-id after" pattern; you flip to id-based referencing as soon as the
referent already exists (e.g. a future "add a section to an existing event"
endpoint).
"""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

# --- request payloads (inputs) ----------------------------------------------


class SeatCreate(BaseModel):
    """One seat in a section. ``row_label`` is a string (A, AA, Pit, ...)."""

    row_label: str = Field(min_length=1, max_length=10)
    # ``ge=1`` mirrors the DB CHECK; validate here for a friendly 422 instead
    # of a 500 from a constraint violation.
    seat_number: int = Field(ge=1)


class SectionCreate(BaseModel):
    """A physical section of the new event, plus its seats.

    ``ticket_type_name`` (not ``ticket_type_id``) because the ticket type is
defined in the same payload — the client has no id to send yet. The service
resolves name -> id after inserting ticket types.
    """

    name: str = Field(min_length=1, max_length=100)
    ticket_type_name: str = Field(min_length=1, max_length=100)
    seats: list[SeatCreate] = Field(min_length=1)


class TicketTypeCreate(BaseModel):
    """A pricing tier of the new event."""

    name: str = Field(min_length=1, max_length=100)
    price_cents: int = Field(ge=0)
    currency: str = Field(default="USD", min_length=3, max_length=3)


class EventCreate(BaseModel):
    """Full nested payload for POST /events.

    Structural validation lives here (``starts_at < ends_at``): that is a
    malformed-request concern and belongs at the parse boundary. Policy
    validation ("starts_at must be in the future") lives in the service — see
    ``service.create`` for the rationale.
    """

    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    venue_name: str = Field(min_length=1, max_length=200)
    venue_address: str = Field(min_length=1, max_length=500)
    starts_at: datetime
    ends_at: datetime
    timezone: str = Field(default="UTC", max_length=64)
    ticket_types: list[TicketTypeCreate] = Field(min_length=1)
    sections: list[SectionCreate] = Field(min_length=1)

    @model_validator(mode="after")
    def _starts_before_ends(self) -> "EventCreate":
        """Structural rule: ``starts_at`` must strictly precede ``ends_at``.

        Deliberately NOT a policy check — whether the event is in the past is
        a business decision (admins may backfill), but an event whose start
        is after its end is nonsense at any time.
        """
        if self.starts_at >= self.ends_at:
            raise ValueError("starts_at must be strictly before ends_at")
        return self


# --- response projections (outputs) ------------------------------------------


class TicketTypePublic(BaseModel):
    """Safe projection of a ``TicketType`` row."""

    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    price_cents: int
    currency: str


class SeatPublic(BaseModel):
    """Safe projection of a ``Seat`` row."""

    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    row_label: str
    seat_number: int


class SectionPublic(BaseModel):
    """Safe projection of a ``Section`` with its seats."""

    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    ticket_type_id: uuid.UUID
    seats: list[SeatPublic]


class EventSummary(BaseModel):
    """Light projection for GET /events list.

    Deliberately excludes ``description``/``venue_address``/nested collections
    — the list response is meant to be cheap to render.
    """

    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organizer_id: uuid.UUID
    name: str
    venue_name: str
    starts_at: datetime
    ends_at: datetime
    timezone: str


class EventDetail(EventSummary):
    """Full projection for POST /events response and GET /events/{id}."""

    description: str | None
    venue_address: str
    ticket_types: list[TicketTypePublic]
    sections: list[SectionPublic]
    created_at: datetime
