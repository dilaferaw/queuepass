"""SQLModel tables for the events domain: Event, TicketType, Section, Seat.
Why these four and why this shape:
  * A **TicketType** is a *price label* ("Standard 2500", "VIP 10000").
  * A **Section** is a *physical area* ("Floor", "Balcony") that references
    exactly one TicketType — that reference is how pricing hangs off a section.
  * A **Seat** is a *physical spot* inside a Section, identified by
    ``(row_label, seat_number)``. The chain Event -> Section -> Seat is the
    ownership tree; TicketType sits beside Section and is joined in via the
    section's ``ticket_type_id``.
  Do not conflate seat and ticket type: a seat is where you sit, a ticket type
  is what you pay. Conflating them forces an explosion of rows (one ``VIP``
  ticket type per VIP seat) and makes re-pricing a section a data migration.

Cascade policy (also mirrored in the migration):
  * event -> ticket_type    CASCADE  — deleting an event removes its price
                                       labels (they are meaningless alone).
  * event -> section        CASCADE  — same for physical areas.
  * section -> seat         CASCADE  — seats are meaningless without a section.
  * section -> ticket_type  RESTRICT — a ticket type cannot be deleted while a
                                       section still prices off it. Prevents
                                       orphaning a live price.
  * user  -> event          RESTRICT — an organiser with events cannot be
                                       deleted. Preserves referential integrity
                                       for the money trail (orders reference
                                       events, which reference a user).

No ``capacity`` column on ``Section``: capacity is
``COUNT(seats WHERE section_id = X)`` — derived, not stored. Storing it would
invite drift the moment we bulk-insert seats.

No ``updated_at`` anywhere in this increment: there are no update endpoints.
Add the column when event editing exists — otherwise the column lies.

No ``is_active`` / soft delete: hard delete + CASCADE is the model we chose.
"""
import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlmodel import Field, Relationship, SQLModel


class Event(SQLModel, table=True):
    """Top-level ticketing entity. Owned by a User (the organiser).

    ``starts_at``/``ends_at`` are timezone-aware (``DateTime(timezone=True)``)
    because events happen at a physical place and time — a naive datetime
    would be interpreted in whatever timezone the app server happens to run
    in. ``timezone`` stores the IANA name (e.g. ``"Europe/Berlin"``) as
    display metadata for the client; the DB timestamps are absolute (UTC).
    """

    __tablename__ = "events"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    # RESTRICT: an organiser with events cannot be deleted. See module docstring.
    organizer_id: uuid.UUID = Field(
        sa_column=Column(
            ForeignKey("users.id", ondelete="RESTRICT"),
            index=True,
            nullable=False,
        ),
    )
    name: str = Field(sa_column=Column(String(200), nullable=False))
    description: str | None = Field(sa_column=Column(String(2000), nullable=True))
    venue_name: str = Field(sa_column=Column(String(200), nullable=False))
    venue_address: str = Field(sa_column=Column(String(500), nullable=False))
    # ``sa_column=Column(DateTime(timezone=True))`` is required for TZ-aware
    # values; SQLModel's plain ``Field`` would produce a naive DateTime column.
    starts_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False, index=True),
    )
    ends_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    timezone: str = Field(
        default="UTC", sa_column=Column(String(64), server_default="UTC", nullable=False),
    )
    # Let PostgreSQL supply the timestamp when the row is inserted.
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True), server_default=func.now(), nullable=False),
    )

    # Read-only collections: repositories write explicit FKs. The detail query
    # opts into eager loading; accidental lazy I/O during serialization raises.
    ticket_types: list["TicketType"] = Relationship(
        sa_relationship_kwargs={"viewonly": True, "lazy": "raise"},
    )
    sections: list["Section"] = Relationship(
        sa_relationship_kwargs={"viewonly": True, "lazy": "raise"},
    )


class TicketType(SQLModel, table=True):
    """A pricing tier for one event (e.g. ``Standard 2500``, ``VIP 10000``).

    ``price_cents`` is an integer in minor currency units — never a float.
    Floats cannot represent ``0.10`` exactly and every arithmetic step
    compounds the error; integer cents sidesteps the entire class of bugs.

    ``currency`` is a 3-letter ISO 4217 code (default ``USD``) — we do not
    convert currencies in this increment; the field is metadata for the client.

    UNIQUE ``(event_id, name)``: two tiers in the same event cannot share a
    name (they would be indistinguishable in the client UI), but two events
    may both have a ``Standard`` tier. A composite unique is exactly the
    primitive for "unique within a parent".
    """

    __tablename__ = "ticket_types"
    __table_args__ = (
        UniqueConstraint("event_id", "name", name="uq_ticket_types_event_id_name"),
        CheckConstraint("price_cents >= 0", name="ck_ticket_types_price_cents_non_negative"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    # CASCADE: deleting an event removes its pricing tiers.
    event_id: uuid.UUID = Field(
        sa_column=Column(
            ForeignKey("events.id", ondelete="CASCADE"),
            index=True,
            nullable=False,
        ),
    )
    name: str = Field(sa_column=Column(String(100), nullable=False))
    price_cents: int = Field(sa_column=Column(Integer, nullable=False))
    currency: str = Field(
        default="USD", sa_column=Column(String(3), server_default="USD", nullable=False),
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True), server_default=func.now(), nullable=False),
    )


class Section(SQLModel, table=True):
    """A physical area of an event (``Floor``, ``Balcony``, ``Pit``, ...).

    Each section references exactly one TicketType — the price guests pay to
    sit in that section. The FK is RESTRICT (not CASCADE) so a ticket type
    cannot be deleted while a live section still prices off it.

    No ``capacity`` column: capacity is the count of seats in the section,
    derived at query time. Storing it invites drift.

    UNIQUE ``(event_id, name)``: two sections in the same event cannot share a
    name (the client resolves ``ticket_type_name -> ticket_type_id`` by name
    lookup within the payload and needs unambiguous section names too).
    """

    __tablename__ = "sections"
    __table_args__ = (
        UniqueConstraint("event_id", "name", name="uq_sections_event_id_name"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    event_id: uuid.UUID = Field(
        sa_column=Column(
            ForeignKey("events.id", ondelete="CASCADE"),
            index=True,
            nullable=False,
        ),
    )
    name: str = Field(sa_column=Column(String(100), nullable=False))
    # RESTRICT: cannot delete a ticket type while a section still uses it.
    ticket_type_id: uuid.UUID = Field(
        sa_column=Column(
            ForeignKey("ticket_types.id", ondelete="RESTRICT"),
            index=True,
            nullable=False,
        ),
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True), server_default=func.now(), nullable=False),
    )

    seats: list["Seat"] = Relationship(
        sa_relationship_kwargs={"viewonly": True, "lazy": "raise"},
    )


class Seat(SQLModel, table=True):
    """A physical spot inside a section, identified by ``(row_label, seat_number)``.

    ``row_label`` is a **String**, not an Integer: real venues number rows
    ``A``-``Z``, ``AA``-``AZ``, ``GA1``, ``GA2``, ``Pit``. An integer column
    works until the third letter or first GA row and then breaks. The cost is
    a slightly larger index (string collation vs integer compare), which is
    negligible for the row cardinality we are talking about (thousands of
    seats per event).

    UNIQUE ``(section_id, row_label, seat_number)`` — **composite**, not three
    separate uniques. A seat is only unique *within its section*: row A seat 1
    in Floor and row A seat 1 in Balcony are two different physical seats.
    Three separate UNIQUE constraints would (a) forbid the same row_label in
    two sections, and (b) forbid the same seat_number twice — both nonsense.

    No ``status``/``held_by``/``hold_expires_at`` — those are Increment 4's
    seat-hold feature. A Seat row in Increment 3 is just a record of
    existence.
    """

    __tablename__ = "seats"
    __table_args__ = (
        UniqueConstraint(
            "section_id",
            "row_label",
            "seat_number",
            name="uq_seats_section_id_row_label_seat_number",
        ),
        CheckConstraint("seat_number >= 1", name="ck_seats_seat_number_positive"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    # CASCADE: deleting a section removes its seats.
    section_id: uuid.UUID = Field(
        sa_column=Column(
            ForeignKey("sections.id", ondelete="CASCADE"),
            index=True,
            nullable=False,
        ),
    )
    row_label: str = Field(sa_column=Column(String(10), nullable=False))
    seat_number: int = Field(sa_column=Column(Integer, nullable=False))
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True), server_default=func.now(), nullable=False),
    )

