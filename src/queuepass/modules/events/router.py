"""Events HTTP endpoints: create, list, get-by-id.

Thin by design: parse input, call ``EventService``, serialise, map module
exceptions to HTTP status. No business rules in the handler bodies.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlmodel.ext.asyncio.session import AsyncSession

from queuepass.core.db import get_session
from queuepass.core.deps import get_current_user
from queuepass.modules.auth.models import User
from queuepass.modules.events.models import Event
from queuepass.modules.events.repository import (
    EventRepository,
    SeatRepository,
    SectionRepository,
    TicketTypeRepository,
)
from queuepass.modules.events.schemas import EventCreate, EventDetail, EventSummary
from queuepass.modules.events.service import (
    EventConflictError,
    EventNotFound,
    EventService,
    EventValidationError,
)

router = APIRouter()


def get_event_service(
    session: AsyncSession = Depends(get_session),
) -> EventService:
    """FastAPI dependency: compose the events service with real infrastructure.

    One session feeds all four repositories, so the whole nested creation
    shares a single transaction boundary (commit-on-success is handled by
    ``get_session``).
    """
    return EventService(
        events=EventRepository(session),
        ticket_types=TicketTypeRepository(session),
        sections=SectionRepository(session),
        seats=SeatRepository(session),
    )


@router.post("", response_model=EventDetail, status_code=status.HTTP_201_CREATED)
async def create_event(
    payload: EventCreate,
    current_user: User = Depends(get_current_user),
    service: EventService = Depends(get_event_service),
) -> Event:
    """Create an event with its full nested tree atomically."""
    try:
        return await service.create(current_user.id, payload)
    except EventValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from None
    except EventConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc)
        ) from None


@router.get("", response_model=list[EventSummary])
async def list_events(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    service: EventService = Depends(get_event_service),
) -> list[Event]:
    """Page through events. Public — no auth required."""
    return await service.list(limit, offset)


@router.get("/{event_id}", response_model=EventDetail)
async def get_event(
    event_id: uuid.UUID,
    service: EventService = Depends(get_event_service),
) -> Event:
    """Return one event with nested ticket_types/sections/seats. Public."""
    try:
        return await service.get_detail(event_id)
    except EventNotFound:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Event not found"
        ) from None
