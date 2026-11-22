"""Events module — Event / TicketType / Section / Seat.
Increment 3 introduces the ticketing domain as a vertical slice:
  * ``models.py``     — the four SQLModel tables.
  * ``schemas.py``    — request / response Pydantic shapes.
  * ``repository.py`` — four thin SQL wrappers (no protocols — see module docstring).
  * ``service.py``    — orchestration + domain exceptions.
  * ``router.py``     — three HTTP endpoints (create + read only).

Deliberately NOT in this increment: seat holds, availability, checkout,
Celery, Redis. Seats are just records; ``status``/``held_by`` come in
Increment 4.
"""
