"""Pydantic schemas for the auth module.

These are separate from the SQLModel table on purpose:
  * ``UserCreate`` carries a plaintext password; the table must never hold one.
  * ``UserPublic`` never exposes ``password_hash``; using the table directly
    as a response model would leak it unless we remembered to exclude the field.
  * ``Token`` matches OAuth2 password-flow's expected response shape exactly —
    Swagger's Authorize button will not work otherwise.

Pydantic (not SQLModel) is used here because schemas are not DB models; keeping
them off SQLModel reinforces that distinction and avoids accidental table=True.
"""

import uuid
from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, computed_field, field_validator


class UserCreate(BaseModel):
    """Payload accepted by POST /auth/register."""

    # EmailStr requires the ``email-validator`` package (added in Increment 1).
    # It normalises nothing — the service lowercases before persisting.
    email: EmailStr
    # Length bounds are the DB column bounds; validate here for a friendly 422
    # instead of a 500 from a DB constraint violation.
    username: str = Field(min_length=3, max_length=50)

    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)
    # ``birthdate`` (not ``age``). See ``User.birthdate`` docstring in models.py
    # for the rationale. Not nullable, no 18+ check here — that policy varies
    # per event and is enforced at ticket purchase (later increment).
    birthdate: date

    # ``min_length=8`` is a floor, not a policy. Real strength policy (length
    # entropy, dictionary checks) is deliberately out of scope for Increment 1.
    password: str = Field(min_length=8)

    @field_validator("birthdate")
    @classmethod
    def _birthdate_not_in_future(cls, v: date) -> date:
        """Reject future birthdates — they would produce a negative age."""
        if v > date.today():
            raise ValueError("birthdate cannot be in the future")
        return v


class UserPublic(BaseModel):
    """Safe user projection returned by register / me.

    ``model_config = ConfigDict(from_attributes=True)`` lets FastAPI validate a
    ``User`` ORM instance into this schema directly (``response_model=UserPublic``).
    ``id`` is ``int`` here (never ``None`` on a successfully-persisted user).
    """

    model_config = ConfigDict(from_attributes=True)

    # ``id`` matches the model: a uuid4. Pydantic serialises UUIDs as strings
    # over JSON (canonical hyphenated form), so the wire contract is a string,
    # but the Python type is ``uuid.UUID`` — validation catches malformed input.
    id: uuid.UUID
    email: EmailStr
    username: str
    first_name: str
    last_name: str
    birthdate: date
    is_active: bool
    created_at: datetime

    @computed_field  # type: ignore[prop-decorator]
    @property
    def age(self) -> int:
        """Derived from ``birthdate`` — never stored, so it cannot drift.

        Leap-year policy: ``(today.month, today.day) < (bd.month, bd.day)``
        means a Feb-29 baby turns older on Mar 1 in non-leap years — slightly
        conservative, which is the safer default for age-gated events (won't
        sell alcohol a day early).

        This is the *display* age ("how old is this person today"). The
        ticket-purchase gate (later increment) needs a different question —
        "will they be N on the event date?" — which is why we store
        ``birthdate`` and not ``age``.
        """
        today = date.today()
        years = today.year - self.birthdate.year
        if (today.month, today.day) < (self.birthdate.month, self.birthdate.day):
            years -= 1
        return years


class Token(BaseModel):
    """Response body of POST /auth/login.

    ``token_type`` defaults to ``"bearer"`` because that is the wire value the
    OAuth2 password flow mandates. Swagger UI keys off this field to prepend
    ``Bearer `` automatically — deviate and the Authorize button breaks.
    """

    access_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    """Shape of a decoded access token.

    Used as documentation and for typed access in tests. The runtime decode path
    in ``core/security.decode_token`` returns a raw dict — we do not re-validate
    it through this model on the hot path, to keep a hand-rolled token from
    burning extra cycles before we 401 it anyway.
    """

    sub: str
    exp: int
    iat: int
    jti: str
    type: str
