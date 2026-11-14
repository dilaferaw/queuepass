"""Auth business logic — no FastAPI, no Session, no SQL.

What lives here:
  * Uniqueness policy (email/username taken).
  * Password hashing (delegated to ``core/security.hash_password``).
  * Credential verification (with user-enumeration defense).
  * Token issuance (delegated to ``core/security.create_access_token``).

What does NOT live here:
  * HTTP status codes (router owns those).
  * SQL (repository owns that).
  * ``Request``/``Response``/``HTTPException`` — importing ``fastapi`` here
    would make this module unusable outside HTTP, and it would defeat the whole
    point of the layered design.

Testability consequence: ``AuthService`` accepts any ``UserRepositoryProtocol``,
so unit tests inject a pure-Python fake and never touch Postgres. The e2e tests
run the real repo, but they only exercise the wire behaviour — the correctness of
the rules above is covered in milliseconds by the unit tests.
"""

from datetime import date

from queuepass.core.security import (
    DUMMY_PASSWORD_HASH,
    create_access_token,
    hash_password,
    verify_password,
)
from queuepass.modules.auth.models import User
from queuepass.modules.auth.repository import UserRepositoryProtocol


# Module-local exception hierarchy. These are auth-domain errors, not shared
# infrastructure, so they live here rather than in ``shared/``. The router is
# the only consumer — it maps each to an HTTP response.
class AuthError(Exception):
    """Base for all auth-domain failures."""


class EmailTakenError(AuthError):
    """Registration refused: email already in use."""


class UsernameTakenError(AuthError):
    """Registration refused: username already in use."""


class InvalidCredentialsError(AuthError):
    """Login refused. Deliberately indistinguishable across failure modes
    (unknown email, wrong password, inactive user) so the API cannot be used
    to enumerate accounts."""


class AuthService:
    def __init__(self, repo: UserRepositoryProtocol) -> None:
        self.repo = repo

    async def register(
        self,
        email: str,
        username: str,
        password: str,
        *,
        first_name: str,
        last_name: str,
        birthdate: date,
    ) -> User:
        """Create a new user. Raises ``EmailTakenError``/``UsernameTakenError``.

        ``first_name``, ``last_name``, and ``birthdate`` are keyword-only and
        required — matching the increment spec's ``register(email, username,
        password)`` prefix while making the new fields self-documenting at
        every call site. ``birthdate`` is a ``date`` (not an int age) — see
        ``models.py`` for the rationale.
        """
        # Normalise at the service boundary so every layer downstream can
        # treat ``user.email`` as canonical lowercase. If we normalised in the
        # repository instead, ``register`` and ``authenticate`` could disagree.
        email = email.lower()

        if await self.repo.get_by_email(email) is not None:
            raise EmailTakenError(email)
        if await self.repo.get_by_username(username) is not None:
            raise UsernameTakenError(username)

        user = User(
            email=email,
            username=username,
            password_hash=hash_password(password),
            first_name=first_name,
            last_name=last_name,
            birthdate=birthdate,
        )
        return await self.repo.add(user)

    async def authenticate(self, email: str, password: str) -> User:
        """Verify credentials. Raises ``InvalidCredentialsError`` on any failure.

        Timing side-channel: on unknown email we still run ``verify_password``
        against a dummy hash so the request takes roughly the same wall-clock
        time as a real verify. Without this, an attacker can distinguish
        "email not registered" (fast) from "wrong password" (slow) even when
        both return 401.

        The order of checks is also deliberate: password first, then active
        check. If we checked ``is_active`` first, an inactive account would
        return faster than an active one — same enumeration leak, inverted.
        """
        email = email.lower()
        user = await self.repo.get_by_email(email)

        if user is None:
            # Burn ~argon2 cost; the return value is ignored.
            verify_password(password, DUMMY_PASSWORD_HASH)
            raise InvalidCredentialsError()

        if not verify_password(password, user.password_hash):
            raise InvalidCredentialsError()

        if not user.is_active:
            raise InvalidCredentialsError()

        return user

    def issue_token(self, user: User) -> str:
        """Mint an access token for an authenticated user.

        Sync on purpose: token creation is pure CPU and does not touch the DB.
        Keeping it sync lets callers use it from sync contexts (CLI, future
        Celery task) without an event loop.

        No ``if user.id is None`` guard here any more: ``User.id`` is a
        ``default_factory=uuid4`` field, so it is populated at construction
        time (see ``models.py``). The guard was a holdover from the int-PK
        design where ``id`` only existed after INSERT.
        """
        return create_access_token(user.id)
