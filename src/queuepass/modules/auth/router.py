"""Auth HTTP endpoints: register, login, me.

Everything here is thin by design:
  * parse input,
  * call ``AuthService``,
  * serialise the result,
  * map module exceptions to HTTP status + body.

No handler is longer than 8 lines of body, and no handler contains business
rules. That way the rules are tested by fast unit tests against the service,
and the router only needs smoke coverage via e2e.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel.ext.asyncio.session import AsyncSession

from queuepass.core.db import get_session
from queuepass.core.deps import get_current_user
from queuepass.modules.auth.models import User
from queuepass.modules.auth.repository import UserRepository
from queuepass.modules.auth.schemas import Token, UserCreate, UserPublic
from queuepass.modules.auth.service import (
    AuthService,
    EmailTakenError,
    InvalidCredentialsError,
    UsernameTakenError,
)

router = APIRouter()


def get_auth_service(session: AsyncSession = Depends(get_session)) -> AuthService:
    """FastAPI dependency: compose a service with a real repository.

    This is the ONLY place where ``AuthService`` and ``UserRepository`` are
    wired together at runtime. Tests (unit) skip this entirely by constructing
    the service with a fake; tests (e2e) go through the wire and land here.
    """
    return AuthService(UserRepository(session))


@router.post("/register", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
async def register(
    payload: UserCreate,
    service: AuthService = Depends(get_auth_service),
) -> User:
    try:
        return await service.register(
            payload.email,
            payload.username,
            payload.password,
            first_name=payload.first_name,
            last_name=payload.last_name,
            birthdate=payload.birthdate,
        )
    except EmailTakenError:
        # 409 Conflict is the correct semantic: the request is well-formed and
        # understood, but the email collides with an existing resource.
        # ``from None`` drops the module-local exception from the traceback —
        # the client only needs the HTTP body, and the domain error class is
        # internal implementation detail.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Email already registered"
        ) from None
    except UsernameTakenError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Username already taken"
        ) from None


@router.post("/login", response_model=Token)
async def login(
    form: OAuth2PasswordRequestForm = Depends(),
    service: AuthService = Depends(get_auth_service),
) -> Token:
    # ``OAuth2PasswordRequestForm`` puts the submitted username in ``form.username``.
    # We use that field for the EMAIL because OAuth2 password flow standardises
    # on a single identifier field — clients send ``username=<email>``. The
    # e2e login curl in the increment DoD reflects this convention.
    try:
        user = await service.authenticate(form.username, form.password)
    except InvalidCredentialsError:
        # Same message and status for unknown-email / wrong-password /
        # inactive-user. Do not differentiate — that would enable enumeration.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        ) from None
    return Token(access_token=service.issue_token(user))


@router.get("/me", response_model=UserPublic)
async def me(current_user: User = Depends(get_current_user)) -> User:
    # No DB work here — ``get_current_user`` already resolved the row. Returning
    # the ORM instance is safe because ``response_model=UserPublic`` strips
    # ``password_hash`` and every other non-public field.
    return current_user
