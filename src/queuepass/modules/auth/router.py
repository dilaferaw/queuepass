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

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel.ext.asyncio.session import AsyncSession

from queuepass.core.db import get_session
from queuepass.core.deps import get_current_user, get_revocation_store, oauth2_scheme
from queuepass.modules.auth.models import User
from queuepass.modules.auth.repository import UserRepository
from queuepass.modules.auth.revocation import RevocationStore
from queuepass.modules.auth.schemas import Token, UserCreate, UserPublic
from queuepass.modules.auth.service import (
    AuthService,
    EmailTakenError,
    InvalidCredentialsError,
    UsernameTakenError,
)

router = APIRouter()


def get_auth_service(
    session: AsyncSession = Depends(get_session),
    revocation: RevocationStore = Depends(get_revocation_store),
) -> AuthService:
    """FastAPI dependency: compose a service with real infrastructure.

    This is the ONLY place where ``AuthService``, ``UserRepository``, and
    ``RevocationStore`` are wired together at runtime. Tests (unit) skip this
    entirely by constructing the service with fakes; tests (e2e) go through
    the wire and land here.
    """
    return AuthService(UserRepository(session), revocation)


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


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    token: str = Depends(oauth2_scheme),
    service: AuthService = Depends(get_auth_service),
) -> None:
    """Revoke the current bearer token. Idempotent 204.

    Uses raw ``oauth2_scheme`` rather than ``get_current_user``: a revoked
    token would 401 inside the dep, making retry impossible. Expired tokens
    are accepted as no-ops (the token already fails ``exp`` validation); a
    malformed token is still a 401, since we cannot determine what to revoke.
    """
    try:
        await service.logout(token)
    except jwt.ExpiredSignatureError:
        return
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(
    user: User = Depends(get_current_user),
    service: AuthService = Depends(get_auth_service),
) -> None:
    # ``get_current_user`` is correct here: we need a valid identity, and a
    # revoked token 401ing is exactly what we want (the user is already
    # logged out everywhere).
    await service.logout_all(str(user.id))
