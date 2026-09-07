"""Local authentication endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm

from mist_config_guardian_backend.api.dependencies import (
    get_current_user,
    get_session_service,
    get_user_service,
)
from mist_config_guardian_backend.config import Settings, get_settings
from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.schemas.auth import (
    BootstrapAdminRequest,
    LoginSuccessResponse,
    LogoutResponse,
    MfaChallengeResponse,
    MfaLoginRequest,
    PasskeyAuthenticationOptionsResponse,
    PasskeyAuthenticationRequest,
    UserResponse,
)
from mist_config_guardian_backend.security.auth import create_access_token
from mist_config_guardian_backend.security.webauthn import WebAuthnError
from mist_config_guardian_backend.services.mfa import (
    ChallengeTokenError,
    MfaService,
    get_mfa_service,
)
from mist_config_guardian_backend.services.passkeys import (
    PasskeyError,
    PasskeyService,
    get_passkey_service,
)
from mist_config_guardian_backend.services.sessions import CsrfError, SessionService
from mist_config_guardian_backend.services.users import (
    BootstrapClosedError,
    InvalidBootstrapTokenError,
    UserAlreadyExistsError,
    UserService,
)

router = APIRouter(prefix="/auth")

_INVALID_CREDENTIALS = "Invalid email or password"
_INVALID_SECOND_FACTOR = "That code is not valid"


@router.post("/bootstrap", status_code=status.HTTP_201_CREATED)
async def bootstrap_administrator(
    request: BootstrapAdminRequest,
    users: Annotated[UserService, Depends(get_user_service)],
) -> UserResponse:
    """Create the first local administrator."""
    try:
        user = await users.bootstrap_administrator(request)
    except BootstrapClosedError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except InvalidBootstrapTokenError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except UserAlreadyExistsError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return UserResponse.from_document(user)


@router.post("/login")
async def login(  # noqa: PLR0913, PLR0917 - one dependency per collaborating service
    request: Request,
    response: Response,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    users: Annotated[UserService, Depends(get_user_service)],
    sessions: Annotated[SessionService, Depends(get_session_service)],
    mfa: Annotated[MfaService, Depends(get_mfa_service)],
    passkeys: Annotated[PasskeyService, Depends(get_passkey_service)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> MfaChallengeResponse | LoginSuccessResponse:
    """Authenticate a local account with an email address and password.

    A successful sign-in always sets the browser session and CSRF cookies and
    additionally returns a bearer access token, so command-line callers can use
    the same endpoint. Accounts with an authenticator enrolled receive an
    ``mfa_required`` challenge instead and get no session until they complete
    ``POST /auth/login/mfa``. Failures are indistinguishable whether or not the
    email address exists.
    """
    user = await users.authenticate(form.username, form.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_INVALID_CREDENTIALS,
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user.totp is not None:
        return MfaChallengeResponse(
            challenge_token=mfa.issue_login_challenge(user),
            methods=["totp", "recovery_code"],
        )
    return await _complete_sign_in(
        user,
        request=request,
        response=response,
        users=users,
        sessions=sessions,
        passkeys=passkeys,
        settings=settings,
        mfa_verified=False,
    )


@router.post("/login/mfa")
async def complete_mfa_login(  # noqa: PLR0913, PLR0917 - one dependency per collaborating service
    payload: MfaLoginRequest,
    request: Request,
    response: Response,
    users: Annotated[UserService, Depends(get_user_service)],
    sessions: Annotated[SessionService, Depends(get_session_service)],
    mfa: Annotated[MfaService, Depends(get_mfa_service)],
    passkeys: Annotated[PasskeyService, Depends(get_passkey_service)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> LoginSuccessResponse:
    """Complete a sign-in with an authenticator code or a single-use recovery code."""
    rejected = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=_INVALID_SECOND_FACTOR,
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        user_id = mfa.resolve_login_challenge(payload.challenge_token)
    except ChallengeTokenError as exc:
        raise rejected from exc

    user = await users.get_by_id(user_id)
    if user is None or not user.is_active or not await mfa.verify_second_factor(user, payload.code):
        raise rejected
    return await _complete_sign_in(
        user,
        request=request,
        response=response,
        users=users,
        sessions=sessions,
        passkeys=passkeys,
        settings=settings,
        mfa_verified=True,
    )


@router.post("/passkey/options")
async def passkey_authentication_options(
    passkeys: Annotated[PasskeyService, Depends(get_passkey_service)],
) -> PasskeyAuthenticationOptionsResponse:
    """Start a passwordless sign-in and return its WebAuthn options.

    The challenge itself stays on the server; the returned token only names it.
    """
    options, challenge_token = await passkeys.begin_authentication()
    return PasskeyAuthenticationOptionsResponse(challenge_token=challenge_token, options=options)


@router.post("/passkey/verify")
async def verify_passkey_authentication(  # noqa: PLR0913, PLR0917 - one dependency per collaborating service
    payload: PasskeyAuthenticationRequest,
    request: Request,
    response: Response,
    users: Annotated[UserService, Depends(get_user_service)],
    sessions: Annotated[SessionService, Depends(get_session_service)],
    passkeys: Annotated[PasskeyService, Depends(get_passkey_service)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> LoginSuccessResponse:
    """Complete a passwordless sign-in by verifying a passkey assertion."""
    try:
        user, _credential = await passkeys.complete_authentication(
            challenge_token=payload.challenge_token,
            credential=payload.credential,
        )
    except (PasskeyError, ChallengeTokenError, WebAuthnError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="That passkey could not be verified",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    return await _complete_sign_in(
        user,
        request=request,
        response=response,
        users=users,
        sessions=sessions,
        passkeys=passkeys,
        settings=settings,
        mfa_verified=True,
    )


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    sessions: Annotated[SessionService, Depends(get_session_service)],
) -> LogoutResponse:
    """End the current session and clear its cookies, whether or not one exists."""
    try:
        user = await sessions.resolve_request_user(request)
    except CsrfError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    session = getattr(request.state, "session", None)
    if user is not None and user.id is not None and session is not None and session.id is not None:
        await sessions.revoke(user.id, session.id)
    sessions.clear(response)
    return LogoutResponse()


@router.get("/me")
async def current_user(
    user: Annotated[User, Depends(get_current_user)],
    passkeys: Annotated[PasskeyService, Depends(get_passkey_service)],
) -> UserResponse:
    """Return the signed-in user with preferences and second-factor status."""
    return UserResponse.from_document(user, passkey_count=await passkeys.count_for_user(user.id))


async def _complete_sign_in(  # noqa: PLR0913 - a sign-in touches every collaborator
    user: User,
    *,
    request: Request,
    response: Response,
    users: UserService,
    sessions: SessionService,
    passkeys: PasskeyService,
    settings: Settings,
    mfa_verified: bool,
) -> LoginSuccessResponse:
    """Start a session, stamp the sign-in, and build the shared success body."""
    await sessions.start(
        user,
        response=response,
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
        mfa_verified=mfa_verified,
    )
    await users.record_login(user)
    token, expires_in = create_access_token(user, settings)
    return LoginSuccessResponse(
        user=UserResponse.from_document(user, passkey_count=await passkeys.count_for_user(user.id)),
        access_token=token,
        expires_in=expires_in,
    )
