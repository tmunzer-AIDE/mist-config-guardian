"""Signed-in account profile, password, MFA, passkey, and session endpoints."""

from typing import Annotated

from beanie import PydanticObjectId
from fastapi import APIRouter, Depends, HTTPException, Request, status

from mist_config_guardian_backend.api.dependencies import get_session_service, require_viewer
from mist_config_guardian_backend.config import Settings, get_settings
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.session import UserSession
from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.schemas.account import (
    EmailChangeConfirmRequest,
    EmailChangeRequest,
    EmailChangeResponse,
    PasskeyListResponse,
    PasskeyRegistrationOptionsResponse,
    PasskeyRegistrationRequest,
    PasskeyRenameRequest,
    PasskeyResponse,
    PasswordChangeRequest,
    PasswordChangeResponse,
    PasswordConfirmationRequest,
    ProfileResponse,
    ProfileUpdateRequest,
    RecoveryCodesResponse,
    SessionListResponse,
    SessionResponse,
    SessionRevocationResponse,
    TotpConfirmRequest,
    TotpEnrollmentResponse,
)
from mist_config_guardian_backend.security.webauthn import WebAuthnError
from mist_config_guardian_backend.services.account import (
    AccountService,
    EmailChangeError,
    get_account_service,
)
from mist_config_guardian_backend.services.mfa import (
    ChallengeTokenError,
    InvalidMfaCodeError,
    MfaError,
    MfaService,
    PendingEnrollmentError,
    TotpAlreadyEnrolledError,
    TotpNotEnrolledError,
    get_mfa_service,
)
from mist_config_guardian_backend.services.passkeys import (
    PasskeyError,
    PasskeyNotFoundError,
    PasskeyService,
    get_passkey_service,
)
from mist_config_guardian_backend.services.sessions import SessionService
from mist_config_guardian_backend.services.users import InvalidPasswordError, UserAlreadyExistsError

router = APIRouter(prefix="/account")


def _current_session(request: Request) -> UserSession | None:
    """Return the cookie session behind this request, if there is one."""
    session = getattr(request.state, "session", None)
    return session if isinstance(session, UserSession) else None


def _require_persisted(user: User) -> PydanticObjectId:
    if user.id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Persisted user is missing an identifier",
        )
    return user.id


def _wrong_password(exc: InvalidPasswordError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))


# --------------------------------------------------------------------- profile
@router.get("/profile")
async def get_profile(user: Annotated[User, Depends(require_viewer)]) -> ProfileResponse:
    """Return the signed-in user's editable profile."""
    return ProfileResponse.from_document(user)


@router.patch("/profile")
async def update_profile(
    payload: ProfileUpdateRequest,
    user: Annotated[User, Depends(require_viewer)],
    accounts: Annotated[AccountService, Depends(get_account_service)],
) -> ProfileResponse:
    """Update display name, time zone, clock format, and landing page."""
    return ProfileResponse.from_document(await accounts.update_profile(user, payload))


# ---------------------------------------------------------------- email change
@router.post("/email-change")
async def request_email_change(
    payload: EmailChangeRequest,
    user: Annotated[User, Depends(require_viewer)],
    accounts: Annotated[AccountService, Depends(get_account_service)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> EmailChangeResponse:
    """Start a change of the account's email address.

    Email delivery is not implemented: this deployment has no mail transport.
    Outside production the confirmation token is returned here so the change can
    still be completed; in production an operator must deliver it out of band.
    """
    try:
        updated, token = await accounts.request_email_change(
            user,
            new_email=str(payload.new_email),
            password=payload.password.get_secret_value(),
        )
    except InvalidPasswordError as exc:
        raise _wrong_password(exc) from exc
    except UserAlreadyExistsError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except EmailChangeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    pending = updated.pending_email_change
    if pending is None:  # pragma: no cover - defensive, the service just set it
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="The email change was not recorded",
        )
    return EmailChangeResponse(
        pending_email=pending.new_email,
        expires_at=pending.expires_at,
        confirmation_token=token if settings.environment != "production" else None,
    )


@router.post("/email-change/confirm")
async def confirm_email_change(
    payload: EmailChangeConfirmRequest,
    user: Annotated[User, Depends(require_viewer)],
    accounts: Annotated[AccountService, Depends(get_account_service)],
) -> ProfileResponse:
    """Apply a pending email change using its confirmation token."""
    try:
        updated = await accounts.confirm_email_change(user, payload.token)
    except UserAlreadyExistsError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except EmailChangeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return ProfileResponse.from_document(updated)


@router.delete("/email-change")
async def cancel_email_change(
    user: Annotated[User, Depends(require_viewer)],
    accounts: Annotated[AccountService, Depends(get_account_service)],
) -> ProfileResponse:
    """Cancel a pending email change."""
    try:
        updated = await accounts.cancel_email_change(user)
    except EmailChangeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return ProfileResponse.from_document(updated)


# -------------------------------------------------------------------- password
@router.post("/password")
async def change_password(
    payload: PasswordChangeRequest,
    request: Request,
    user: Annotated[User, Depends(require_viewer)],
    accounts: Annotated[AccountService, Depends(get_account_service)],
    sessions: Annotated[SessionService, Depends(get_session_service)],
) -> PasswordChangeResponse:
    """Replace the account password and sign every other session out."""
    try:
        updated = await accounts.change_password(
            user,
            current_password=payload.current_password.get_secret_value(),
            new_password=payload.new_password.get_secret_value(),
        )
    except InvalidPasswordError as exc:
        raise _wrong_password(exc) from exc

    session = _current_session(request)
    revoked = await sessions.revoke_all(
        _require_persisted(updated),
        except_session_id=session.id if session is not None else None,
    )
    return PasswordChangeResponse(
        password_changed_at=updated.password_changed_at or utc_now(),
        revoked_sessions=revoked,
    )


# -------------------------------------------------------------------- sessions
@router.get("/sessions")
async def list_sessions(
    request: Request,
    user: Annotated[User, Depends(require_viewer)],
    sessions: Annotated[SessionService, Depends(get_session_service)],
) -> SessionListResponse:
    """List every live session for the signed-in user."""
    current = _current_session(request)
    current_id = current.id if current is not None else None
    items = [
        SessionResponse.from_document(session, current=session.id == current_id)
        for session in await sessions.list_for_user(_require_persisted(user))
    ]
    return SessionListResponse(items=items, total=len(items))


@router.post("/sessions/revoke-others")
async def revoke_other_sessions(
    request: Request,
    user: Annotated[User, Depends(require_viewer)],
    sessions: Annotated[SessionService, Depends(get_session_service)],
) -> SessionRevocationResponse:
    """Sign out every session except the one making this request."""
    current = _current_session(request)
    revoked = await sessions.revoke_all(
        _require_persisted(user),
        except_session_id=current.id if current is not None else None,
    )
    return SessionRevocationResponse(revoked_sessions=revoked)


@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: PydanticObjectId,
    user: Annotated[User, Depends(require_viewer)],
    sessions: Annotated[SessionService, Depends(get_session_service)],
) -> SessionRevocationResponse:
    """Sign out one of the signed-in user's own sessions."""
    revoked = await sessions.revoke(_require_persisted(user), session_id)
    if not revoked:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    return SessionRevocationResponse(revoked_sessions=1)


# ------------------------------------------------------------------------ totp
@router.post("/totp/enroll")
async def enroll_totp(
    user: Annotated[User, Depends(require_viewer)],
    mfa: Annotated[MfaService, Depends(get_mfa_service)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> TotpEnrollmentResponse:
    """Start authenticator enrollment and return its secret exactly once."""
    try:
        started = await mfa.begin_totp_enrollment(user)
    except TotpAlreadyEnrolledError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except MfaError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return TotpEnrollmentResponse(
        secret=started.secret,
        otpauth_uri=started.otpauth_uri,
        issuer=settings.totp_issuer,
    )


@router.post("/totp/confirm")
async def confirm_totp(
    payload: TotpConfirmRequest,
    user: Annotated[User, Depends(require_viewer)],
    mfa: Annotated[MfaService, Depends(get_mfa_service)],
) -> RecoveryCodesResponse:
    """Confirm authenticator enrollment and return recovery codes exactly once."""
    try:
        codes = await mfa.confirm_totp_enrollment(user, payload.code)
    except (TotpAlreadyEnrolledError, PendingEnrollmentError) as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except InvalidMfaCodeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except MfaError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return RecoveryCodesResponse(recovery_codes=codes, generated_at=utc_now())


@router.delete("/totp")
async def disable_totp(
    payload: PasswordConfirmationRequest,
    user: Annotated[User, Depends(require_viewer)],
    mfa: Annotated[MfaService, Depends(get_mfa_service)],
) -> ProfileResponse:
    """Remove the account's authenticator enrollment after re-entering the password."""
    try:
        updated = await mfa.disable_totp(user, payload.password.get_secret_value())
    except InvalidPasswordError as exc:
        raise _wrong_password(exc) from exc
    except TotpNotEnrolledError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return ProfileResponse.from_document(updated)


@router.post("/totp/recovery-codes")
async def regenerate_recovery_codes(
    payload: PasswordConfirmationRequest,
    user: Annotated[User, Depends(require_viewer)],
    mfa: Annotated[MfaService, Depends(get_mfa_service)],
) -> RecoveryCodesResponse:
    """Replace the account's recovery codes and return them exactly once."""
    try:
        codes = await mfa.regenerate_recovery_codes(user, payload.password.get_secret_value())
    except InvalidPasswordError as exc:
        raise _wrong_password(exc) from exc
    except TotpNotEnrolledError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return RecoveryCodesResponse(recovery_codes=codes, generated_at=utc_now())


# -------------------------------------------------------------------- passkeys
@router.get("/passkeys")
async def list_passkeys(
    user: Annotated[User, Depends(require_viewer)],
    passkeys: Annotated[PasskeyService, Depends(get_passkey_service)],
) -> PasskeyListResponse:
    """List the signed-in user's registered passkeys."""
    items = [
        PasskeyResponse.from_document(credential)
        for credential in await passkeys.list_for_user(_require_persisted(user))
    ]
    return PasskeyListResponse(items=items, total=len(items))


@router.post("/passkeys/options")
async def passkey_registration_options(
    user: Annotated[User, Depends(require_viewer)],
    passkeys: Annotated[PasskeyService, Depends(get_passkey_service)],
) -> PasskeyRegistrationOptionsResponse:
    """Return WebAuthn options for registering a new passkey.

    The challenge stays on the server; the returned token only names it.
    """
    try:
        options, challenge_token = await passkeys.begin_registration(user)
    except (PasskeyError, WebAuthnError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return PasskeyRegistrationOptionsResponse(challenge_token=challenge_token, options=options)


@router.post("/passkeys", status_code=status.HTTP_201_CREATED)
async def register_passkey(
    payload: PasskeyRegistrationRequest,
    user: Annotated[User, Depends(require_viewer)],
    passkeys: Annotated[PasskeyService, Depends(get_passkey_service)],
) -> PasskeyResponse:
    """Verify a passkey attestation and store the credential."""
    try:
        credential = await passkeys.complete_registration(
            user,
            challenge_token=payload.challenge_token,
            credential=payload.credential,
            name=payload.name,
        )
    except (PasskeyError, ChallengeTokenError, WebAuthnError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return PasskeyResponse.from_document(credential)


@router.patch("/passkeys/{credential_id}")
async def rename_passkey(
    credential_id: PydanticObjectId,
    payload: PasskeyRenameRequest,
    user: Annotated[User, Depends(require_viewer)],
    passkeys: Annotated[PasskeyService, Depends(get_passkey_service)],
) -> PasskeyResponse:
    """Rename one of the signed-in user's passkeys."""
    try:
        credential = await passkeys.rename(user, credential_id, payload.name)
    except PasskeyNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return PasskeyResponse.from_document(credential)


@router.delete("/passkeys/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_passkey(
    credential_id: PydanticObjectId,
    user: Annotated[User, Depends(require_viewer)],
    passkeys: Annotated[PasskeyService, Depends(get_passkey_service)],
) -> None:
    """Remove one of the signed-in user's passkeys."""
    try:
        await passkeys.delete(user, credential_id)
    except PasskeyNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
