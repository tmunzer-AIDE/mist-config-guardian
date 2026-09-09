"""Proving, again, that the person at the keyboard is the account holder.

A session or bearer token proves who signed in; it does not prove who is
using it now. Changes that outlive the session — enrolling a second factor,
replacing a credential the deployment authenticates with — ask for the
password again, so a stolen session cannot convert temporary access into
something durable.

Enrolled accounts additionally pass through ``require_fresh_mfa``, which is
declared on the routes themselves. It admits accounts with no authenticator,
so it strengthens this check rather than replacing it.
"""

from fastapi import HTTPException, status

from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.security.auth import verify_password
from mist_config_guardian_backend.services.throttling import ThrottleService, reserve_or_raise

_WRONG_PASSWORD_DETAIL = "The password you entered is incorrect"  # noqa: S105 - a message, not a credential


async def confirm_password(user: User, password: str, throttle: ThrottleService) -> None:
    """Check a re-entered password, counting a wrong one against the account.

    A stolen session must not be able to guess the password it lacks at
    leisure, so the limit that governs sign-in governs this too.
    """
    if user.id is None:
        msg = "Cannot confirm a password for an unpersisted user"
        raise ValueError(msg)
    scope = throttle.user(user.id)
    await reserve_or_raise(throttle, scope)
    if not verify_password(password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=_WRONG_PASSWORD_DETAIL)
    await throttle.succeeded(scope)
