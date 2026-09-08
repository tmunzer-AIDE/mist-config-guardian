"""Revocable cookie sessions with double-submit CSRF protection."""

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

from beanie import PydanticObjectId
from fastapi import Request, Response

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.session import UserSession
from mist_config_guardian_backend.models.user import User

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
_TOKEN_BYTES = 32


class CsrfError(PermissionError):
    """Raised when a state-changing request fails CSRF validation."""


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class SessionService:
    """Issue, validate, refresh, and revoke authenticated sessions."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    # ------------------------------------------------------------------ issue
    async def start(
        self,
        user: User,
        *,
        response: Response,
        user_agent: str | None,
        ip_address: str | None,
        mfa_verified: bool,
    ) -> UserSession:
        """Create a session and attach its cookies to the response."""
        if user.id is None:
            msg = "Cannot start a session for an unpersisted user"
            raise ValueError(msg)

        token = secrets.token_urlsafe(_TOKEN_BYTES)
        csrf = secrets.token_urlsafe(_TOKEN_BYTES)
        now = utc_now()
        session = UserSession(
            user_id=user.id,
            token_hash=_digest(token),
            csrf_hash=_digest(csrf),
            label=self._label(user_agent),
            user_agent=user_agent,
            ip_address=ip_address,
            expires_at=now + timedelta(days=self._settings.session_absolute_lifetime_days),
            mfa_verified_at=now if mfa_verified else None,
        )
        await session.insert()
        self._write_cookies(response, token=token, csrf=csrf)
        return session

    def clear(self, response: Response) -> None:
        """Remove session cookies from the browser."""
        for name in (self._settings.session_cookie_name, self._settings.csrf_cookie_name):
            response.delete_cookie(
                name,
                path="/",
                domain=self._settings.session_cookie_domain,
                samesite=self._settings.session_cookie_same_site,
                secure=self._settings.session_cookie_secure,
            )

    # ----------------------------------------------------------------- verify
    async def resolve_request_user(self, request: Request) -> User | None:
        """Return the authenticated user for a cookie session, if any.

        Enforces CSRF on state-changing methods and refuses idle or revoked
        sessions. Returns ``None`` when no session cookie is present so that the
        caller can fall back to bearer-token authentication.
        """
        token = request.cookies.get(self._settings.session_cookie_name)
        if not token:
            return None

        session = await UserSession.find_one(UserSession.token_hash == _digest(token))
        if session is None or not self._is_live(session):
            return None

        if request.method.upper() not in _SAFE_METHODS:
            self._verify_csrf(request, session)

        user = await User.get(session.user_id)
        if user is None or not user.is_active:
            return None

        await self._touch(session)
        request.state.session = session
        return user

    def _verify_csrf(self, request: Request, session: UserSession) -> None:
        header = request.headers.get(self._settings.csrf_header_name)
        cookie = request.cookies.get(self._settings.csrf_cookie_name)
        if not header or not cookie or not hmac.compare_digest(header, cookie):
            msg = "Missing or invalid CSRF token"
            raise CsrfError(msg)
        if not hmac.compare_digest(_digest(header), session.csrf_hash):
            msg = "CSRF token does not belong to this session"
            raise CsrfError(msg)

    def _is_live(self, session: UserSession) -> bool:
        now = utc_now()
        if session.revoked_at is not None:
            return False
        if _aware(session.expires_at) <= now:
            return False
        idle_limit = timedelta(minutes=self._settings.session_idle_timeout_minutes)
        return _aware(session.last_seen_at) + idle_limit > now

    async def _touch(self, session: UserSession) -> None:
        """Record activity without writing anything else this request loaded.

        A whole-document save would carry the ``revoked_at`` of ``None`` this
        request read back over a revocation that happened since, bringing a
        revoked session back to life. The write names only the timestamps and
        applies only while the session is still live.
        """
        now = utc_now()
        if (now - _aware(session.last_seen_at)) < timedelta(minutes=1):
            return
        result = await UserSession.get_pymongo_collection().update_one(
            {"_id": session.id, "revoked_at": None},
            {"$set": {"last_seen_at": now, "updated_at": now}},
        )
        if result.modified_count:
            session.last_seen_at = now

    # ------------------------------------------------------------- management
    async def list_for_user(self, user_id: PydanticObjectId) -> list[UserSession]:
        """Return a user's live sessions, most recently seen first."""
        sessions = (
            await UserSession.find(
                UserSession.user_id == user_id,
                UserSession.revoked_at == None,  # noqa: E711 - Beanie query operator
            )
            .sort("-last_seen_at")
            .to_list()
        )
        return [session for session in sessions if self._is_live(session)]

    async def revoke(self, user_id: PydanticObjectId, session_id: PydanticObjectId) -> bool:
        """Revoke one of a user's own sessions.

        Revocation is monotonic and written as one conditional field update,
        so it cannot be undone by another request that read the session while
        it was still live.
        """
        now = utc_now()
        result = await UserSession.get_pymongo_collection().update_one(
            {"_id": session_id, "user_id": user_id, "revoked_at": None},
            {"$set": {"revoked_at": now, "updated_at": now}},
        )
        return result.modified_count == 1

    async def revoke_all(
        self,
        user_id: PydanticObjectId,
        *,
        except_session_id: PydanticObjectId | None = None,
    ) -> int:
        """Revoke every session for a user, optionally keeping the current one."""
        query = UserSession.find(
            UserSession.user_id == user_id,
            UserSession.revoked_at == None,  # noqa: E711 - Beanie query operator
        )
        del query
        now = utc_now()
        criteria: dict[str, object] = {"user_id": user_id, "revoked_at": None}
        if except_session_id is not None:
            criteria["_id"] = {"$ne": except_session_id}
        result = await UserSession.get_pymongo_collection().update_many(
            criteria,
            {"$set": {"revoked_at": now, "updated_at": now}},
        )
        return int(result.modified_count)

    async def mark_mfa_verified(self, session: UserSession) -> None:
        """Record a successful step-up authentication on a session."""
        now = utc_now()
        await UserSession.get_pymongo_collection().update_one(
            {"_id": session.id, "revoked_at": None},
            {"$set": {"mfa_verified_at": now, "updated_at": now}},
        )
        session.mfa_verified_at = now

    def has_fresh_mfa(self, session: UserSession | None) -> bool:
        """Report whether a session completed step-up inside the allowed window."""
        if session is None or session.mfa_verified_at is None:
            return False
        window = timedelta(minutes=self._settings.mfa_step_up_window_minutes)
        return _aware(session.mfa_verified_at) + window > utc_now()

    # --------------------------------------------------------------- internals
    def _write_cookies(self, response: Response, *, token: str, csrf: str) -> None:
        max_age = self._settings.session_absolute_lifetime_days * 24 * 60 * 60
        for name, value, http_only in (
            (self._settings.session_cookie_name, token, True),
            # The CSRF cookie is readable by the browser application so it can
            # echo the value back in the CSRF header; the paired httpOnly
            # session cookie is what carries authority, so exposing this value
            # on its own grants nothing.
            (self._settings.csrf_cookie_name, csrf, False),
        ):
            response.set_cookie(
                name,
                value,
                max_age=max_age,
                path="/",
                domain=self._settings.session_cookie_domain,
                secure=self._settings.session_cookie_secure,
                httponly=http_only,
                samesite=self._settings.session_cookie_same_site,
            )

    @staticmethod
    def _label(user_agent: str | None) -> str:
        if not user_agent:
            return "Unknown client"
        agent = user_agent
        browser = next(
            (name for name in ("Firefox", "Edg", "Chrome", "Safari") if name in agent),
            None,
        )
        platform = next(
            (name for name in ("Windows", "Macintosh", "Linux", "Android", "iPhone") if name in agent),
            None,
        )
        readable = {"Edg": "Edge", "Macintosh": "macOS", "iPhone": "iOS"}
        if browser and platform:
            return f"{readable.get(browser, browser)} on {readable.get(platform, platform)}"
        return readable.get(browser or "", browser or agent[:60])


def _aware(value: datetime) -> datetime:
    """Treat naive datetimes read back from MongoDB as UTC."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
