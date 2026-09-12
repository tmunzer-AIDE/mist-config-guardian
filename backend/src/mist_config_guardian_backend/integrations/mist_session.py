"""Mist HTTP login sessions, with regional cookies and CSRF protection."""

import json
from contextlib import suppress
from http import HTTPStatus
from typing import Any

import httpx


class MistMfaChallengeError(ValueError):
    """Mist accepted the password but requires a second factor."""


SESSION_PREFIX = "mist-session:"


def credential_headers(credential: str) -> dict[str, str]:
    if credential.startswith(SESSION_PREFIX):
        data = json.loads(credential.removeprefix(SESSION_PREFIX))
        return {"Cookie": data["cookie"], "X-CSRFToken": data["csrf"], "Referer": data["origin"] + "/"}
    return {"Authorization": f"Token {credential}"}


def session_credential(client: httpx.AsyncClient) -> str:
    cookies = client.cookies
    csrf = next((value for key, value in cookies.items() if key == "csrftoken" or key.startswith("csrftoken.")), None)
    if not csrf or not any(key == "sessionid" or key.startswith("sessionid.") for key in cookies):
        msg = "Mist did not return a complete login session"
        raise ValueError(msg)
    cookie = client.build_request("GET", "/api/v1/self").headers.get("cookie", "")
    return SESSION_PREFIX + json.dumps({"cookie": cookie, "csrf": csrf, "origin": str(client.base_url).rstrip("/")})


async def logout_session(client: httpx.AsyncClient) -> None:
    # Best effort: cleanup must not replace an authentication or restore failure.
    if client.cookies:
        with suppress(ValueError):
            client.headers.update(credential_headers(session_credential(client)))
    with suppress(httpx.HTTPError):
        await client.post("/api/v1/logout")


async def login_session(client: httpx.AsyncClient, payload: dict[str, str]) -> tuple[str, dict[str, Any]]:
    response = await client.post("/api/v1/login", json=payload)
    if response.status_code != HTTPStatus.OK:
        msg = "Mist rejected the login or multi-factor code"
        raise ValueError(msg)
    if response.content:
        login = response.json()
        if isinstance(login, dict):
            require_completed_mfa(login)
    credential = session_credential(client)
    client.headers.update(credential_headers(credential))
    response = await client.get("/api/v1/self")
    if response.status_code != HTTPStatus.OK:
        msg = "Mist rejected the login"
        raise ValueError(msg)
    identity = response.json()
    if not isinstance(identity, dict) or not identity.get("email"):
        msg = "Mist returned an invalid identity response"
        raise ValueError(msg)
    require_completed_mfa(identity)
    if str(identity["email"]).lower() != payload["email"].lower():
        msg = "Mist returned a different account identity"
        raise ValueError(msg)
    return session_credential(client), identity


def require_completed_mfa(identity: dict[str, Any]) -> None:
    if identity.get("two_factor_required") and identity.get("two_factor_passed") is not True:
        msg = "Enter a valid Mist multi-factor code"
        raise MistMfaChallengeError(msg)
