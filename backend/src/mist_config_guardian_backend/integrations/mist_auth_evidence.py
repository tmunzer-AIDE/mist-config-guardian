"""WLAN authentication evidence scoped by immutable WLAN identity, never SSID prose."""

import asyncio
import json
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import UUID

import httpx

from mist_config_guardian_backend.impact.contracts import (
    AuthEventRow,
    AuthEvidence,
    DispatchDenial,
    Window,
    WlanRemovalPlan,
    WlanTarget,
)
from mist_config_guardian_backend.impact.limits import MAX_PORT_EVENTS
from mist_config_guardian_backend.integrations.mist_port_history import MistPortHistoryClient
from mist_config_guardian_backend.models.base import utc_now

_SUCCESSES = {"CLIENT_AUTHENTICATED", "CLIENT_AUTH_ASSOCIATION", "CLIENT_AUTH_REASSOCIATION"}
_FAILURES = {
    "MARVIS_EVENT_CLIENT_AUTH_FAILURE",
    "MARVIS_EVENT_CLIENT_AUTH_DENIED",
    "MARVIS_EVENT_CLIENT_MAC_AUTH_FAILURE",
}
_MAX_BYTES = 262_144
_MAX_ROWS = 1000


class MistImpactEvidenceClient(MistPortHistoryClient):
    async def capture_auth(
        self,
        *,
        plan: WlanRemovalPlan,
        target: WlanTarget,
        mist_org_id: UUID,
        window: Window,
        reserve_dispatch: Callable[[], Awaitable[DispatchDenial | None]],
    ) -> AuthEvidence:
        if (
            target not in plan.targets
            or not target.auth_changed
            or window.start != plan.changed_at - timedelta(hours=1)
            or window.end > plan.changed_at + timedelta(hours=1)
        ):
            msg = "Authentication history is not authorized by the plan"
            raise ValueError(msg)
        denial = await reserve_dispatch()
        if denial:
            return AuthEvidence(
                target_handle=target.handle,
                window=window,
                captured_at=utc_now(),
                state="dispatch_denied",
                dispatch_denial=denial,
                reason=denial.explanation,
            )
        status, size = None, None
        try:
            async with (
                asyncio.timeout(20),
                self._client.stream(
                    "GET",
                    f"/api/v1/sites/{target.site_id}/clients/events/search",
                    params={
                        "wlan_id": str(target.wlan_id),
                        "start": str(int(window.start.timestamp())),
                        "end": str(int(window.end.timestamp())),
                        "limit": str(_MAX_ROWS),
                    },
                ) as response,
            ):
                status = response.status_code
                response.raise_for_status()
                body = bytearray()
                size = 0
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    size = len(body)
                    if size > _MAX_BYTES:
                        return AuthEvidence(
                            target_handle=target.handle,
                            window=window,
                            captured_at=utc_now(),
                            state="partial",
                            reason="Authentication response byte limit reached.",
                            http_status=status,
                            response_bytes=size,
                        )
            return parse_auth(json.loads(body), plan, target, mist_org_id, window).model_copy(
                update={"http_status": status, "response_bytes": size}
            )
        except httpx.HTTPStatusError:
            reason = f"Mist returned HTTP {status} during WLAN authentication collection."
        except (httpx.HTTPError, TimeoutError):
            reason = "Authentication collection transport failed or timed out."
        except (ValueError, TypeError, OverflowError):
            reason = "Authentication evidence rejected: invalid scope, interval or event identity."
        return AuthEvidence(
            target_handle=target.handle,
            window=window,
            captured_at=utc_now(),
            state="error",
            reason=reason,
            http_status=status,
            response_bytes=size,
        )


def parse_auth(
    payload: object, plan: WlanRemovalPlan, target: WlanTarget, mist_org_id: UUID, window: Window
) -> AuthEvidence:
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        msg = "Missing authentication results"
        raise TypeError(msg)
    rows = payload["results"]
    if (
        type(payload.get("total")) is not int
        or payload["total"] < len(rows)
        or len(rows) > _MAX_ROWS
        or type(payload.get("start")) not in {int, float}
        or type(payload.get("end")) not in {int, float}
        or payload["start"] != int(window.start.timestamp())
        or payload["end"] != int(window.end.timestamp())
    ):
        msg = "Authentication envelope is not the requested window"
        raise ValueError(msg)
    accepted = {}
    missing_identity = False
    for row in rows:
        if (
            not isinstance(row, dict)
            or row.get("wlan_id") != str(target.wlan_id)
            or row.get("site_id") != str(target.site_id)
            or row.get("org_id") != str(mist_org_id)
        ):
            msg = "Authentication event scope mismatch"
            raise ValueError(msg)
        kind = row.get("type")
        if kind not in _SUCCESSES | _FAILURES:
            continue
        mac = row.get("mac")
        if not isinstance(mac, str) or re.fullmatch(r"[0-9a-f]{12}", mac) is None:
            missing_identity = True
            continue
        timestamp = row.get("timestamp")
        if type(timestamp) not in {int, float} or not window.start.timestamp() <= timestamp <= window.end.timestamp():
            msg = "Authentication event has invalid timing"
            raise ValueError(msg)
        at = datetime.fromtimestamp(timestamp, UTC)
        ap = row.get("ap")
        if ap is not None and (not isinstance(ap, str) or re.fullmatch(r"[0-9a-f]{12}", ap) is None):
            msg = "Invalid serving AP identity"
            raise ValueError(msg)
        client = sha256(
            f"auth-client.v1:{plan.organization_id}:{plan.audit_id}:{target.handle}:{mac}".encode()
        ).hexdigest()
        outcome = "success" if kind in _SUCCESSES else "failure"
        accepted[(client, at, outcome, ap)] = AuthEventRow.model_validate(
            {"client_handle": client, "ap_mac": ap, "occurred_at": at, "outcome": outcome}
        )
    ordered = sorted(accepted.values(), key=lambda row: (row.occurred_at, row.client_handle, row.outcome))
    partial = (
        missing_identity or bool(payload.get("next")) or payload["total"] != len(rows) or len(ordered) > MAX_PORT_EVENTS
    )
    return AuthEvidence(
        target_handle=target.handle,
        window=window,
        captured_at=utc_now(),
        state="partial" if partial else "complete",
        rows=tuple(ordered[-MAX_PORT_EVENTS:]),
        reason=(
            "Authentication evidence has missing identities or truncated history."
            if partial
            else "Scoped authentication events only; no events does not establish successful authentication."
        ),
    )
