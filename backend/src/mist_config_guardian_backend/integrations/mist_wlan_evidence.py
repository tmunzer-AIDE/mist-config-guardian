"""Bounded WLAN historical reads through the approved check/handle boundary."""

import asyncio
import json
from collections.abc import Awaitable, Callable
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime, timedelta
from types import TracebackType
from typing import Self

import httpx

from mist_config_guardian_backend.impact.contracts import (
    DispatchDenial,
    SessionEvidence,
    SessionRow,
    Window,
    WlanRemovalPlan,
)
from mist_config_guardian_backend.impact.wlan_removal import authorize_check
from mist_config_guardian_backend.integrations.mist import REGION_HOSTS
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.organization import MistCloudRegion

_MAX_BYTES = 524_288
_LIMIT = 1000


class MistWlanEvidenceClient(AbstractAsyncContextManager["MistWlanEvidenceClient"]):
    """One bounded page per check; truncation is partial, never an empty success."""

    def __init__(self, *, token: str, region: MistCloudRegion) -> None:
        self._client = httpx.AsyncClient(
            base_url=REGION_HOSTS[region],
            headers={"Authorization": f"Token {token}"},
            timeout=15,
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self._client.aclose()

    async def capture(
        self,
        *,
        plan: WlanRemovalPlan,
        target_handle: str,
        window: Window,
        reserve_dispatch: Callable[[], Awaitable[DispatchDenial | None]],
        check_id: str = "wlan-client-sessions.v1",
    ) -> SessionEvidence:
        target = authorize_check(plan, check_id=check_id, target_handle=target_handle)
        # Callers cannot query arbitrary historical periods through this capability.
        if (
            window.start < plan.changed_at.replace(microsecond=0) - _BASELINE
            or window.end > plan.changed_at + _DURATION
        ):
            msg = "Window exceeds the audit's allowed evidence interval"
            raise ValueError(msg)
        denial = await reserve_dispatch()
        if denial is not None:
            return SessionEvidence(
                target_handle=target_handle,
                window=window,
                captured_at=utc_now(),
                state="dispatch_denied",
                dispatch_denial=denial,
                reason=denial.explanation,
            )
        path = f"/api/v1/sites/{target.site_id}/clients/sessions/search"
        params = {
            "wlan_id": str(target.wlan_id),
            "start": str(int(window.start.timestamp())),
            "end": str(int(window.end.timestamp())),
            "limit": str(_LIMIT),
        }
        http_status = None
        response_bytes = None
        try:
            async with asyncio.timeout(20), self._client.stream("GET", path, params=params) as response:
                http_status = response.status_code
                response.raise_for_status()
                data = bytearray()
                response_bytes = 0
                async for chunk in response.aiter_bytes():
                    data.extend(chunk)
                    response_bytes = len(data)
                    if len(data) > _MAX_BYTES:
                        return self._result(
                            target_handle,
                            window,
                            "partial",
                            "Response byte limit reached.",
                            http_status=http_status,
                            response_bytes=response_bytes,
                        )
                payload = json.loads(data)
            return self._parse(payload, target_handle, window, str(target.site_id), str(target.wlan_id)).model_copy(
                update={"http_status": http_status, "response_bytes": response_bytes}
            )
        except httpx.HTTPStatusError as exc:
            return self._result(
                target_handle,
                window,
                "error",
                f"Mist returned HTTP {exc.response.status_code}.",
                http_status=http_status,
                response_bytes=response_bytes,
            )
        except (httpx.HTTPError, ValueError, TypeError, OverflowError, TimeoutError):
            return self._result(
                target_handle,
                window,
                "error",
                "Historical session evidence was unavailable or invalid.",
                http_status=http_status,
                response_bytes=response_bytes,
            )

    @staticmethod
    def _result(  # noqa: PLR0913 - explicit optional transport metadata, separate from normalized evidence
        handle: str,
        window: Window,
        state: str,
        reason: str,
        *,
        http_status: int | None = None,
        response_bytes: int | None = None,
    ) -> SessionEvidence:
        return SessionEvidence.model_validate(
            {
                "target_handle": handle,
                "window": window,
                "captured_at": utc_now(),
                "state": state,
                "reason": reason,
                "http_status": http_status,
                "response_bytes": response_bytes,
            }
        )

    @staticmethod
    def _parse(
        payload: object,
        handle: str,
        window: Window,
        site_id: str,
        wlan_id: str,
    ) -> SessionEvidence:
        if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
            msg = "Missing session results"
            raise TypeError(msg)
        raw_rows = payload["results"]
        total = payload.get("total")
        if type(total) is not int or total < len(raw_rows):
            msg = "Invalid session result count"
            raise ValueError(msg)
        if payload.get("start") != int(window.start.timestamp()) or payload.get("end") != int(window.end.timestamp()):
            msg = "Returned evidence window differs from request"
            raise ValueError(msg)
        rows = []
        for raw in raw_rows[:_LIMIT]:
            if not isinstance(raw, dict) or raw.get("site_id") != site_id or raw.get("wlan_id") != wlan_id:
                msg = "Returned session belongs to a different scope"
                raise ValueError(msg)
            connected = raw.get("connect")
            disconnected = raw.get("disconnect")
            if type(connected) not in (int, float) or (
                disconnected is not None and type(disconnected) not in (int, float)
            ):
                msg = "Session boundary timestamps are missing"
                raise ValueError(msg)
            rows.append(
                SessionRow(
                    client_mac=str(raw.get("mac", "")).replace(":", "").lower(),
                    ap_mac=str(raw.get("ap", "")).replace(":", "").lower(),
                    connected_at=datetime.fromtimestamp(connected, UTC),
                    disconnected_at=datetime.fromtimestamp(disconnected, UTC) if disconnected is not None else None,
                )
            )
        partial = bool(payload.get("next")) or total != len(rows)
        return SessionEvidence(
            target_handle=handle,
            window=window,
            captured_at=utc_now(),
            state="partial" if partial else "complete",
            rows=tuple(rows),
            reason="Pagination or row limit reached." if partial else "",
        )


# These bounds are part of the capability, independent of model instructions.
_BASELINE = timedelta(hours=1)
_DURATION = timedelta(hours=1)
