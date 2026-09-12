"""Bounded exact-port history, never an interpretation of provider event prose."""

import asyncio
import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID

import httpx

from mist_config_guardian_backend.impact.contracts import (
    DispatchDenial,
    PortEventRow,
    PortHistoryEvidence,
    PortTarget,
    Window,
    WlanRemovalPlan,
)
from mist_config_guardian_backend.impact.limits import MAX_PORT_EVENTS
from mist_config_guardian_backend.integrations.mist_neighbor_evidence import MistNeighborEvidenceClient
from mist_config_guardian_backend.models.base import utc_now

_EVENT_TYPES = {"SW_PORT_UP", "SW_PORT_DOWN", "SW_POE_PORT_ENABLED", "SW_POE_PORT_DISABLED"}
_MAX_BYTES = 262_144
_MAX_PROVIDER_ROWS = 1000


class MistPortHistoryClient(MistNeighborEvidenceClient):
    async def capture_port_history(
        self,
        *,
        plan: WlanRemovalPlan,
        target: PortTarget,
        mist_org_id: UUID,
        window: Window,
        reserve_dispatch: Callable[[], Awaitable[DispatchDenial | None]],
    ) -> PortHistoryEvidence:
        if (
            not plan.port_history
            or target not in plan.port_targets
            or window.start != plan.changed_at - timedelta(hours=1)
            or window.end > plan.changed_at + timedelta(hours=1)
        ):
            msg = "Port history is not authorized by this plan"
            raise ValueError(msg)
        denial = await reserve_dispatch()
        if denial:
            return PortHistoryEvidence(
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
                    f"/api/v1/sites/{target.site_id}/devices/events/search",
                    params={
                        "mac": target.device_mac,
                        "start": str(int(window.start.timestamp())),
                        "end": str(int(window.end.timestamp())),
                        "limit": str(_MAX_PROVIDER_ROWS),
                        "sort": "timestamp",
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
                        return PortHistoryEvidence(
                            target_handle=target.handle,
                            window=window,
                            captured_at=utc_now(),
                            state="partial",
                            reason="Port event response byte limit reached.",
                            http_status=status,
                            response_bytes=size,
                        )
            reading = parse_port_history(json.loads(body), target, mist_org_id, window)
            return reading.model_copy(update={"http_status": status, "response_bytes": size})
        except httpx.HTTPStatusError:
            reason = f"Mist returned HTTP {status} during port event collection."
        except (httpx.HTTPError, TimeoutError):
            reason = "Port event collection transport failed or timed out."
        except (ValueError, TypeError, OverflowError):
            reason = "Port event response rejected: invalid scope, time window or event record."
        return PortHistoryEvidence(
            target_handle=target.handle,
            window=window,
            captured_at=utc_now(),
            state="error",
            reason=reason,
            http_status=status,
            response_bytes=size,
        )


def parse_port_history(payload: object, target: PortTarget, mist_org_id: UUID, window: Window) -> PortHistoryEvidence:
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        msg = "Missing event results"
        raise TypeError(msg)
    rows = payload["results"]
    if (
        type(payload.get("total")) is not int
        or payload["total"] < len(rows)
        or len(rows) > _MAX_PROVIDER_ROWS
        or type(payload.get("start")) not in {int, float}
        or type(payload.get("end")) not in {int, float}
        or payload["start"] != int(window.start.timestamp())
        or payload["end"] != int(window.end.timestamp())
    ):
        msg = "Event envelope is not the requested window"
        raise ValueError(msg)
    accepted: set[tuple[str, datetime]] = set()
    for row in rows:
        if (
            not isinstance(row, dict)
            or row.get("mac") != target.device_mac
            or row.get("site_id") != str(target.site_id)
            or row.get("org_id") != str(mist_org_id)
            or row.get("device_type") != "switch"
        ):
            msg = "Event identity mismatch"
            raise ValueError(msg)
        # The documented endpoint has no exact port filter. Only validated exact-port
        # records reach the evidence contract; other ports/types do not imply absence.
        if row.get("port_id") != target.port_id or row.get("type") not in _EVENT_TYPES:
            continue
        timestamp = row.get("timestamp")
        if type(timestamp) not in {int, float}:
            msg = "Missing event timestamp"
            raise ValueError(msg)
        at = datetime.fromtimestamp(timestamp, UTC)
        if not int(window.start.timestamp()) <= timestamp <= int(window.end.timestamp()):
            msg = "Event outside the requested window"
            raise ValueError(msg)
        accepted.add((row["type"], at))
    partial = bool(payload.get("next")) or payload["total"] != len(rows) or len(accepted) > MAX_PORT_EVENTS
    events = sorted(accepted, key=lambda event: (event[1], event[0]))
    return PortHistoryEvidence(
        target_handle=target.handle,
        window=window,
        captured_at=utc_now(),
        state="partial" if partial else "complete",
        rows=tuple(
            PortEventRow.model_validate({"event_type": kind, "occurred_at": at})
            for kind, at in events[-MAX_PORT_EVENTS:]
        ),
        reason=(
            "Event history is truncated; missing events cannot establish state or recovery."
            if partial
            else "Exact-port events only. PoE enabled/disabled does not prove power delivery or an impacted AP."
        ),
    )
