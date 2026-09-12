"""One exact-port read per resolver-issued capability; no neighbor queries or history claims."""

import asyncio
import json
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import httpx

from mist_config_guardian_backend.impact.contracts import (
    DispatchDenial,
    PortEvidence,
    PortRow,
    PortTarget,
    Window,
    WlanRemovalPlan,
)
from mist_config_guardian_backend.integrations.mist_wlan_evidence import MistWlanEvidenceClient
from mist_config_guardian_backend.models.base import utc_now

_MAX_BYTES = 65_536


class MistPortEvidenceClient(MistWlanEvidenceClient):
    """Reuse the bounded regional read-only HTTP session lifecycle.

    A snapshot's collection interval is not passed to Mist as a historical filter:
    port search returns current or most recent state, potentially from before the
    change. Only an explicit row timestamp can establish observation time.
    """

    async def capture_port(
        self,
        *,
        plan: WlanRemovalPlan,
        target_handle: str,
        window: Window,
        reserve_dispatch: Callable[[], Awaitable[DispatchDenial | None]],
    ) -> PortEvidence:
        target = next((t for t in plan.port_targets if t.handle == target_handle), None)
        if target is None or window.start != plan.changed_at or window.end > plan.changed_at + timedelta(hours=1):
            msg = "Port check or interval is not authorized by this audit plan"
            raise ValueError(msg)
        denial = await reserve_dispatch()
        if denial is not None:
            return PortEvidence(
                target_handle=target_handle,
                window=window,
                captured_at=utc_now(),
                state="dispatch_denied",
                dispatch_denial=denial,
                reason=denial.explanation,
            )
        status = None
        size = None
        try:
            async with (
                asyncio.timeout(20),
                self._client.stream(
                    "GET",
                    f"/api/v1/sites/{target.site_id}/stats/ports/search",
                    params={"device_type": "switch", "mac": target.device_mac, "port_id": target.port_id, "limit": "2"},
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
                        return PortEvidence(
                            target_handle=target_handle,
                            window=window,
                            captured_at=utc_now(),
                            state="partial",
                            reason="Port response byte limit reached.",
                            http_status=status,
                            response_bytes=size,
                        )
                payload = json.loads(body)
            return self.parse(payload, plan, target, window).model_copy(
                update={"http_status": status, "response_bytes": size}
            )
        except (httpx.HTTPError, ValueError, TypeError, OverflowError, TimeoutError):
            return PortEvidence(
                target_handle=target_handle,
                window=window,
                captured_at=utc_now(),
                state="error",
                reason="Port snapshot was unavailable or invalid.",
                http_status=status,
                response_bytes=size,
            )

    @staticmethod
    def parse(payload: object, plan: WlanRemovalPlan, target: PortTarget, window: Window) -> PortEvidence:
        if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
            msg = "Missing port results"
            raise TypeError(msg)
        rows = payload["results"]
        total = payload.get("total")
        if type(total) is not int or total < len(rows):
            msg = "Invalid port result count"
            raise ValueError(msg)
        # No latest-wins guess across duplicates, and an empty page is not a down port.
        if len(rows) != 1 or total != 1 or payload.get("next"):
            return PortEvidence(
                target_handle=target.handle,
                window=window,
                captured_at=utc_now(),
                state="partial",
                reason="No unique complete port observation was returned; absence does not establish a down port.",
            )
        row = rows[0]
        if (
            not isinstance(row, dict)
            or row.get("site_id") != str(target.site_id)
            or row.get("mac") != target.device_mac
            or row.get("port_id") != target.port_id
            or row.get("type") != "switch"
        ):
            msg = "Returned port does not match the resolved device, site and port"
            raise ValueError(msg)
        neighbor = row.get("neighbor_mac")
        # LLDP can be spoofed. A syntactically valid neighbor is still unverified,
        # not a managed AP, a powered-device identity or an executable target.
        neighbor_handle = None
        if isinstance(neighbor, str):
            normalized = neighbor.replace(":", "").replace("-", "").lower()
            if re.fullmatch(r"[0-9a-f]{12}", normalized) is not None and normalized != target.device_mac:
                neighbor_handle = sha256(
                    f"observed-neighbor.v1:{plan.organization_id}:{plan.audit_id}:{target.handle}:{normalized}".encode()
                ).hexdigest()
        stamp = row.get("timestamp")
        observed = datetime.fromtimestamp(stamp, UTC) if type(stamp) in (int, float) else None
        if observed is not None and observed > utc_now():
            msg = "Port observation timestamp is in the future"
            raise ValueError(msg)
        reading = PortRow(
            up=row.get("up"),
            poe_on=row.get("poe_on"),
            power_draw=row.get("power_draw"),
            observed_at=observed,
            neighbor_handle=neighbor_handle,
        )
        return PortEvidence(
            target_handle=target.handle,
            window=window,
            captured_at=utc_now(),
            state="complete",
            rows=(reading,),
            reason="Most recent reported state only; no transition, managed neighbor, "
            "power dependency or impact is established. "
            + ("Observation time is unavailable." if observed is None else "Observation time may precede the change."),
        )
