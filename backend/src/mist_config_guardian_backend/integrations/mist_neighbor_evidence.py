"""Exact AP inventory verification, with no recursive discovery or operational AP reads."""

import asyncio
import json
import re
from collections.abc import Awaitable, Callable
from datetime import timedelta
from hashlib import sha256

import httpx

from mist_config_guardian_backend.impact.contracts import (
    DispatchDenial,
    ManagedNeighbor,
    NeighborEvidence,
    NeighborTarget,
    Window,
    WlanRemovalPlan,
)
from mist_config_guardian_backend.impact.neighbor_identity import PrivateCandidate
from mist_config_guardian_backend.integrations.mist_port_evidence import MistPortEvidenceClient
from mist_config_guardian_backend.models.base import utc_now

_MAX_BYTES = 65_536


class MistNeighborEvidenceClient(MistPortEvidenceClient):
    async def capture_neighbor(
        self,
        *,
        plan: WlanRemovalPlan,
        target: NeighborTarget,
        candidate: PrivateCandidate,
        window: Window,
        reserve_dispatch: Callable[[], Awaitable[DispatchDenial | None]],
    ) -> NeighborEvidence:
        if (
            target not in plan.neighbor_targets
            or (candidate.site_id, candidate.mist_org_id) != (target.site_id, target.mist_org_id)
            or re.fullmatch(r"[0-9a-f]{12}", candidate.mac) is None
            or window.start != plan.changed_at
            or window.end > plan.changed_at + timedelta(hours=1)
        ):
            msg = "Inventory verification is not authorized by this plan"
            raise ValueError(msg)
        denial = await reserve_dispatch()
        if denial:
            return NeighborEvidence(
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
                    f"/api/v1/orgs/{target.mist_org_id}/inventory/search",
                    params={"type": "ap", "site_id": str(target.site_id), "mac": candidate.mac, "limit": "2"},
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
                        return NeighborEvidence(
                            target_handle=target.handle,
                            window=window,
                            captured_at=utc_now(),
                            state="partial",
                            reason="Inventory response byte limit reached.",
                            http_status=status,
                            response_bytes=size,
                        )
            return self.parse_inventory(json.loads(body), plan, target, candidate, window).model_copy(
                update={"http_status": status, "response_bytes": size}
            )
        except httpx.HTTPStatusError:
            reason = f"Mist returned HTTP {status} during inventory verification."
        except (httpx.HTTPError, TimeoutError):
            reason = "Inventory verification transport failed or timed out."
        except (ValueError, TypeError):
            reason = "Inventory response was invalid or did not match the exact organization, site and AP identity."
        return NeighborEvidence(
            target_handle=target.handle,
            window=window,
            captured_at=utc_now(),
            state="error",
            reason=reason,
            http_status=status,
            response_bytes=size,
        )

    @staticmethod
    def parse_inventory(
        payload: object, plan: WlanRemovalPlan, target: NeighborTarget, candidate: PrivateCandidate, window: Window
    ) -> NeighborEvidence:
        if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
            msg = "Missing inventory results"
            raise TypeError(msg)
        rows = payload["results"]
        total = payload.get("total")
        if type(total) is not int or total < len(rows):
            msg = "Invalid inventory result count"
            raise ValueError(msg)
        if total != 1 or len(rows) != 1 or payload.get("next"):
            return NeighborEvidence(
                target_handle=target.handle,
                window=window,
                captured_at=utc_now(),
                state="partial",
                reason=(
                    "No unique complete AP inventory match; other device types and missing inventory remain unresolved."
                ),
            )
        row = rows[0]
        if (
            not isinstance(row, dict)
            or row.get("org_id") != str(candidate.mist_org_id)
            or row.get("site_id") != str(candidate.site_id)
            or row.get("mac") != candidate.mac
            or row.get("type") != "ap"
            or row.get("vc_mac")
            or row.get("master_mac")
            or row.get("members")
        ):
            msg = "Inventory scope or alias mismatch"
            raise ValueError(msg)
        handle = sha256(
            f"managed-neighbor.v1:{plan.organization_id}:{plan.audit_id}:{candidate.site_id}:{candidate.mac}".encode()
        ).hexdigest()
        return NeighborEvidence(
            target_handle=target.handle,
            window=window,
            captured_at=utc_now(),
            state="complete",
            rows=(ManagedNeighbor(device_handle=handle),),
            reason=(
                "Unique AP inventory membership verified at collection time. LLDP, PoE dependency and impact "
                "remain unverified; no downstream check is authorized."
            ),
        )
