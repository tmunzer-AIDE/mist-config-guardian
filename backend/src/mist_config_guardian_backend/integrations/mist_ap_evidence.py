"""Exact AP statistics from a private port binding; no graph traversal or device-ID guessing."""

import asyncio
import json
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import httpx

from mist_config_guardian_backend.impact.contracts import (
    ApAdjacency,
    ApEvidence,
    DispatchDenial,
    NeighborTarget,
    PortEvidence,
    PortTarget,
    Window,
    WlanRemovalPlan,
)
from mist_config_guardian_backend.impact.neighbor_identity import PrivateCandidate
from mist_config_guardian_backend.integrations.mist_auth_evidence import MistImpactEvidenceClient
from mist_config_guardian_backend.models.base import utc_now

_MAX_BYTES = 65_536


class MistScopedEvidenceClient(MistImpactEvidenceClient):
    async def capture_ap(  # noqa: PLR0913 - explicit binding and evidence authority
        self,
        *,
        plan: WlanRemovalPlan,
        target: NeighborTarget,
        candidate: PrivateCandidate,
        source: PortEvidence,
        window: Window,
        reserve_dispatch: Callable[[], Awaitable[DispatchDenial | None]],
    ) -> ApEvidence:
        if (
            not plan.neighbor_statistics
            or target not in plan.neighbor_targets
            or source.target_handle != target.source_port_handle
            or source.candidate_binding != target.binding
            or (candidate.site_id, candidate.mist_org_id) != (target.site_id, target.mist_org_id)
            or re.fullmatch(r"[0-9a-f]{12}", candidate.mac) is None
            or window.start != plan.changed_at
            or window.end > plan.changed_at + timedelta(hours=1)
        ):
            msg = "AP statistics are not authorized by this private source binding"
            raise ValueError(msg)
        port = next(p for p in plan.port_targets if p.handle == target.source_port_handle)
        denial = await reserve_dispatch()
        if denial:
            return ApEvidence(
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
                    f"/api/v1/orgs/{target.mist_org_id}/stats/devices",
                    params={
                        "type": "ap",
                        "status": "all",
                        "site_id": str(target.site_id),
                        "mac": candidate.mac,
                        "limit": "2",
                        "page": "1",
                        "fields": "mac,type,org_id,site_id,status,last_seen,lldp_stat,lldp_stats,port_stat",
                    },
                ) as response,
            ):
                status = response.status_code
                response.raise_for_status()
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    size = len(body)
                    if size > _MAX_BYTES:
                        return ApEvidence(
                            target_handle=target.handle,
                            window=window,
                            captured_at=utc_now(),
                            state="partial",
                            http_status=status,
                            response_bytes=size,
                            reason="AP snapshot byte limit reached.",
                        )
            return self.parse_ap(json.loads(body), plan, target, candidate, source, port, window).model_copy(
                update={"http_status": status, "response_bytes": size}
            )
        except httpx.HTTPStatusError:
            reason = f"Mist returned HTTP {status} during AP statistics collection."
        except (httpx.HTTPError, TimeoutError):
            reason = "AP statistics transport failed or timed out."
        except (ValueError, TypeError, OverflowError, OSError):
            reason = "AP statistics failed exact identity or timestamp validation; response rejected."
        return ApEvidence(
            target_handle=target.handle,
            window=window,
            captured_at=utc_now(),
            state="error",
            reason=reason,
            http_status=status,
            response_bytes=size,
        )

    @staticmethod
    def parse_ap(  # noqa: PLR0913, PLR0917 - exact source identities and interval
        payload: object,
        plan: WlanRemovalPlan,
        target: NeighborTarget,
        candidate: PrivateCandidate,
        source: PortEvidence,
        port: PortTarget,
        window: Window,
    ) -> ApEvidence:
        now = utc_now()
        if not isinstance(payload, list):
            raise TypeError
        if len(payload) != 1:
            return ApEvidence(
                target_handle=target.handle,
                window=window,
                captured_at=now,
                state="partial",
                reason="No unique AP snapshot; absence does not establish an outage.",
            )
        row = payload[0]
        if (
            not isinstance(row, dict)
            or row.get("mac") != candidate.mac
            or row.get("type") != "ap"
            or row.get("org_id") != str(candidate.mist_org_id)
            or row.get("site_id") != str(candidate.site_id)
        ):
            raise ValueError
        observed = None
        if row.get("last_seen") is not None:
            stamp = row["last_seen"]
            if type(stamp) not in {float, int} or stamp <= 0:
                raise ValueError
            observed = datetime.fromtimestamp(stamp, UTC)
            if observed > now:
                raise ValueError
        connected = {"connected": True, "disconnected": False}.get(row.get("status"))
        switch = source.rows[0] if source.state == "complete" and source.rows else None
        recent = bool(
            observed
            and now - timedelta(minutes=5) <= observed
            and connected is True
            and switch
            and switch.observed_at
            and now - timedelta(minutes=5) <= switch.observed_at <= now
            and switch.up is True
        )
        links = row.get("lldp_stats")
        links = list(links.values()) if isinstance(links, dict) else [row.get("lldp_stat")]
        corroborated = False
        port_stats = row.get("port_stat")
        for link in links:
            if not isinstance(link, dict):
                continue
            chassis = str(link.get("chassis_id", "")).replace(":", "").replace("-", "").lower()
            local = (
                port_stats.get(link.get("ap_port_name"))
                if isinstance(port_stats, dict) and isinstance(link.get("ap_port_name"), str)
                else None
            )
            if (
                recent
                and chassis == port.device_mac
                and link.get("port_id") == port.port_id
                and isinstance(local, dict)
                and local.get("up") is True
            ):
                corroborated = True
        handle = sha256(
            f"managed-neighbor.v1:{plan.organization_id}:{plan.audit_id}:{candidate.site_id}:{candidate.mac}".encode()
        ).hexdigest()
        return ApEvidence(
            target_handle=target.handle,
            window=window,
            captured_at=now,
            state="complete",
            rows=(
                ApAdjacency(
                    device_handle=handle,
                    connected=connected,
                    observed_at=observed,
                    relationship="corroborated_recent" if corroborated else "unverified",
                ),
            ),
            reason="Recent LLDP observations agree; past dependency, sole power path and impact remain unproven."
            if corroborated
            else "AP identity verified; recent reciprocal adjacency is not established.",
        )
