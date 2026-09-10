"""Collect bounded, site-validated LLDP neighbor evidence from org port search."""

import asyncio
from urllib.parse import parse_qs, urljoin, urlsplit

import httpx

_PAGE_SIZE = 1000
_MAX_REQUESTS = 5
_MAC_BATCH_SIZE = 100
_UNAVAILABLE = "Neighbor collection is incomplete. Check Mist port-search access and data availability."


def _cursor(value: object, current: httpx.URL, path: str) -> str:
    if not isinstance(value, str):
        message = "Invalid pagination URL"
        raise TypeError(message)
    resolved = urlsplit(urljoin(str(current), value))
    origin = urlsplit(str(current))
    if (resolved.scheme, resolved.netloc, resolved.path) != (origin.scheme, origin.netloc, path):
        message = "Unexpected pagination destination"
        raise ValueError(message)
    cursors = parse_qs(resolved.query).get("search_after", [])
    if len(cursors) != 1 or not cursors[0]:
        message = "Missing pagination cursor"
        raise ValueError(message)
    return cursors[0]


async def fetch_neighbor_ports(
    client: httpx.AsyncClient, *, org_id: str, site_id: str, macs: list[str]
) -> tuple[list[dict], list[str]]:
    """Preserve device inventory and partial evidence if port collection fails.

    Only the cursor is copied from provider pagination URLs: credentials, org,
    device filters and limits always remain attached to our original request.
    """
    rows: list[dict] = []
    path = f"/api/v1/orgs/{org_id}/stats/ports/search"
    requests = 0
    try:
        async with asyncio.timeout(15):
            for offset in range(0, len(macs), _MAC_BATCH_SIZE):
                query = {
                    "device_type": "all",
                    "mac": ",".join(macs[offset : offset + _MAC_BATCH_SIZE]),
                    "limit": str(_PAGE_SIZE),
                    "sort": "-timestamp",
                }
                seen_cursors: set[str] = set()
                count = 0
                while True:
                    if requests >= _MAX_REQUESTS:
                        return rows, [
                            "Neighbor collection reached its 5-request / 5000-port limit; links are incomplete."
                        ]
                    requests += 1
                    response = await client.get(path, params=query)
                    response.raise_for_status()
                    payload = response.json()
                    batch = payload.get("results") if isinstance(payload, dict) else None
                    total = payload.get("total") if isinstance(payload, dict) else None
                    if (
                        not isinstance(batch, list)
                        or len(batch) > _PAGE_SIZE
                        or any(not isinstance(row, dict) for row in batch)
                        or type(total) is not int
                        or total < 0
                    ):
                        return rows, [_UNAVAILABLE]
                    count += len(batch)
                    rows.extend(row for row in batch if row.get("org_id") == org_id and row.get("site_id") == site_id)
                    following = payload.get("next")
                    if not following:
                        if total > count:
                            return rows, [_UNAVAILABLE]
                        break
                    cursor = _cursor(following, response.url, path)
                    if cursor in seen_cursors or not batch:
                        return rows, [_UNAVAILABLE]
                    seen_cursors.add(cursor)
                    query["search_after"] = cursor
    except (httpx.HTTPError, ValueError, TypeError, TimeoutError):
        return rows, [_UNAVAILABLE]
    return rows, []
