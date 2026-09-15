"""Page walking shared by every Mist list read.

The collector and the restore preflight must see the same objects for a type,
so they must agree on exactly when a listing has reached its last page.
"""

import httpx


def _integer_header(response: httpx.Response, name: str) -> int | None:
    """Read a numeric paging header; anything unparseable counts as absent."""
    value = response.headers.get(name)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def is_last_page(response: httpx.Response, *, page: int, page_items: int) -> bool:
    """Whether a listing ends at ``page``.

    An empty page, or a total Mist did not state, ends it. Without a usable
    page limit the page's own length stands in, so a zero or missing limit
    cannot page forever.
    """
    total = _integer_header(response, "X-Page-Total")
    limit = _integer_header(response, "X-Page-Limit") or page_items
    return page_items == 0 or total is None or page * limit >= total
