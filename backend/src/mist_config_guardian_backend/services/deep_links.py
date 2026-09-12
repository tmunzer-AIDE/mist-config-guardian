"""Query parameters the browser application reads on each of its pages.

Search results and notifications open a page by name, with query parameters
naming the record to show. The page decides which parameters it reads, and a
parameter it does not read is not an error: the browser drops it on arrival and
the link lands on a generic page, which is worse than failing. Every deep link
is built through :func:`deep_link` so a misspelt or invented parameter is
refused here, where a test sees it, rather than in a browser.
"""

from collections.abc import Mapping
from types import MappingProxyType

# Kept in step with the page inputs under ``frontend/src/app/features``.
CONSUMED_PARAMETERS: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "overview": frozenset(),
        "changes": frozenset({"group", "actor"}),
        "history": frozenset({"object", "a", "b"}),
        "impact": frozenset({"session", "severity"}),
        "restore": frozenset({"operation", "step", "versions", "changeGroup", "compensate"}),
        "settings": frozenset({"tab"}),
    }
)

SETTINGS_TABS = frozenset({"organizations", "users", "ai", "email", "health"})


def deep_link(target: str, /, **parameters: str | None) -> dict[str, str]:
    """Return the query parameters for one page, omitting any that are ``None``.

    Raises :class:`ValueError` for a page the application does not have, a
    parameter the page does not read, or a settings tab that does not exist.
    """
    consumed = CONSUMED_PARAMETERS.get(str(target))
    if consumed is None:
        msg = f"{target!r} is not a page the application deep-links into"
        raise ValueError(msg)
    unread = set(parameters) - consumed
    if unread:
        msg = f"the {target} page does not read {sorted(unread)}"
        raise ValueError(msg)
    tab = parameters.get("tab")
    if tab is not None and tab not in SETTINGS_TABS:
        msg = f"{tab!r} is not a settings tab; expected one of {sorted(SETTINGS_TABS)}"
        raise ValueError(msg)
    return {name: value for name, value in parameters.items() if value is not None}
