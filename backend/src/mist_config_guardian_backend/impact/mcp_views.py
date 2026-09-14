"""Chart selectors choose existing JSON fields; the model never supplies chart values."""

from collections import Counter
from math import isfinite

from mist_config_guardian_backend.impact.mcp_contracts import McpEvidence, McpView
from mist_config_guardian_backend.impact.mcp_scope import McpScopeError


def selected_rows(
    evidence: McpEvidence, view: McpView
) -> list[tuple[str | int | float | None, str | int | float | None]]:
    data = evidence.data
    for key in view.rows_path:
        if not isinstance(data, dict) or key not in data:
            msg = "Chart path must select returned evidence"
            raise McpScopeError(msg)
        data = data[key]
    if not isinstance(data, list):
        msg = "Chart path must select a returned list"
        raise McpScopeError(msg)
    rows = []
    for item in data:
        if not isinstance(item, dict) or view.label_key not in item or view.value_key not in item:
            msg = "Chart fields must exist on every selected row"
            raise McpScopeError(msg)
        label, value = item[view.label_key], item[view.value_key]
        if isinstance(label, (dict, list, bool)) or isinstance(value, (dict, list, bool)):
            msg = "Chart cells must be scalar evidence values"
            raise McpScopeError(msg)
        if view.kind in {"bar", "histogram"} and (not isinstance(value, (float, int)) or not isfinite(value)):
            msg = "Numeric charts require measured finite numbers, never missing values"
            raise McpScopeError(msg)
        rows.append((label, value))
    if view.kind == "histogram":
        # Exact observed-value frequencies, not a fleet rate or model-generated bins.
        counts = Counter(value for _, value in rows)
        return [(value, count) for value, count in counts.items()]
    return rows
