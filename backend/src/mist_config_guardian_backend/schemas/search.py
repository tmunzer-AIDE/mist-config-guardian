"""Global search API schemas."""

from typing import Literal

from pydantic import BaseModel, Field

SearchResultKind = Literal["object", "change_group", "actor", "audit_id", "restore", "site"]
SearchTarget = Literal["overview", "changes", "history", "restore", "impact", "settings"]


class SearchResultResponse(BaseModel):
    """One row of the global search results page."""

    kind: SearchResultKind
    id: str
    title: str
    subtitle: str = ""
    meta: str = ""
    target: SearchTarget
    target_params: dict[str, str] = Field(default_factory=dict)


class SearchResultListResponse(BaseModel):
    """Everything the query matched, capped at the requested limit."""

    items: list[SearchResultResponse] = Field(default_factory=list)
    total: int
