"""Secret-safe AI assistance schemas."""

from datetime import datetime
from typing import Literal

from beanie import PydanticObjectId
from pydantic import BaseModel, Field

AI_DISCLAIMER = "Field names and values only — secrets are never sent."

QUESTION_MAX_LENGTH = 500


class DiffSummaryRequest(BaseModel):
    """Ask for a summary of one deterministic version comparison."""

    organization_id: PydanticObjectId
    from_version_id: PydanticObjectId
    to_version_id: PydanticObjectId
    regenerate: bool = False


class DiffFollowupRequest(BaseModel):
    """Ask a question answered only against one deterministic comparison."""

    organization_id: PydanticObjectId
    from_version_id: PydanticObjectId
    to_version_id: PydanticObjectId
    question: str = Field(min_length=3, max_length=QUESTION_MAX_LENGTH)


class AiAssistCard(BaseModel):
    """One model-produced card shown beside the deterministic diff.

    ``kind`` separates stated intent from flagged risks; ``field`` references a
    diff entry path when the model cited one.
    """

    kind: Literal["intent", "flag"]
    level: Literal["info", "warn", "crit"] = "info"
    text: str
    field: str | None = None


class AiDiffSummaryResponse(BaseModel):
    """Model summary of a comparison, with provider metadata."""

    summary: str
    model: str
    generated_at: datetime
    cards: list[AiAssistCard] = Field(default_factory=list)
    duration_ms: int = 0
    cached: bool = False
    disclaimer: str = AI_DISCLAIMER


class AiDiffFollowupResponse(BaseModel):
    """Model answer to one question about a fixed comparison."""

    question: str
    answer: str
    model: str
    generated_at: datetime
    duration_ms: int = 0
    disclaimer: str = AI_DISCLAIMER
