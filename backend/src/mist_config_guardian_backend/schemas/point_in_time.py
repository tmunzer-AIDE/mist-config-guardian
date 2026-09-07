"""Point-in-time navigation API schemas."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from mist_config_guardian_backend.models.monitoring import ImpactSeverity


class TimelineMarkerResponse(BaseModel):
    """One change tick drawn on the shell's time bar."""

    at: datetime
    severity: ImpactSeverity = ImpactSeverity.NONE
    change_group_id: str
    label: str


class TimelineMarkerListResponse(BaseModel):
    """Every marker inside the selected window."""

    items: list[TimelineMarkerResponse] = Field(default_factory=list)
    range_start: datetime
    range_end: datetime


class ReconstructedObjectResponse(BaseModel):
    """One object as it existed at the reconstructed instant."""

    logical_object_id: str
    object_type: str
    name: str
    version_id: str
    version: int
    is_deleted: bool = False


class PointInTimeStateResponse(BaseModel):
    """A scope reconstructed as it existed at one instant."""

    as_of: datetime
    scope: Literal["org", "site"]
    object_count: int
    objects: list[ReconstructedObjectResponse] = Field(default_factory=list)


class PointInTimeModeResponse(BaseModel):
    """Whether the caller is browsing a past point in time."""

    historical: bool
    as_of: datetime | None = None
