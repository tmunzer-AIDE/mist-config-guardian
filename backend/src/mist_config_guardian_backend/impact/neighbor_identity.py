"""Executor-only identity; never a report, model argument or public lookup key."""

from dataclasses import dataclass, field
from uuid import UUID


@dataclass(frozen=True)
class PrivateCandidate:
    mac: str = field(repr=False)
    mist_org_id: UUID
    site_id: UUID
