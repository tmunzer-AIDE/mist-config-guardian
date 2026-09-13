"""Private candidate identities. No viewer or model endpoint exposes this collection."""

from typing import ClassVar
from uuid import UUID

from beanie import Document, PydanticObjectId
from pydantic import AwareDatetime, Field
from pymongo import IndexModel

from mist_config_guardian_backend.impact.contracts import Contract, PortTarget


class BindingIdentity(Contract):
    organization_id: PydanticObjectId
    investigation_id: PydanticObjectId
    audit_id: str
    generation: int = Field(ge=1)
    candidate_revision: int = Field(ge=1)
    source_dispatch_id: UUID
    source_check_ref: str = Field(pattern=r"^[0-9a-f]{64}$")
    target: PortTarget
    mist_org_id: UUID
    captured_at: AwareDatetime
    observed_at: AwareDatetime | None
    expires_at: AwareDatetime


class NeighborBinding(Document):
    """Insert-only encrypted identity, bound by AEAD to every provenance field."""

    identity: BindingIdentity
    encrypted_mac: str = Field(max_length=256)
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    class Settings:
        name = "impact_neighbor_bindings"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel([("identity.organization_id", 1), ("identity.investigation_id", 1)]),
            # TTL includes unreferenced inserts: losing workers cannot leave private
            # identities indefinitely. Retention is pinned from org policy at write.
            IndexModel([("identity.expires_at", 1)], expireAfterSeconds=0),
        ]
