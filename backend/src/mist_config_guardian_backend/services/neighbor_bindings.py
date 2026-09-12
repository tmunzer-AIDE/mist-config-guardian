"""Source-linked private identity storage; public handles are never lookup arguments."""

import json
import re
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import UUID

from beanie import PydanticObjectId
from beanie.odm.utils.encoder import Encoder

from mist_config_guardian_backend.impact.contracts import CandidateReference, PortEvidence, PortTarget
from mist_config_guardian_backend.impact.dispatch import DispatchRecord
from mist_config_guardian_backend.impact.neighbor_identity import PrivateCandidate
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.investigation import ImpactInvestigation
from mist_config_guardian_backend.models.neighbor_binding import BindingIdentity, NeighborBinding
from mist_config_guardian_backend.security.credentials import CredentialVault


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _milliseconds(value: datetime) -> datetime:
    # BSON stores millisecond precision. Hash/encrypt the persisted identity,
    # so a real Mongo round trip cannot change the authenticated context.
    return value.astimezone(UTC).replace(microsecond=value.microsecond // 1000 * 1000)


def _aad(identity: BindingIdentity, artifact_id: PydanticObjectId) -> str:
    return (
        f"neighbor-binding.v1:{artifact_id}:{sha256(_canonical(identity.model_dump(mode='json')).encode()).hexdigest()}"
    )


def _digest(identity: BindingIdentity, ciphertext: str) -> str:
    return sha256(
        _canonical({"identity": identity.model_dump(mode="json"), "encrypted_mac": ciphertext}).encode()
    ).hexdigest()


class NeighborBindingStore:
    def __init__(self, vault: CredentialVault) -> None:
        self.vault = vault

    @staticmethod
    def identity(  # noqa: PLR0913, PLR0917 - complete source provenance
        root: ImpactInvestigation,
        target: PortTarget,
        source: PortEvidence,
        source_ref: str,
        dispatch_id: UUID,
        mist_org_id: UUID,
        retention_days: int,
    ) -> BindingIdentity:
        if (
            root.id is None
            or source.target_handle != target.handle
            or source.state != "complete"
            or len(source.rows) != 1
        ):
            msg = "Candidate binding requires a complete source for this persisted investigation"
            raise ValueError(msg)
        return BindingIdentity(
            organization_id=root.organization_id,
            investigation_id=root.id,
            audit_id=root.audit_id,
            generation=root.generation,
            candidate_revision=root.revision + 1,
            source_dispatch_id=dispatch_id,
            source_check_ref=source_ref,
            target=target,
            mist_org_id=mist_org_id,
            captured_at=_milliseconds(source.captured_at),
            observed_at=_milliseconds(source.rows[0].observed_at) if source.rows[0].observed_at else None,
            expires_at=_milliseconds(source.captured_at + timedelta(days=retention_days)),
        )

    async def persist(self, identity: BindingIdentity, mac: str) -> CandidateReference:
        if re.fullmatch(r"[0-9a-f]{12}", mac) is None:
            msg = "Invalid candidate identity"
            raise ValueError(msg)
        artifact_id = PydanticObjectId()
        encrypted = self.vault.encrypt_for_context(mac, context=_aad(identity, artifact_id))
        digest = _digest(identity, encrypted)
        await NeighborBinding(id=artifact_id, identity=identity, encrypted_mac=encrypted, content_hash=digest).insert()
        return CandidateReference(
            artifact_id=artifact_id, content_hash=digest, source_dispatch_id=identity.source_dispatch_id
        )

    async def load(
        self, root: ImpactInvestigation, expected: BindingIdentity, reference: CandidateReference, source: PortEvidence
    ) -> PrivateCandidate:
        if (
            (expected.organization_id, expected.investigation_id, expected.audit_id)
            != (root.organization_id, root.id, root.audit_id)
            or (expected.generation, expected.candidate_revision) != (root.generation, root.revision + 1)
            or source.state != "complete"
            or len(source.rows) != 1
            or source.target_handle != expected.target.handle
        ):
            msg = "Candidate source belongs to a different investigation or checkpoint"
            raise ValueError(msg)
        # Follow only a completed source dispatch from this generation/checkpoint.
        doc = await ImpactInvestigation.get_pymongo_collection().find_one(
            {
                "_id": root.id,
                "organization_id": root.organization_id,
                "generation": root.generation,
                "revision": root.revision,
            },
            {
                "organization_id": 1,
                "generation": 1,
                "revision": 1,
                "dispatches": {
                    "$elemMatch": Encoder().encode({"id": reference.source_dispatch_id, "state": "complete"})
                },
            },
        )
        valid = doc is not None and all(
            doc.get(k) == v
            for k, v in {
                "_id": root.id,
                "organization_id": root.organization_id,
                "generation": root.generation,
                "revision": root.revision,
            }.items()
        )
        records = doc.get("dispatches", []) if doc else []
        if not valid or len(records) != 1:
            msg = "Candidate source dispatch is unavailable"
            raise ValueError(msg)
        record = DispatchRecord.model_validate(records[0])
        if (
            record.id,
            record.generation,
            record.candidate_revision,
            record.check_id,
            record.target_handle,
            record.site_id,
            record.device_mac,
            record.port_id,
            record.window.start,
            record.window.end,
            record.state,
        ) != (
            expected.source_dispatch_id,
            root.generation,
            root.revision + 1,
            source.check_id,
            expected.target.handle,
            expected.target.site_id,
            expected.target.device_mac,
            expected.target.port_id,
            _milliseconds(source.window.start),
            _milliseconds(source.window.end),
            "complete",
        ):
            msg = "Candidate source dispatch identity mismatch"
            raise ValueError(msg)
        artifact = await NeighborBinding.find_one(
            {"_id": reference.artifact_id, "identity": expected.model_dump(), "content_hash": reference.content_hash}
        )
        if (
            artifact is None
            or artifact.id != reference.artifact_id
            or artifact.identity != expected
            or expected.source_dispatch_id != reference.source_dispatch_id
            or expected.expires_at <= utc_now()
            or artifact.content_hash != reference.content_hash
            or _digest(artifact.identity, artifact.encrypted_mac) != reference.content_hash
        ):
            msg = "Private candidate binding is unavailable or invalid"
            raise ValueError(msg)
        mac = self.vault.decrypt_for_context(artifact.encrypted_mac, context=_aad(expected, reference.artifact_id))
        if re.fullmatch(r"[0-9a-f]{12}", mac) is None:
            msg = "Invalid decrypted candidate identity"
            raise ValueError(msg)
        source_handle = sha256(
            f"observed-neighbor.v1:{expected.organization_id}:{expected.audit_id}:{expected.target.handle}:{mac}".encode()
        ).hexdigest()
        if mac == expected.target.device_mac or source.rows[0].neighbor_handle != source_handle:
            msg = "Candidate does not match the observed source neighbor"
            raise ValueError(msg)
        return PrivateCandidate(mac, expected.mist_org_id, expected.target.site_id)
