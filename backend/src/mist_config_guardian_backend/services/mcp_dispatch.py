"""Fenced, budgeted dispatch to the existing Mist MCP; no provider credentials in artifacts."""

import json
from datetime import timedelta
from hashlib import sha256
from uuid import uuid4

from beanie import PydanticObjectId
from beanie.odm.utils.encoder import Encoder

from mist_config_guardian_backend.impact.limits import MAX_AUDIT_CALLS
from mist_config_guardian_backend.impact.mcp_contracts import McpDispatch, McpEvidence
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.investigation import ImpactInvestigation, ModelRequestArtifact
from mist_config_guardian_backend.models.organization import Organization, OrganizationStatus


class McpDispatchDeniedError(RuntimeError):
    """Fixed operator-facing reason, never a database or credential value."""


class McpJournal:
    def __init__(self, root: ImpactInvestigation, credential: str) -> None:
        self.root, self.credential = root, credential

    async def reserve(self, tool: str, arguments: dict) -> McpDispatch:
        root = self.root
        record = McpDispatch(
            id=uuid4(),
            generation=root.generation,
            candidate_revision=root.revision + 1,
            tool=tool,
            arguments_hash=sha256(json.dumps(arguments, sort_keys=True).encode()).hexdigest(),
            reserved_at=utc_now(),
        )
        # Input first. An uncertain insert or reservation never authorizes HTTP.
        artifact = await self.artifact(record, "mcp_input", json.dumps(arguments, sort_keys=True))
        record = record.model_copy(update={"input_artifact_id": str(artifact.id)})
        organization = await Organization.get(root.organization_id)
        now = utc_now()
        if organization is None or organization.status is not OrganizationStatus.VERIFIED:
            msg = "Organization is no longer verified."
            raise McpDispatchDeniedError(msg)
        if organization.encrypted_service_token != self.credential:
            msg = "Organization service credential changed; dispatch stopped."
            raise McpDispatchDeniedError(msg)
        if now > root.expires_at + timedelta(minutes=2):
            msg = "Investigation evidence window expired."
            raise McpDispatchDeniedError(msg)
        result = await ImpactInvestigation.get_pymongo_collection().update_one(
            {
                "_id": root.id,
                "organization_id": root.organization_id,
                "generation": root.generation,
                "lease_until": {"$gt": now},
                "calls_used": {"$lt": min(root.calls_limit, MAX_AUDIT_CALLS)},
                f"mcp_dispatches.{MAX_AUDIT_CALLS - 1}": {"$exists": False},
            },
            {"$inc": {"calls_used": 1}, "$push": {"mcp_dispatches": Encoder().encode(record)}},
        )
        if result.matched_count != 1:
            msg = "Audit query budget or worker lease is no longer available."
            raise McpDispatchDeniedError(msg)
        return record

    async def artifact(self, record: McpDispatch, kind: str, body: str) -> ModelRequestArtifact:
        if self.root.id is None:
            msg = "Persisted investigation identity is unavailable."
            raise McpDispatchDeniedError(msg)
        artifact = ModelRequestArtifact(
            id=PydanticObjectId(),
            organization_id=self.root.organization_id,
            investigation_id=self.root.id,
            request_id=record.id,
            generation=record.generation,
            candidate_revision=record.candidate_revision,
            kind=kind,
            content_hash=sha256(body.encode()).hexdigest(),
            content_json=body,
            created_at=utc_now(),
            retained_until=self.root.retained_until,
        )
        await artifact.insert()
        return artifact

    async def finish(self, record: McpDispatch, evidence: McpEvidence) -> None:
        if (
            record.id != evidence.id
            or record.tool != evidence.tool
            or record.arguments_hash != sha256(json.dumps(evidence.arguments, sort_keys=True).encode()).hexdigest()
        ):
            msg = "MCP completion identity does not match its reservation."
            raise McpDispatchDeniedError(msg)
        artifact = await self.artifact(record, "mcp_result", evidence.model_dump_json())
        fields = {
            "state": evidence.state,
            "finished_at": utc_now(),
            "artifact_id": str(artifact.id),
            "content_hash": artifact.content_hash,
            "error": evidence.error,
        }
        result = await ImpactInvestigation.get_pymongo_collection().update_one(
            Encoder().encode(
                {
                    "_id": self.root.id,
                    "organization_id": self.root.organization_id,
                    "mcp_dispatches": {
                        "$elemMatch": {
                            "id": record.id,
                            "generation": record.generation,
                            "candidate_revision": record.candidate_revision,
                            "state": "reserved",
                        }
                    },
                }
            ),
            {"$set": Encoder().encode({f"mcp_dispatches.$.{k}": v for k, v in fields.items()})},
        )
        if result.matched_count != 1:
            msg = "MCP completion was not journalled; publication stopped."
            raise RuntimeError(msg)
