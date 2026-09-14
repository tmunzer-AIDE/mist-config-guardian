"""On-demand MCP artifact reads require an authorized audit and exact journal pointers."""

import json
from hashlib import sha256
from uuid import UUID

from beanie import PydanticObjectId
from beanie.odm.utils.encoder import Encoder
from pymongo.errors import PyMongoError

from mist_config_guardian_backend.impact.agent import MAX_INPUT_BYTES
from mist_config_guardian_backend.impact.mcp_contracts import McpDispatch, McpEvidence
from mist_config_guardian_backend.models.investigation import ImpactInvestigation, ModelRequestArtifact
from mist_config_guardian_backend.models.webhook import AuditChangeGroup
from mist_config_guardian_backend.schemas.investigation import ModelRequestDetails


async def mcp_request_details(
    organization_id: PydanticObjectId, group_id: PydanticObjectId, request_id: UUID
) -> ModelRequestDetails | None:
    try:
        return await _details(organization_id, group_id, request_id)
    except (PyMongoError, ValueError, TypeError):
        return ModelRequestDetails(request_id=request_id, response_state="unavailable")


async def _details(  # noqa: C901 - verify both journal-linked artifacts independently
    organization_id: PydanticObjectId, group_id: PydanticObjectId, request_id: UUID
) -> ModelRequestDetails | None:
    group = await AuditChangeGroup.find_one({"_id": group_id, "organization_id": organization_id})
    if group is None:
        return None
    root = await ImpactInvestigation.get_pymongo_collection().find_one(
        {"organization_id": organization_id, "audit_id": group.audit_id},
        projection={"_id": 1, "mcp_dispatches": Encoder().encode({"$elemMatch": {"id": request_id}})},
    )
    if root is None or not root.get("mcp_dispatches"):
        return None
    record = McpDispatch.model_validate(root["mcp_dispatches"][0])
    if record.id != request_id:
        return None
    result = ModelRequestDetails(request_id=request_id, action_state="not_recorded")
    for kind, identity, digest in (
        ("mcp_input", record.input_artifact_id, record.arguments_hash),
        ("mcp_result", record.artifact_id, record.content_hash),
    ):
        if identity is None or digest is None:
            continue
        query = {
            "_id": PydanticObjectId(identity),
            "organization_id": organization_id,
            "investigation_id": root["_id"],
            "request_id": request_id,
            "generation": record.generation,
            "candidate_revision": record.candidate_revision,
            "kind": kind,
            "content_hash": digest,
        }
        artifact = await ModelRequestArtifact.find_one(query)
        actual = {**artifact.model_dump(), "_id": artifact.id} if artifact else {}
        if artifact is None or any(actual.get(k) != v for k, v in query.items()):
            continue
        body = artifact.content_json
        if len(body.encode()) > MAX_INPUT_BYTES or sha256(body.encode()).hexdigest() != digest:
            continue
        if kind == "mcp_input" and isinstance(json.loads(body), dict):
            result.input_json, result.input_state = body, "available"
        elif kind == "mcp_result":
            evidence = McpEvidence.model_validate_json(body)
            if evidence.id == record.id and evidence.tool == record.tool:
                result.response_json, result.response_state = body, "available"
    if record.state != "reserved" and result.response_state != "available":
        result.response_state = "unavailable"
    return result
