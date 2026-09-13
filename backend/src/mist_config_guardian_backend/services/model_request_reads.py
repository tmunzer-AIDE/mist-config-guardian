"""Load one journal-linked request's payloads on demand, never arbitrary artifacts."""

import json
from hashlib import sha256
from typing import Literal
from uuid import UUID

from beanie import PydanticObjectId
from beanie.odm.utils.encoder import Encoder
from pymongo.errors import PyMongoError

from mist_config_guardian_backend.impact.agent import ACTION_ADAPTER, MAX_INPUT_BYTES, ModelRequestRecord
from mist_config_guardian_backend.models.investigation import ImpactInvestigation, ModelRequestArtifact
from mist_config_guardian_backend.models.webhook import AuditChangeGroup
from mist_config_guardian_backend.schemas.investigation import ModelRequestDetails


async def model_request_details(
    organization_id: PydanticObjectId, group_id: PydanticObjectId, request_id: UUID
) -> ModelRequestDetails | None:
    try:
        return await _details(organization_id, group_id, request_id)
    except (PyMongoError, ValueError, TypeError):
        # No payload or provider/DB error text leaks through a failed read.
        return ModelRequestDetails(request_id=request_id)


async def _details(  # noqa: C901 - current artifacts and bounded legacy payloads remain distinct
    organization_id: PydanticObjectId, group_id: PydanticObjectId, request_id: UUID
) -> ModelRequestDetails | None:
    group = await AuditChangeGroup.find_one({"_id": group_id, "organization_id": organization_id})
    if group is None:
        return None
    selected = Encoder().encode({"$elemMatch": {"id": request_id}})
    root = await ImpactInvestigation.get_pymongo_collection().find_one(
        {"organization_id": organization_id, "audit_id": group.audit_id},
        projection={"_id": 1, "model_requests": selected},
    )
    if root is None or not root.get("model_requests"):
        return None
    raw = root["model_requests"][0]
    record = ModelRequestRecord.model_validate({k: v for k, v in raw.items() if k not in {"input_json", "action"}})
    if record.id != request_id:
        return None
    result = ModelRequestDetails(request_id=request_id)
    if record.input_artifact_id is not None:
        body = await _artifact(organization_id, root["_id"], record, "input")
        if body is not None and isinstance(json.loads(body), dict):
            result.input_json, result.input_state = body, "available"
    else:
        body = raw.get("input_json")
        if isinstance(body, str) and len(body.encode()) <= MAX_INPUT_BYTES and isinstance(json.loads(body), dict):
            result.input_json, result.input_state = body, "legacy"
    if record.action_artifact_id is not None:
        body = await _artifact(organization_id, root["_id"], record, "action")
        if body is not None:
            result.action, result.action_state = ACTION_ADAPTER.validate_json(body), "available"
    elif raw.get("action") is not None:
        result.action, result.action_state = ACTION_ADAPTER.validate_python(raw["action"]), "legacy"
    elif record.state != "complete":
        result.action_state = "not_recorded"
    return result


async def _artifact(
    organization_id: PydanticObjectId,
    investigation_id: PydanticObjectId,
    record: ModelRequestRecord,
    kind: Literal["input", "action"],
) -> str | None:
    identifier = record.input_artifact_id if kind == "input" else record.action_artifact_id
    expected_hash = record.input_context_hash if kind == "input" else record.action_hash
    if identifier is None or expected_hash is None:
        return None
    identity = {
        "_id": identifier,
        "organization_id": organization_id,
        "investigation_id": investigation_id,
        "request_id": record.id,
        "generation": record.generation,
        "candidate_revision": record.candidate_revision,
        "kind": kind,
        "content_hash": expected_hash,
    }
    artifact = await ModelRequestArtifact.find_one(identity)
    if artifact is None:
        return None
    actual = {**artifact.model_dump(), "_id": artifact.id}
    if any(actual.get(key) != value for key, value in identity.items()):
        return None
    body = artifact.content_json
    if len(body.encode()) > MAX_INPUT_BYTES or sha256(body.encode()).hexdigest() != expected_hash:
        return None
    return body
