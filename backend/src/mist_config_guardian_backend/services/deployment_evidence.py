"""Bounded local receipt evidence for one audit; never performs operational checks."""

from datetime import datetime
from typing import Any

from pydantic import ValidationError
from pymongo.errors import PyMongoError

from mist_config_guardian_backend.impact.deployment import (
    DeploymentEvidence,
    DeploymentObservation,
    DeploymentSignal,
    deployment_devices,
)
from mist_config_guardian_backend.models.investigation import ImpactInvestigation
from mist_config_guardian_backend.models.monitoring import MonitoringSession
from mist_config_guardian_backend.models.webhook import WebhookReceipt

_MAX_SESSIONS = 500
_MAX_SESSION_RECEIPTS = 32
_MAX_CANDIDATE_RECEIPTS = 4000
_MAX_EVENTS = 2000
_MAX_DEVICES = 500


async def collect_deployment(root: ImpactInvestigation, *, as_of: datetime) -> DeploymentEvidence:
    """Pin the observed deployment set to this report revision, independently of SLE coverage."""
    try:
        candidates, gaps = await _candidate_receipts(root, as_of)
        rows = (
            await WebhookReceipt.get_pymongo_collection()
            .find(
                {
                    "organization_id": root.organization_id,
                    "topic": "device-events",
                    "signature_valid": True,
                    "created_at": {"$lte": as_of},
                    "$or": [{"audit_id": root.audit_id}, {"audit_id": None, "_id": {"$in": candidates}}],
                },
                {"audit_id": 1, "created_at": 1, "deployment_normalized": 1, "deployment": 1},
            )
            .sort([("created_at", -1), ("_id", -1)])
            .to_list(length=_MAX_EVENTS + 1)
        )
    except PyMongoError:
        return DeploymentEvidence(
            collected_at=as_of,
            state="unavailable",
            gaps=("Deployment receipt collection is unavailable.",),
        )
    if len(rows) > _MAX_EVENTS:
        gaps.append(
            "Deployment receipt limit reached; newest receipts retained and earlier deployment history may be missing."
        )
    observations = []
    for row in rows[:_MAX_EVENTS]:
        observation = _observation(root, row, gaps, as_of)
        if observation is not None:
            observations.append(observation)
    identities = {
        (o.signal.site_id, o.signal.device_mac) for o in observations if o.signal.site_id and o.signal.device_mac
    }
    if len(identities) > _MAX_DEVICES:
        gaps.append("Deployment device limit reached; additional identities remain in the receipt observations.")
    return DeploymentEvidence(
        collected_at=as_of,
        state="partial" if gaps else "available",
        observations=tuple(observations),
        devices=deployment_devices(observations),
        gaps=tuple(sorted(set(gaps))),
    )


async def _candidate_receipts(root: ImpactInvestigation, as_of: datetime) -> tuple[list[object], list[str]]:
    """A shared session provides candidates only, even if it currently names one audit."""
    sessions = (
        await MonitoringSession.get_pymongo_collection()
        .find(
            {"organization_id": root.organization_id, "audit_ids": root.audit_id, "created_at": {"$lte": as_of}},
            {"_id": 1, "receipt_ids": {"$slice": _MAX_SESSION_RECEIPTS + 1}},
        )
        .sort([("created_at", 1), ("_id", 1)])
        .to_list(length=_MAX_SESSIONS + 1)
    )
    gaps = []
    if len(sessions) > _MAX_SESSIONS:
        gaps.append("Session correlation limit reached; candidate receipts may be missing.")
    candidates = set()
    for session in sessions[:_MAX_SESSIONS]:
        ids = session.get("receipt_ids", [])
        if len(ids) > _MAX_SESSION_RECEIPTS:
            gaps.append("A session's receipt limit was reached; candidate receipts may be missing.")
        candidates.update(ids[:_MAX_SESSION_RECEIPTS])
    if len(candidates) > _MAX_CANDIDATE_RECEIPTS:
        gaps.append("Candidate receipt limit reached; correlation is partial.")
    return sorted(candidates, key=str)[:_MAX_CANDIDATE_RECEIPTS], gaps


def _observation(
    root: ImpactInvestigation, row: dict[str, Any], gaps: list[str], as_of: datetime
) -> DeploymentObservation | None:
    if not row.get("deployment_normalized"):
        gaps.append("Older device-event receipts have no normalized deployment evidence; no history was inferred.")
        return None
    if row.get("deployment") is None:
        return None  # A normalized non-deployment event is deliberately outside this domain.
    if row.get("audit_id") not in {None, root.audit_id}:
        return None
    try:
        signal = DeploymentSignal.model_validate(row["deployment"])
        if row.get("audit_id") is None:
            correlation = "session_candidate"
        elif signal.occurred_at is None or not root.anchor_known:
            correlation = "time_unknown"
        elif not root.changed_at <= signal.occurred_at <= min(root.expires_at, as_of):
            correlation = "outside_window"
        else:
            correlation = "audit_id"
        observation = DeploymentObservation(
            receipt_id=str(row["_id"]),
            received_at=row["created_at"],
            correlation=correlation,
            signal=signal,
        )
    except ValidationError:
        gaps.append("A normalized deployment receipt is invalid; its device identity was not used.")
        return None
    gaps.extend(signal.gaps)
    if correlation == "session_candidate":
        gaps.append("Session-linked events lack an explicit audit ID; they are candidates, not confirmed deployment.")
    elif correlation in {"time_unknown", "outside_window"}:
        gaps.append(
            "Some audit-linked deployment events have uncertain timing or fall outside the investigation window."
        )
    return observation
