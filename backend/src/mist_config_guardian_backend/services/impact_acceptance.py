"""Authenticated human labels and offline replay of pinned, retained evidence."""

from hashlib import sha256

from beanie import PydanticObjectId
from pymongo.errors import PyMongoError

from mist_config_guardian_backend.impact.acceptance import (
    AcceptanceCase,
    AcceptanceResult,
    AdjudicationRequest,
    acceptance,
    policy_hash,
)
from mist_config_guardian_backend.impact.contracts import SessionEvidence
from mist_config_guardian_backend.impact.domain_evaluation import compose_domains
from mist_config_guardian_backend.impact.limits import MAX_PUBLISHED_CHECKPOINTS
from mist_config_guardian_backend.impact.report import Band
from mist_config_guardian_backend.impact.wlan_removal import evaluate_wlan_removal
from mist_config_guardian_backend.models.adjudication import ImpactAdjudication
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.investigation import InvestigationRevision
from mist_config_guardian_backend.models.webhook import AuditChangeGroup
from mist_config_guardian_backend.services.investigation_reads import read_investigation_root
from mist_config_guardian_backend.services.published_revision import published_revision


async def replay_chain(head: InvestigationRevision) -> tuple[str, Band] | None:
    """Replay the published chain without Mist/model calls; preserve earlier proven loss."""
    digest = sha256()
    peak: Band = "none"
    order = {"none": 0, "info": 1, "warning": 2, "critical": 3}
    artifact = head
    for _ in range(MAX_PUBLISHED_CHECKPOINTS):
        digest.update(
            artifact.model_dump_json(
                include={"id", "previous_report_id", "revision", "plan", "evidence", "assessment"}
            ).encode()
        )
        base = evaluate_wlan_removal(
            artifact.plan,
            [e for e in artifact.evidence if isinstance(e, SessionEvidence)],
            evidence_as_of=artifact.assessment.evaluated_at,
        )
        replay = compose_domains(artifact.plan, artifact.evidence, base)
        predicted = replay.impact if replay.impact != "none" or replay.coverage == "complete" else "info"
        if artifact is head:
            peak = predicted
        elif predicted in {"warning", "critical"}:
            peak = max((peak, predicted), key=order.__getitem__)
        if artifact.revision == 1:
            return digest.hexdigest(), peak
        if artifact.previous_report_id is None:
            return None
        parent = await InvestigationRevision.find_one(
            {
                "_id": artifact.previous_report_id,
                "organization_id": head.organization_id,
                "investigation_id": head.investigation_id,
                "revision": artifact.revision - 1,
            }
        )
        if parent is None or (
            parent.id != artifact.previous_report_id
            or parent.organization_id != head.organization_id
            or parent.investigation_id != head.investigation_id
            or parent.revision != artifact.revision - 1
            or parent.plan.audit_id != head.plan.audit_id
            or parent.assessment.audit_id != head.assessment.audit_id
            or parent.plan.organization_id != str(head.organization_id)
        ):
            return None
        artifact = parent
    return None


async def adjudicate(
    org: PydanticObjectId, group_id: PydanticObjectId, reviewer: PydanticObjectId, request: AdjudicationRequest
) -> bool:
    group = await AuditChangeGroup.find_one({"_id": group_id, "organization_id": org})
    if group is None:
        return False
    root = await read_investigation_root({"organization_id": org, "audit_id": group.audit_id})
    if (
        root is None
        or root.status not in {"completed", "incomplete"}
        or str(root.report_id) != request.report_id
        or root.revision != request.revision
    ):
        return False
    artifact = await published_revision(root)
    if not artifact or root.id is None or artifact.id is None:
        return False
    replay = await replay_chain(artifact)
    if replay is None:
        return False
    await ImpactAdjudication(
        organization_id=org,
        investigation_id=root.id,
        audit_id=root.audit_id,
        report_id=artifact.id,
        revision=artifact.revision,
        reviewer_id=reviewer,
        reviewed_at=utc_now(),
        retained_until=root.retained_until,
        label=request.label,
        rationale=request.rationale,
        evidence_hash=replay[0],
        policy_hash=policy_hash(),
    ).insert()
    return True


async def acceptance_status(org: PydanticObjectId) -> AcceptanceResult:
    fingerprint = policy_hash()
    try:
        labels = await ImpactAdjudication.find({"organization_id": org, "policy_hash": fingerprint}).limit(51).to_list()
        cases = []
        for label in labels:
            artifact = await InvestigationRevision.find_one(
                {
                    "_id": label.report_id,
                    "organization_id": org,
                    "investigation_id": label.investigation_id,
                    "revision": label.revision,
                }
            )
            valid = bool(
                artifact
                and artifact.id == label.report_id
                and artifact.organization_id == org
                and artifact.investigation_id == label.investigation_id
                and artifact.revision == label.revision
                and artifact.plan.audit_id == label.audit_id
                and artifact.assessment.audit_id == label.audit_id
                and artifact.plan.organization_id == str(org)
            )
            replay = await replay_chain(artifact) if valid and artifact else None
            valid = bool(valid and replay and replay[0] == label.evidence_hash)
            predicted = replay[1] if valid and replay else "info"
            cases.append(AcceptanceCase(audit_id=label.audit_id, label=label.label, predicted=predicted, valid=valid))
        return acceptance(cases, fingerprint=fingerprint)
    except (PyMongoError, ValueError):
        return AcceptanceResult(
            policy_hash=fingerprint, reasons=("Adjudication evidence is unavailable; promotion denied.",)
        )
