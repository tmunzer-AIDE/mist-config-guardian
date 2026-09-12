"""Bounded batch projection of exact published revisions, without evidence payloads."""

import logging
from collections.abc import Sequence
from typing import Any, Protocol

from beanie import PydanticObjectId
from pymongo.errors import PyMongoError

from mist_config_guardian_backend.models.investigation import ImpactInvestigation, InvestigationRevision
from mist_config_guardian_backend.schemas.audit_impact import AuditImpactSummary

logger = logging.getLogger(__name__)
_MAX_AUDITS = 500


class AuditImpactReader(Protocol):
    async def summaries(
        self, organization_id: PydanticObjectId, audit_ids: Sequence[str]
    ) -> dict[str, AuditImpactSummary]: ...


class PublishedAuditImpactReader:
    """Two bounded reads per page; root pointers are captured before artifact lookup."""

    async def summaries(
        self, organization_id: PydanticObjectId, audit_ids: Sequence[str]
    ) -> dict[str, AuditImpactSummary]:
        identities = sorted(set(audit_ids))
        if len(identities) > _MAX_AUDITS:
            msg = "Audit projection batch exceeds the page limit"
            raise ValueError(msg)
        if not identities:
            return {}
        try:
            return await self._read(organization_id, identities)
        except PyMongoError:
            # A failing shadow read cannot break production pages or look benign.
            logger.warning("Published shadow assessment read unavailable for organization %s", organization_id)
            return {key: AuditImpactSummary(result="unavailable") for key in identities}

    async def _read(self, organization_id: PydanticObjectId, audit_ids: list[str]) -> dict[str, AuditImpactSummary]:
        roots = (
            await ImpactInvestigation.get_pymongo_collection()
            .find(
                {"organization_id": organization_id, "audit_id": {"$in": audit_ids}},
                {"audit_id": 1, "report_id": 1, "revision": 1, "status": 1, "stop_reason": 1},
            )
            .to_list(length=_MAX_AUDITS)
        )
        references = [
            {"_id": root["report_id"], "investigation_id": root["_id"], "revision": root["revision"]}
            for root in roots
            if root.get("report_id")
        ]
        artifacts = (
            await InvestigationRevision.get_pymongo_collection()
            .find(
                {"organization_id": organization_id, "$or": references},
                {
                    "investigation_id": 1,
                    "revision": 1,
                    "assessment.audit_id": 1,
                    "assessment.policy_version": 1,
                    "assessment.evaluated_at": 1,
                    "assessment.impact": 1,
                    "assessment.confidence": 1,
                    "assessment.coverage": 1,
                    "assessment.gaps": 1,
                    "plan.unmapped": 1,
                },
            )
            .to_list(length=_MAX_AUDITS)
            if references
            else []
        )
        by_reference = {(a["_id"], a["investigation_id"], a["revision"]): a for a in artifacts}
        result = {key: AuditImpactSummary(result="not_recorded") for key in audit_ids}
        for root in roots:
            artifact = by_reference.get((root.get("report_id"), root["_id"], root["revision"]))
            result[root["audit_id"]] = project_published_impact(root, artifact)
        return result


def project_published_impact(root: dict[str, Any], artifact: dict[str, Any] | None) -> AuditImpactSummary:
    """Render one validated publication reference; callers enforce tenant and pointer identity."""
    assessment = artifact["assessment"] if artifact else None
    if assessment and assessment["audit_id"] != root["audit_id"]:
        assessment = None
    summary = AuditImpactSummary(
        result="unavailable"
        if root.get("report_id") or root["revision"] > 0 or root["status"] in {"incomplete", "completed"}
        else "pending",
        investigation_id=str(root["_id"]),
        revision=root["revision"],
        status=root["status"],
        stop_reason=root.get("stop_reason", ""),
    )
    if assessment and artifact is not None:
        summary.report_id = str(root["report_id"])
        summary.policy_version = assessment["policy_version"]
        summary.evaluated_at = assessment["evaluated_at"]
        summary.impact = assessment["impact"]
        summary.confidence = assessment["confidence"]
        summary.coverage = assessment["coverage"]
        summary.gap_count = len(assessment["gaps"])
        summary.unmapped_count = len(artifact["plan"]["unmapped"])
        summary.result = "insufficient_evidence"
        if summary.impact == "warning":
            summary.result = "possible_disruption"
        elif summary.impact == "none" and summary.coverage == "complete" and root["status"] != "incomplete":
            summary.result = "no_observed_disconnect"
    return summary
