"""Exact, tenant-bound publication reads shared by memory and operator reports."""

from typing import Literal

from pymongo.errors import PyMongoError

from mist_config_guardian_backend.models.investigation import ImpactInvestigation, InvestigationRevision


async def published_revision(root: ImpactInvestigation) -> InvestigationRevision | Literal[False] | None:
    if root.report_id is None:
        return None
    try:
        artifact = await InvestigationRevision.find_one(
            {
                "_id": root.report_id,
                "organization_id": root.organization_id,
                "investigation_id": root.id,
                "revision": root.revision,
            }
        )
    except PyMongoError:
        return False
    if not isinstance(artifact, InvestigationRevision) or (
        artifact.id != root.report_id
        or artifact.organization_id != root.organization_id
        or artifact.investigation_id != root.id
        or artifact.revision != root.revision
        or artifact.plan.audit_id != root.audit_id
        or artifact.assessment.audit_id != root.audit_id
        or artifact.plan.organization_id != str(root.organization_id)
    ):
        return False
    if artifact.agent and artifact.agent.memory and artifact.agent.memory.source_revision > root.revision:
        return False
    if artifact.report and (
        artifact.report.investigation_id != str(root.id)
        or artifact.report.audit_id != root.audit_id
        or artifact.report.revision != root.revision
    ):
        return False
    return artifact
