"""Authorized published preview plus live dispatch metadata; no unpublished evidence artifacts."""

from beanie import PydanticObjectId

from mist_config_guardian_backend.impact.agent import ModelActivity
from mist_config_guardian_backend.impact.dispatch import DispatchLog
from mist_config_guardian_backend.models.investigation import ImpactInvestigation, InvestigationRevision
from mist_config_guardian_backend.models.webhook import AuditChangeGroup
from mist_config_guardian_backend.schemas.investigation import (
    ShadowCheckResponse,
    ShadowInvestigationResponse,
    ShadowTargetResponse,
)
from mist_config_guardian_backend.services.audit_impact_reads import project_published_impact


async def shadow_investigation(
    organization_id: PydanticObjectId,
    group_id: PydanticObjectId,
) -> ShadowInvestigationResponse | None:
    group = await AuditChangeGroup.find_one({"_id": group_id, "organization_id": organization_id})
    if group is None:
        return None
    root = await ImpactInvestigation.find_one({"organization_id": organization_id, "audit_id": group.audit_id})
    if root is None:
        return None
    artifact = (
        await InvestigationRevision.find_one(
            {
                "_id": root.report_id,
                "organization_id": organization_id,
                "investigation_id": root.id,
                "revision": root.revision,
            }
        )
        if root.report_id
        else None
    )
    return ShadowInvestigationResponse(
        id=str(root.id),
        audit_id=root.audit_id,
        status=root.status,
        stop_reason=root.stop_reason,
        revision=root.revision,
        changed_at=root.changed_at,
        expires_at=root.expires_at,
        calls_used=root.calls_used,
        calls_limit=root.calls_limit,
        assessment=artifact.assessment if artifact else None,
        deployment=artifact.deployment if artifact else None,
        agent=artifact.agent if artifact else None,
        model_activity=ModelActivity(
            calls_used=root.model_calls_used,
            calls_limit=root.model_calls_limit,
            input_bytes_reserved=root.model_input_bytes_reserved,
            input_bytes_limit=root.model_input_bytes_limit,
            records=tuple(root.model_requests),
        )
        if root.model_requests or (artifact and artifact.agent is not None)
        else None,
        dispatch_log=DispatchLog(
            records=tuple(root.dispatches),
            unlogged_reservations=max(0, root.calls_used - len(root.dispatches)),
        ),
        shadow_impact=project_published_impact(
            {**root.model_dump(), "_id": root.id},
            artifact.model_dump(include={"assessment", "plan"}) if artifact else None,
        ),
        targets=[
            ShadowTargetResponse(handle=t.handle, site_id=str(t.site_id), wlan_id=str(t.wlan_id))
            for t in artifact.plan.targets
        ]
        if artifact
        else [],
        checks=[
            ShadowCheckResponse(
                check_id=e.check_id,
                target_handle=e.target_handle,
                window=e.window,
                captured_at=e.captured_at,
                state=e.state,
                row_count=len(e.rows),
                reason=e.reason,
                dispatch_denial=e.dispatch_denial,
            )
            for e in artifact.evidence
        ]
        if artifact
        else [],
    )
