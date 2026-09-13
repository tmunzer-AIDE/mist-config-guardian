"""Authorized published preview plus live dispatch metadata; no unpublished evidence artifacts."""

from beanie import PydanticObjectId

from mist_config_guardian_backend.impact.agent import ModelActivity
from mist_config_guardian_backend.impact.contracts import (
    ApEvidence,
    NeighborEvidence,
    PortEvidence,
    PortHistoryEvidence,
)
from mist_config_guardian_backend.impact.dispatch import DispatchLog
from mist_config_guardian_backend.impact.limits import MAX_PUBLISHED_CHECKPOINTS
from mist_config_guardian_backend.models.investigation import (
    ROOT_METADATA_PROJECTION,
    ImpactInvestigation,
)
from mist_config_guardian_backend.models.webhook import AuditChangeGroup
from mist_config_guardian_backend.schemas.investigation import (
    ReportHistory,
    ShadowCheckResponse,
    ShadowInvestigationResponse,
    ShadowTargetResponse,
)
from mist_config_guardian_backend.services.audit_impact_reads import project_published_impact
from mist_config_guardian_backend.services.published_revision import published_revision


async def read_investigation_root(query: dict[str, object]) -> ImpactInvestigation | None:
    document = await ImpactInvestigation.get_pymongo_collection().find_one(query, projection=ROOT_METADATA_PROJECTION)
    return ImpactInvestigation.model_validate(document) if document is not None else None


async def shadow_investigation(
    organization_id: PydanticObjectId,
    group_id: PydanticObjectId,
) -> ShadowInvestigationResponse | None:
    group = await AuditChangeGroup.find_one({"_id": group_id, "organization_id": organization_id})
    if group is None:
        return None
    root = await read_investigation_root({"organization_id": organization_id, "audit_id": group.audit_id})
    if root is None:
        return None
    publication = await published_revision(root)
    artifact = publication or None
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
        report=artifact.report if artifact else None,
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
            artifact.model_dump(include={"assessment", "plan", "report"}) if artifact else None,
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
                port_events=e.rows if isinstance(e, PortHistoryEvidence) else (),
                port=e.rows[0] if isinstance(e, PortEvidence) and e.rows else None,
                ap_adjacency=e.rows[0] if isinstance(e, ApEvidence) and e.rows else None,
                managed_neighbor=e.rows[0] if isinstance(e, NeighborEvidence) and e.rows else None,
                response_error=e.response_error if isinstance(e, PortEvidence) else None,
                device_mac=next(
                    (t.device_mac for t in artifact.plan.port_targets if t.handle == e.target_handle), None
                ),
                port_id=next((t.port_id for t in artifact.plan.port_targets if t.handle == e.target_handle), None),
            )
            for e in artifact.evidence
        ]
        if artifact
        else [],
    )


async def report_history(organization_id: PydanticObjectId, group_id: PydanticObjectId) -> ReportHistory | None:
    """Follow only the immutable published-parent chain, never orphan revision numbers."""
    group = await AuditChangeGroup.find_one({"_id": group_id, "organization_id": organization_id})
    if group is None:
        return None
    root = await read_investigation_root({"organization_id": organization_id, "audit_id": group.audit_id})
    if root is None:
        return None
    cursor = root
    reports = []
    gaps = []
    for _ in range(MAX_PUBLISHED_CHECKPOINTS):
        artifact = await published_revision(cursor)
        if not artifact:
            if cursor.revision:
                gaps.append("A published revision is unavailable; history is incomplete.")
            break
        if artifact.report:
            reports.append(artifact.report)
        else:
            gaps.append("A legacy revision has no structured report.")
        if artifact.revision == 1:
            break
        if artifact.previous_report_id is None:
            gaps.append("The earlier publication chain was not retained.")
            break
        cursor = cursor.model_copy(update={"report_id": artifact.previous_report_id, "revision": artifact.revision - 1})
    else:
        gaps.append("Publication history exceeded its supported bound.")
    return ReportHistory(
        investigation_id=str(root.id),
        published_revision=root.revision,
        complete=not gaps,
        reports=tuple(reports),
        gaps=tuple(gaps),
    )
