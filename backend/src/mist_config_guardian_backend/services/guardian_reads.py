"""Guardian's read path: bounded root projections for current views, and detailed reads that prove tenancy first.

Two shapes are served from here.

1. **Summaries.** One bounded batch per page projects the small roots behind the audits a page returned, and, when
   a caller needs device rows, the exact runs those roots published. A failure reports ``unavailable`` rather than a
   clean result, and no read here touches a legacy collection.
2. **Details.** The investigation and one run. Both walk the whole chain before answering: the organization, the
   change group inside it, the root for that group's audit, the root's pointers, and the run's own tenant and
   investigation. Every filter comes from :mod:`~mist_config_guardian_backend.guardian.repository`.

Nothing here re-derives a verdict. The report is rendered from the immutable run on read, the published result is
passed through as the root stored it, and whether a run is published is derived from the root's pointers.
"""

import logging
from collections.abc import Sequence
from typing import Any, Protocol

from beanie import PydanticObjectId
from pymongo.errors import PyMongoError

from mist_config_guardian_backend.guardian import repository as repo
from mist_config_guardian_backend.guardian.contracts import MAX_ATTEMPTS_PER_KIND
from mist_config_guardian_backend.models.guardian import GuardianInvestigation, GuardianResult, GuardianRun
from mist_config_guardian_backend.models.webhook import AuditChangeGroup
from mist_config_guardian_backend.schemas.guardian import (
    GuardianAttemptSummary,
    GuardianImpactedDevices,
    GuardianInvestigationResponse,
    GuardianRootResponse,
    GuardianRunReport,
    GuardianRunResponse,
    GuardianSummary,
)

logger = logging.getLogger(__name__)

# One page of change groups, matching the largest page the change-group and site pages ask for.
MAX_PROJECTED_AUDITS = 500
# Two kinds, each capped at its attempts, so one root can never hold more runs than this.
MAX_RUNS = 2 * MAX_ATTEMPTS_PER_KIND


class GuardianReader(Protocol):
    """The batched projection the changes, overview and site impact pages share."""

    async def summaries(
        self, organization_id: PydanticObjectId, audit_ids: Sequence[str], *, include_devices: bool = False
    ) -> dict[str, GuardianSummary]: ...


class PublishedGuardianReader:
    """One bounded read of the roots, plus one of the runs they point at when device rows are asked for."""

    async def summaries(
        self, organization_id: PydanticObjectId, audit_ids: Sequence[str], *, include_devices: bool = False
    ) -> dict[str, GuardianSummary]:
        identities = sorted(set(audit_ids))
        if len(identities) > MAX_PROJECTED_AUDITS:
            msg = "Guardian projection batch exceeds the page limit"
            raise ValueError(msg)
        if not identities:
            return {}
        try:
            return await self._read(organization_id, identities, include_devices=include_devices)
        except PyMongoError:
            # A failing Guardian read cannot break a production page, and cannot look like a clean assessment.
            logger.warning("Guardian projection unavailable for organization %s", organization_id)
            return {audit_id: GuardianSummary.unavailable() for audit_id in identities}

    async def _read(
        self, organization_id: PydanticObjectId, audit_ids: list[str], *, include_devices: bool
    ) -> dict[str, GuardianSummary]:
        roots_read = repo.investigations_for_audits(organization_id, audit_ids)
        roots = (
            await GuardianInvestigation.get_pymongo_collection()
            .find(roots_read.filter, roots_read.projection)
            .to_list(length=MAX_PROJECTED_AUDITS)
        )
        summaries = {
            root["audit_id"]: GuardianSummary(
                status=root["status"],
                status_reason=root.get("status_reason"),
                result=_result(root.get("result")),
            )
            for root in roots
        }
        if include_devices:
            await self._overlay_devices(organization_id, roots, summaries)
        return summaries

    async def _overlay_devices(
        self,
        organization_id: PydanticObjectId,
        roots: Sequence[dict[str, Any]],
        summaries: dict[str, GuardianSummary],
    ) -> None:
        """Attach each published run's own compact rows, which the capped root list cannot stand in for."""
        pointers = [
            (root["_id"], root["audit_id"], pointer)
            for root in roots
            if (pointer := _published_pointer(root)) is not None
        ]
        if not pointers:
            return
        runs_read = repo.published_runs(
            [(pointer, root_id) for root_id, _audit_id, pointer in pointers], organization_id=organization_id
        )
        runs = (
            await GuardianRun.get_pymongo_collection()
            .find(runs_read.filter, runs_read.projection)
            .to_list(length=MAX_PROJECTED_AUDITS)
        )
        by_root = {root_id: audit_id for root_id, audit_id, _pointer in pointers}
        for document in runs:
            audit_id = by_root.get(document["investigation_id"])
            verdict = document.get("verdict") or {}
            if audit_id is None or audit_id not in summaries:
                continue
            summaries[audit_id].impacted = GuardianImpactedDevices.model_validate(
                {
                    "devices": verdict.get("impacted_devices", ()),
                    "omitted": verdict.get("impacted_devices_omitted", 0),
                }
            )


def _result(stored: dict[str, Any] | None) -> GuardianResult | None:
    return None if stored is None else GuardianResult.model_validate(stored)


def _published_pointer(root: dict[str, Any]) -> PydanticObjectId | None:
    """The run the root currently publishes: the final one once it exists, otherwise the early one."""
    return root.get("final_run_id") or root.get("early_run_id")


async def guardian_investigation(
    organization_id: PydanticObjectId, change_group_id: PydanticObjectId
) -> GuardianInvestigationResponse | None:
    """One audit's root, the runs it published with their rendered reports, and every attempt it consumed."""
    root = await _root(organization_id, change_group_id)
    if root is None or root.id is None:
        return None
    runs_read = repo.investigation_runs(root.id, organization_id=organization_id)
    runs = await GuardianRun.find(runs_read.filter).sort(list(runs_read.sort)).limit(MAX_RUNS).to_list()
    return GuardianInvestigationResponse(
        root=GuardianRootResponse.from_root(root),
        runs=[GuardianRunReport.from_run(run, published=True) for run in runs if root.publishes(run)],
        attempts=[GuardianAttemptSummary.from_run(run, published=root.publishes(run)) for run in runs],
    )


async def guardian_run(
    organization_id: PydanticObjectId, change_group_id: PydanticObjectId, run_id: PydanticObjectId
) -> GuardianRunResponse | None:
    """One full run, published or not, and only through the change group whose investigation owns it."""
    root = await _root(organization_id, change_group_id)
    if root is None or root.id is None:
        return None
    read = repo.run_in_investigation(run_id, root_id=root.id, organization_id=organization_id)
    run = await GuardianRun.find_one(read.filter)
    if run is None:
        return None
    return GuardianRunResponse.from_run(run, published=root.publishes(run))


async def _root(organization_id: PydanticObjectId, change_group_id: PydanticObjectId) -> GuardianInvestigation | None:
    """The root for one change group's audit, reached only through a change group inside the organization."""
    group = await AuditChangeGroup.find_one({"_id": change_group_id, "organization_id": organization_id})
    if group is None:
        return None
    read = repo.investigation_identity(organization_id, group.audit_id)
    return await GuardianInvestigation.find_one(read.filter)
