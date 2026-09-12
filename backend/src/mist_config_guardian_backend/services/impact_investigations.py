"""Bounded deterministic shadow investigations driven by the existing worker tick."""

import logging
from datetime import datetime, timedelta
from functools import partial
from uuid import uuid4

from beanie import PydanticObjectId
from beanie.odm.utils.encoder import Encoder
from pymongo import ReturnDocument

from mist_config_guardian_backend.impact.contracts import SessionEvidence, WlanRemovalPlan
from mist_config_guardian_backend.impact.dispatch import MAX_DISPATCHES, DispatchRecord
from mist_config_guardian_backend.impact.wlan_removal import check_windows, compile_wlan_removal, evaluate_wlan_removal
from mist_config_guardian_backend.integrations.mist_wlan_evidence import MistWlanEvidenceClient
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.investigation import ImpactInvestigation, InvestigationRevision
from mist_config_guardian_backend.models.organization import Organization, OrganizationStatus
from mist_config_guardian_backend.models.webhook import AuditChangeGroup
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.change_groups import BeanieChangeGroupStore
from mist_config_guardian_backend.services.deployment_evidence import collect_deployment
from mist_config_guardian_backend.services.service_credentials import service_token

logger = logging.getLogger(__name__)
_LEASE = timedelta(minutes=3)
_INTERVAL = timedelta(minutes=10)
_DURATION = timedelta(hours=1)
_MAX_CHECKPOINTS = 10


class ImpactInvestigationService:
    """One root per audit; no provisional investigations and no device-agent fan-out."""

    def __init__(self, vault: CredentialVault) -> None:
        self._vault = vault
        self._configurations = BeanieChangeGroupStore()

    async def ensure(
        self,
        organization_id: PydanticObjectId,
        audit_id: str,
        *,
        changed_at: datetime,
        anchor_known: bool,
    ) -> None:
        """Persist the audit even before correlation; retries cannot reset budgets.

        Only the authenticated audit receipt path calls this method. An absent
        group delays evidence collection rather than silently losing the audit.
        """
        now = utc_now()
        due = max(now, changed_at) + timedelta(seconds=60)
        root = ImpactInvestigation(
            organization_id=organization_id,
            audit_id=audit_id,
            changed_at=changed_at,
            anchor_known=anchor_known,
            first_due_at=due,
            expires_at=changed_at + _DURATION,
            next_poll_at=due,
        )
        await ImpactInvestigation.get_pymongo_collection().update_one(
            {"organization_id": organization_id, "audit_id": audit_id},
            {"$setOnInsert": root.model_dump(mode="python", exclude={"id"})},
            upsert=True,
        )

    async def poll_due(self) -> int:
        """Use existing minute ticks; bounded claims, separate from device polling."""
        completed = 0
        for _ in range(20):
            now = utc_now()
            document = await ImpactInvestigation.get_pymongo_collection().find_one_and_update(
                {
                    "next_poll_at": {"$ne": None, "$lte": now},
                    "$or": [{"lease_until": None}, {"lease_until": {"$lte": now}}],
                },
                {"$set": {"lease_until": now + _LEASE}, "$inc": {"generation": 1}},
                sort=[("next_poll_at", 1)],
                return_document=ReturnDocument.AFTER,
            )
            if document is None:
                break
            root = ImpactInvestigation.model_validate(document)
            try:
                await self._poll(root)
                completed += 1
            except Exception:  # bounded lease permits another worker to retry after a crash
                logger.exception("Shadow impact checkpoint failed for investigation %s", root.id)
                if utc_now() > root.expires_at + timedelta(minutes=2):
                    await self._stop(root, "Investigation expired before a checkpoint could be published.")
        return completed

    @staticmethod
    def _fence(root: ImpactInvestigation, now: datetime) -> dict[str, object]:
        return {
            "_id": root.id,
            "organization_id": root.organization_id,
            "generation": root.generation,
            "lease_until": {"$gt": now},
        }

    async def _stop(self, root: ImpactInvestigation, reason: str) -> None:
        await ImpactInvestigation.get_pymongo_collection().update_one(
            self._fence(root, utc_now()),
            {
                "$set": {
                    "status": "incomplete",
                    "next_poll_at": None,
                    "lease_until": None,
                    "stop_reason": reason,
                }
            },
        )

    async def _plan(self, root: ImpactInvestigation) -> WlanRemovalPlan:
        group = await AuditChangeGroup.find_one({"organization_id": root.organization_id, "audit_id": root.audit_id})
        versions = (
            await self._configurations.versions_for_audit(root.organization_id, root.audit_id)
            if group is not None
            else []
        )
        # Only terminal versions per object are compiled; conflicting same-audit
        # chains remain a gap until the expander can establish their net change.
        versions.sort(key=lambda item: (str(item.logical_object_id), item.version))
        objects = await self._configurations.logical_objects(
            root.organization_id, [v.logical_object_id for v in versions]
        )
        before = await self._configurations.versions_at(
            root.organization_id,
            [(v.logical_object_id, v.version - 1) for v in versions if v.version > 1],
        )
        plan = compile_wlan_removal(
            organization_id=str(root.organization_id),
            audit_id=root.audit_id,
            changed_at=root.changed_at,
            logicals=objects,
            before=before,
            after=versions,
        )
        if group is None:
            plan = plan.model_copy(
                update={"gaps": (*plan.gaps, "Audit change group is not available; awaiting correlation.")}
            )
        if not root.anchor_known:
            plan = plan.model_copy(
                update={"gaps": (*plan.gaps, "Audit timestamp is missing; receipt time is only an approximate anchor.")}
            )
        return plan

    async def _poll(self, root: ImpactInvestigation) -> None:
        now = utc_now()
        # Only a fenced publication advances revision. Lease claims and orphan
        # artifacts are not completed checkpoints and must not consume this cap.
        if root.revision >= _MAX_CHECKPOINTS:
            await self._stop(root, "Published checkpoint limit reached; evidence is incomplete.")
            return
        plan = await self._plan(root)
        organization = await Organization.get(root.organization_id)
        evidence_as_of = min(now, root.expires_at)
        evidence = []
        # Delayed audit delivery cannot turn a historical change into a fresh hour.
        expired = now > root.expires_at + timedelta(minutes=2)
        if (
            plan.targets
            and organization is not None
            and organization.status is OrganizationStatus.VERIFIED
            and not expired
        ):
            token = await service_token(organization, self._vault)
            credential = organization.encrypted_service_token

            async with MistWlanEvidenceClient(token=token, region=organization.cloud_region) as client:
                for target in plan.targets:
                    for window in check_windows(plan, evidence_as_of):
                        dispatch = DispatchRecord(
                            id=uuid4(),
                            generation=root.generation,
                            candidate_revision=root.revision + 1,
                            target_handle=target.handle,
                            site_id=target.site_id,
                            wlan_id=target.wlan_id,
                            window=window,
                            reserved_at=utc_now(),
                        )
                        reading = await client.capture(
                            plan=plan,
                            target_handle=target.handle,
                            window=window,
                            reserve_dispatch=partial(self._reserve, root, credential, dispatch),
                        )
                        if reading.state != "budget_exhausted":
                            await self._finish_dispatch(root, dispatch, reading)
                        evidence.append(reading)
        assessment = evaluate_wlan_removal(plan, evidence, evidence_as_of=evidence_as_of)
        if root.id is None:
            msg = "Persisted investigation has no identity"
            raise ValueError(msg)
        artifact = InvestigationRevision(
            organization_id=root.organization_id,
            investigation_id=root.id,
            revision=root.revision + 1,
            generated_at=utc_now(),
            plan=plan,
            assessment=assessment,
            evidence=evidence,
            deployment=await collect_deployment(root, as_of=now),
        )
        await artifact.insert()
        finished = now >= root.expires_at or any(item.state == "budget_exhausted" for item in evidence)
        if finished:
            status = "completed" if assessment.coverage == "complete" else "incomplete"
            next_poll = None
        else:
            status = "monitoring"
            elapsed = max(0, int((now - root.changed_at) / _INTERVAL))
            next_poll = min(root.changed_at + (elapsed + 1) * _INTERVAL, root.expires_at)
        # An obsolete worker may retain its immutable artifact, but never publish
        # it over a newer generation, and it cannot dispatch after losing its lease.
        await ImpactInvestigation.get_pymongo_collection().update_one(
            {**self._fence(root, utc_now()), "revision": root.revision},
            {
                "$set": {
                    "report_id": artifact.id,
                    "revision": root.revision + 1,
                    "status": status,
                    "next_poll_at": next_poll,
                    "lease_until": None,
                    "updated_at": utc_now(),
                }
            },
        )

    async def _reserve(self, root: ImpactInvestigation, credential: str, dispatch: DispatchRecord) -> bool:
        fresh = await Organization.get(root.organization_id)
        now = utc_now()
        if (
            fresh is None
            or fresh.status is not OrganizationStatus.VERIFIED
            or fresh.encrypted_service_token != credential
            or now > root.expires_at + timedelta(minutes=2)
        ):
            return False
        record = dispatch.model_copy(update={"reserved_at": now})
        # Budget and journal reservation share one atomic root write. If it fails
        # or its result is uncertain, capture does not issue the HTTP request.
        result = await ImpactInvestigation.get_pymongo_collection().update_one(
            {
                **self._fence(root, now),
                "calls_used": {"$lt": root.calls_limit},
                f"dispatches.{MAX_DISPATCHES - 1}": {"$exists": False},
            },
            {"$inc": {"calls_used": 1}, "$push": {"dispatches": Encoder().encode(record)}},
        )
        return result.matched_count == 1

    @staticmethod
    async def _finish_dispatch(root: ImpactInvestigation, dispatch: DispatchRecord, reading: SessionEvidence) -> None:
        # An old worker may finish only its own reserved record. This factual log
        # update cannot publish evidence or alter the current worker's lease.
        if (reading.check_id, reading.target_handle, reading.window) != (
            dispatch.check_id,
            dispatch.target_handle,
            dispatch.window,
        ):
            msg = "Dispatch result identity does not match its reservation."
            raise ValueError(msg)
        completed = DispatchRecord.model_validate(
            {
                **dispatch.model_dump(),
                "state": reading.state,
                "finished_at": utc_now(),
                "http_status": reading.http_status,
                "response_bytes": reading.response_bytes,
                "row_count": len(reading.rows),
            }
        )
        fields = completed.model_dump(include={"state", "finished_at", "http_status", "response_bytes", "row_count"})
        result = await ImpactInvestigation.get_pymongo_collection().update_one(
            Encoder().encode(
                {
                    "_id": root.id,
                    "organization_id": root.organization_id,
                    "dispatches": {
                        "$elemMatch": {"id": dispatch.id, "generation": dispatch.generation, "state": "reserved"}
                    },
                }
            ),
            {"$set": {f"dispatches.$.{key}": value for key, value in fields.items()}},
        )
        if result.matched_count != 1:
            msg = "Dispatch result could not be recorded; checkpoint publication stopped."
            raise RuntimeError(msg)
