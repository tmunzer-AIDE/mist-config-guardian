"""Historical v8 artifact generator for compatibility tests. Not a production engine.

The MCP engine has separate end-to-end tests. These legacy transcripts continue
to exercise old journal and artifact contracts retained for historical reports.
"""

import asyncio
import logging
from datetime import timedelta
from hashlib import sha256
from uuid import UUID

from mist_config_guardian_backend.impact.agent import CheckCapability, capabilities
from mist_config_guardian_backend.impact.contracts import (
    InvestigationEvidence,
    NeighborTarget,
    PortEvidence,
    SessionEvidence,
)
from mist_config_guardian_backend.impact.domain_evaluation import compose_domains
from mist_config_guardian_backend.impact.limits import MAX_PUBLISHED_CHECKPOINTS
from mist_config_guardian_backend.impact.report import build_report
from mist_config_guardian_backend.impact.wlan_removal import evaluate_wlan_removal
from mist_config_guardian_backend.integrations.mist_ap_evidence import MistScopedEvidenceClient
from mist_config_guardian_backend.models.investigation import (
    ImpactInvestigation,
    InvestigationRevision,
)
from mist_config_guardian_backend.models.organization import Organization, OrganizationStatus
from mist_config_guardian_backend.services import impact_investigations as runtime
from mist_config_guardian_backend.services.impact_agent import ImpactAgent
from mist_config_guardian_backend.services.impact_investigations import ImpactInvestigationService

logger = logging.getLogger(__name__)
_LEASE = timedelta(minutes=3)
_INTERVAL = timedelta(minutes=10)
_DURATION = timedelta(hours=1)
_MAX_RETENTION_DAYS = 36_500


class LegacyAgentFixture(ImpactInvestigationService):
    async def _poll(self, root: ImpactInvestigation) -> None:  # noqa: C901, PLR0912, PLR0915 - fenced discovery and fallback
        now = runtime.utc_now()
        # Only a fenced publication advances revision. Lease claims and orphan
        # artifacts are not completed checkpoints and must not consume this cap.
        if root.revision >= MAX_PUBLISHED_CHECKPOINTS:
            await self._stop(root, "Published checkpoint limit reached; evidence is incomplete.")
            return
        previous = await runtime.published_revision(root)
        plan = await self._plan(root)
        organization = await Organization.get(root.organization_id)
        evidence_as_of = min(now, root.expires_at)
        evidence = []
        agent = None
        deployment = await runtime.collect_deployment(root, as_of=now)
        # Delayed audit delivery cannot turn a historical change into a fresh hour.
        expired = now > root.expires_at + timedelta(minutes=2)
        if (
            (plan.targets or (plan.change_context and plan.change_context.changes))
            and organization is not None
            and organization.status is OrganizationStatus.VERIFIED
            and not expired
        ):
            token = await runtime.service_token(organization, self._vault)
            credential = organization.encrypted_service_token
            neighbor_context = None
            if plan.port_targets or any(t.auth_changed for t in plan.targets):
                try:
                    mist_org_id = UUID(str(getattr(organization, "mist_org_id", "")))
                    retention = getattr(organization, "monitoring_retention_days", None)
                    if type(retention) is not int or not 1 <= retention <= _MAX_RETENTION_DAYS:
                        raise ValueError  # noqa: TRY301 - fail closed on invalid organization policy
                    neighbor_context = (mist_org_id, retention)
                    plan = plan.model_copy(update={"port_history": bool(plan.port_targets)})
                except ValueError:
                    plan = plan.model_copy(
                        update={
                            "gaps": (
                                *plan.gaps,
                                "Neighbor verification lacks a validated Mist organization or retention policy.",
                            )
                        }
                    )

            async with (
                asyncio.timeout(120),
                MistScopedEvidenceClient(token=token, region=organization.cloud_region) as client,
            ):
                collected: dict[str, InvestigationEvidence] = {}

                async def collect(check: CheckCapability) -> InvestigationEvidence:
                    if check.ref not in collected:
                        if evidence and evidence[-1].state in {"budget_exhausted", "dispatch_denied"}:
                            msg = "Evidence collection stopped after dispatch denial"
                            raise RuntimeError(msg)
                        reading = await self._collect(
                            root, plan, check, client, credential, neighbor_context=neighbor_context, sources=evidence
                        )
                        collected[check.ref] = reading
                        evidence.append(reading)
                    return collected[check.ref]

                # Discovery prerequisites run once before the model in both modes.
                # Only completed source bindings can extend the shared required menu.
                if neighbor_context is not None:
                    for check in capabilities(plan, evidence_as_of):
                        if check.check_id == "switch-port-snapshot.v1":
                            if evidence and evidence[-1].state == "dispatch_denied":
                                break
                            await collect(check)
                    neighbors = []
                    for reading in evidence:
                        if isinstance(reading, PortEvidence) and reading.candidate_binding is not None:
                            port = next(t for t in plan.port_targets if t.handle == reading.target_handle)
                            binding = reading.candidate_binding
                            handle = sha256(
                                f"neighbor-inventory.v1:{binding.artifact_id}:{binding.content_hash}".encode()
                            ).hexdigest()
                            neighbors.append(
                                NeighborTarget(
                                    handle=handle,
                                    source_port_handle=port.handle,
                                    site_id=port.site_id,
                                    mist_org_id=neighbor_context[0],
                                    binding=binding,
                                )
                            )
                    plan = plan.model_copy(update={"neighbor_targets": tuple(neighbors), "neighbor_statistics": True})
                if runtime.get_settings().impact_engine_mode == "agent_shadow" and not (
                    evidence and evidence[-1].state in {"budget_exhausted", "dispatch_denied"}
                ):
                    agent = await ImpactAgent(self._vault).run(
                        root,
                        plan,
                        evidence_as_of,
                        collect,
                        service_credential=credential,
                        deployment=deployment,
                        previous=previous,
                    )
                # Model failure or omission cannot cancel a rule's required evidence.
                for check in capabilities(plan, evidence_as_of):
                    if evidence and evidence[-1].state in {"budget_exhausted", "dispatch_denied"}:
                        break
                    await collect(check)
        assessment = evaluate_wlan_removal(
            plan, [e for e in evidence if isinstance(e, SessionEvidence)], evidence_as_of=evidence_as_of
        )
        assessment = compose_domains(plan, evidence, assessment)
        if root.id is None:
            msg = "Persisted investigation has no identity"
            raise ValueError(msg)
        artifact = InvestigationRevision(
            organization_id=root.organization_id,
            investigation_id=root.id,
            revision=root.revision + 1,
            generated_at=runtime.utc_now(),
            previous_report_id=root.report_id,
            retained_until=root.retained_until,
            plan=plan,
            assessment=assessment,
            evidence=evidence,
            deployment=deployment,
            agent=agent,
        )
        artifact.report = build_report(
            investigation_id=str(root.id),
            revision=artifact.revision,
            generated_at=artifact.generated_at,
            plan=plan,
            assessment=assessment,
            evidence=evidence,
            previous=previous.report if previous else None,
            history_available=previous is not False and (root.revision == 0 or bool(previous and previous.report)),
        )
        await artifact.insert()
        finished = now >= root.expires_at or any(
            item.state in {"budget_exhausted", "dispatch_denied"} for item in evidence
        )
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
            {**self._fence(root, runtime.utc_now()), "revision": root.revision},
            {
                "$set": {
                    "report_id": artifact.id,
                    "revision": root.revision + 1,
                    "status": status,
                    "next_poll_at": next_poll,
                    "lease_until": None,
                    "updated_at": runtime.utc_now(),
                }
            },
        )
