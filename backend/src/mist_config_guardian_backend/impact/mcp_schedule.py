"""When the MCP agent runs inside an audit hour, and which agent conclusion a checkpoint carries."""

from datetime import datetime, timedelta
from uuid import UUID

from mist_config_guardian_backend.impact.mcp_contracts import McpCarriedConclusion, McpCheckpoint, McpConclusion

# Post-change data exists by +10 min; +30 and the +60 expiry recheck. At most three agent runs per audit.
AGENT_RUN_THRESHOLDS = (timedelta(minutes=10), timedelta(minutes=30), timedelta(hours=1))


def agent_band(changed_at: datetime, as_of: datetime) -> int:
    return sum(as_of - changed_at >= threshold for threshold in AGENT_RUN_THRESHOLDS)


def agent_due(changed_at: datetime, as_of: datetime, last_run_as_of: datetime | None) -> bool:
    band = agent_band(changed_at, as_of)
    return band > 0 and (last_run_as_of is None or band > agent_band(changed_at, last_run_as_of))


def last_agent_run(checkpoint: McpCheckpoint | None, evaluated_at: datetime) -> datetime | None:
    if checkpoint is None:
        return None
    if checkpoint.agent_as_of is not None:
        return checkpoint.agent_as_of
    # Revisions written before scheduling existed always ran the agent at their evaluation time.
    return None if checkpoint.state == "not_scheduled" else evaluated_at


def cited_ids(conclusion: McpConclusion) -> frozenset[UUID]:
    return frozenset(
        (
            *conclusion.evidence,
            *(r for f in conclusion.findings for r in f.evidence),
            *(r for d in conclusion.impacted_devices for r in d.evidence),
            *(v.evidence_id for v in conclusion.views),
        )
    )


def prior_conclusion(checkpoint: McpCheckpoint | None, revision: int) -> McpCarriedConclusion | None:
    if checkpoint is None:
        return None
    if checkpoint.state == "complete" and checkpoint.conclusion is not None:
        cited = cited_ids(checkpoint.conclusion)
        pool = (
            *([checkpoint.deterministic_evidence] if checkpoint.deterministic_evidence else []),
            *checkpoint.evidence,
        )
        evidence = tuple(e for e in pool if e.id in cited)
        # A carried conclusion may only cite rows carried with it; never point at evidence that is gone.
        if not cited <= {e.id for e in evidence}:
            return None
        return McpCarriedConclusion(source_revision=revision, conclusion=checkpoint.conclusion, evidence=evidence)
    return checkpoint.carried
