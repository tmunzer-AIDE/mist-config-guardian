"""API projections of Guardian roots and runs. They carry status and published results, never evidence."""

from pydantic import BaseModel

from mist_config_guardian_backend.guardian.contracts import RootStatus, RunBudget, RunKind, RunState
from mist_config_guardian_backend.models.guardian import GuardianInvestigation, GuardianResult, GuardianRun


class GuardianSummary(BaseModel):
    """An audit's Guardian status as change groups, the overview and site impact show it."""

    status: RootStatus
    status_reason: str | None
    result: GuardianResult | None

    @classmethod
    def from_root(cls, root: GuardianInvestigation) -> "GuardianSummary":
        return cls(status=root.status, status_reason=root.status_reason, result=root.result)


class GuardianAttemptSummary(BaseModel):
    """One attempt, collapsed. The full run is loaded separately."""

    id: str
    kind: RunKind
    attempt: int
    state: RunState
    failure_reason: str | None
    budget: RunBudget

    @classmethod
    def from_run(cls, run: GuardianRun) -> "GuardianAttemptSummary":
        return cls(
            id=str(run.id),
            kind=run.kind,
            attempt=run.attempt,
            state=run.state,
            failure_reason=run.failure_reason,
            budget=run.budget,
        )
