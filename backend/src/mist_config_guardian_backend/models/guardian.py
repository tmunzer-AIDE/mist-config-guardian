"""Guardian persistence: one small root per audit and one bounded document per attempt.

Lifecycle writes go through ``guardian.repository``; these models validate what those writes produce. A run is
immutable once terminal, and whether it is published is derived from the root's pointers, never stored on the run.
"""

from collections.abc import Mapping
from typing import Any, ClassVar

import bson
from beanie import Document, PydanticObjectId
from beanie.odm.utils.encoder import Encoder
from pydantic import AwareDatetime, BaseModel, Field, JsonValue, model_validator
from pymongo import IndexModel

from mist_config_guardian_backend.guardian.contracts import (
    FAILED_RUN_STATES,
    MAX_ATTEMPTS_PER_KIND,
    MAX_ROOT_IMPACTED_DEVICES,
    RUN_DOCUMENT_MAX_BYTES,
    TERMINAL_RUN_STATES,
    AgentConclusion,
    Band,
    ChangeAtom,
    CompactImpactedDevice,
    Conclusion,
    Confidence,
    Contract,
    Coverage,
    Evidence,
    LedgerRow,
    ObligationOutcome,
    PluginId,
    Recovery,
    RootStatus,
    RunAnchor,
    RunBudget,
    RunKind,
    RunState,
    SafeReason,
    StatusReason,
    Summary,
    Verdict,
    VerdictSource,
    validate_published_verdict,
)
from mist_config_guardian_backend.models.base import TimestampedModel

_RETAINED = {"retained_until": {"$exists": True}}


class GuardianClaim(Contract):
    """A lease on the root. ``attempt`` and ``started_at`` stay null until the attempt is committed."""

    token: PydanticObjectId
    kind: RunKind
    lease_until: AwareDatetime
    attempt: int | None = Field(default=None, ge=1, le=MAX_ATTEMPTS_PER_KIND)
    started_at: AwareDatetime | None = None
    # The +120 min branch, evaluated on server time when the lease was taken.
    final_forced: bool = False

    @property
    def committed(self) -> bool:
        return self.attempt is not None

    @model_validator(mode="after")
    def committed_together(self) -> "GuardianClaim":
        if (self.attempt is None) != (self.started_at is None):
            msg = "A claim's attempt and started_at are recorded together at commit"
            raise ValueError(msg)
        if self.kind == "early" and self.final_forced:
            msg = "Only a final claim can be forced"
            raise ValueError(msg)
        return self


class AttemptCounts(Contract):
    early: int = Field(default=0, ge=0, le=MAX_ATTEMPTS_PER_KIND)
    final: int = Field(default=0, ge=0, le=MAX_ATTEMPTS_PER_KIND)

    def of(self, kind: RunKind) -> int:
        return self.early if kind == "early" else self.final


class GuardianResult(Contract):
    """The root's published summary of one succeeded run, with at most 20 compact devices."""

    run_id: PydanticObjectId
    run_kind: RunKind
    evaluated_at: AwareDatetime
    peak: Band
    current: Band
    recovery: Recovery
    confidence: Confidence
    coverage: Coverage
    sources: tuple[VerdictSource, ...] = ()
    impacted_devices: tuple[CompactImpactedDevice, ...] = Field(default=(), max_length=MAX_ROOT_IMPACTED_DEVICES)
    impacted_device_count: int = Field(default=0, ge=0)
    summary: Summary

    @model_validator(mode="after")
    def consistent(self) -> "GuardianResult":
        validate_published_verdict(self.peak, self.current, self.recovery, self.coverage)
        if self.impacted_device_count < len(self.impacted_devices):
            msg = "impacted_device_count counts at least the listed devices"
            raise ValueError(msg)
        return self

    @classmethod
    def from_verdict(
        cls, *, run_id: PydanticObjectId, run_kind: RunKind, evaluated_at: AwareDatetime, verdict: Verdict
    ) -> "GuardianResult":
        return cls(
            run_id=run_id,
            run_kind=run_kind,
            evaluated_at=evaluated_at,
            peak=verdict.peak,
            current=verdict.current,
            recovery=verdict.recovery,
            confidence=verdict.confidence,
            coverage=verdict.coverage,
            sources=verdict.sources,
            impacted_devices=verdict.impacted_devices[:MAX_ROOT_IMPACTED_DEVICES],
            impacted_device_count=len(verdict.impacted_devices) + verdict.impacted_devices_omitted,
            summary=verdict.summary,
        )


class GuardianInvestigation(TimestampedModel, Document):
    """The small root: identity, trigger timing, the claim, attempt counters and published pointers."""

    organization_id: PydanticObjectId
    audit_id: str
    changed_at: AwareDatetime
    anchor_known: bool
    status: RootStatus = "waiting"
    status_reason: StatusReason | None = None
    next_check_at: AwareDatetime | None = None
    claim: GuardianClaim | None = None
    attempts: AttemptCounts = Field(default_factory=AttemptCounts)
    early_run_id: PydanticObjectId | None = None
    final_run_id: PydanticObjectId | None = None
    result: GuardianResult | None = None
    retained_until: AwareDatetime | None = None

    class Settings:
        name = "guardian_investigations"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel([("organization_id", 1), ("audit_id", 1)], unique=True, name="guardian_investigation_identity"),
            IndexModel([("status", 1), ("next_check_at", 1)], name="guardian_investigation_due"),
            IndexModel(
                [("retained_until", 1)],
                expireAfterSeconds=0,
                partialFilterExpression=_RETAINED,
                name="guardian_investigation_retention",
            ),
        ]

    @model_validator(mode="after")
    def consistent_lifecycle(self) -> "GuardianInvestigation":
        if self.status == "done":
            if self.status_reason is None:
                msg = "A done investigation always has a status reason"
                raise ValueError(msg)
            if self.next_check_at is not None:
                msg = "A done investigation has no next check"
                raise ValueError(msg)
            if self.claim is not None:
                msg = "A done investigation holds no claim"
                raise ValueError(msg)
        elif self.next_check_at is None:
            msg = "A waiting investigation has a next check time"
            raise ValueError(msg)
        if self.claim is not None and self.claim.committed and self.claim.attempt != self.attempts.of(self.claim.kind):
            msg = "A committed claim's attempt is the count of attempts its kind has consumed"
            raise ValueError(msg)
        if self.final_run_id is not None and self.status != "done":
            msg = "A published final run leaves the investigation done"
            raise ValueError(msg)
        pointer = self.final_run_id or self.early_run_id
        expected = None if pointer is None else (pointer, "final" if self.final_run_id else "early")
        published = None if self.result is None else (self.result.run_id, self.result.run_kind)
        if published != expected:
            msg = "The published result describes the latest run the root points at, and exists only with one"
            raise ValueError(msg)
        return self

    def published_run_id(self, kind: RunKind) -> PydanticObjectId | None:
        return self.early_run_id if kind == "early" else self.final_run_id

    def publishes(self, run: "GuardianRun") -> bool:
        """A run is published if and only if this root points at it."""
        return (
            run.id is not None
            and run.organization_id == self.organization_id
            and run.investigation_id == self.id
            and self.published_run_id(run.kind) == run.id
        )


class GuardianRun(TimestampedModel, Document):
    """One attempt. Its ``_id`` is the claim token; full evidence lives here, never on the root."""

    organization_id: PydanticObjectId
    investigation_id: PydanticObjectId
    audit_id: str
    kind: RunKind
    attempt: int = Field(ge=1, le=MAX_ATTEMPTS_PER_KIND)
    state: RunState
    started_at: AwareDatetime
    finished_at: AwareDatetime | None = None
    deadline_at: AwareDatetime | None = None
    failure_reason: SafeReason | None = None
    anchor: RunAnchor | None = None
    as_of: AwareDatetime | None = None
    change: tuple[ChangeAtom, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    ledger: tuple[LedgerRow, ...] = ()
    obligations: tuple[ObligationOutcome, ...] = ()
    monitoring: Conclusion | None = None
    deployment: Conclusion | None = None
    rules: dict[PluginId, Conclusion] = Field(default_factory=dict)
    agent: AgentConclusion | None = None
    verdict: Verdict | None = None
    steps: tuple[dict[str, JsonValue], ...] = ()
    budget: RunBudget = Field(default_factory=RunBudget)
    retained_until: AwareDatetime | None = None

    class Settings:
        name = "guardian_runs"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel(
                [("organization_id", 1), ("investigation_id", 1), ("kind", 1), ("attempt", 1)],
                name="guardian_run_lookup",
            ),
            IndexModel(
                [("retained_until", 1)],
                expireAfterSeconds=0,
                partialFilterExpression=_RETAINED,
                name="guardian_run_retention",
            ),
        ]

    @model_validator(mode="after")
    def consistent_state(self) -> "GuardianRun":
        if self.id is None:
            msg = "A Guardian run is identified by its claim token"
            raise ValueError(msg)
        if (self.state in TERMINAL_RUN_STATES) != (self.finished_at is not None):
            msg = "A terminal run has finished_at, and a running run does not"
            raise ValueError(msg)
        if (self.state in FAILED_RUN_STATES) != (self.failure_reason is not None):
            msg = "A failed or abandoned run has a failure reason, and no other run does"
            raise ValueError(msg)
        if self.state == "succeeded" and self.verdict is None:
            msg = "A succeeded run has a verdict"
            raise ValueError(msg)
        numbers = [int(item.id[1:]) for item in self.evidence]
        if numbers != sorted(set(numbers)):
            msg = "Run evidence is stored in E-id order without duplicates"
            raise ValueError(msg)
        return self


class RunDocumentTooLargeError(ValueError):
    """A run exceeded its asserted bound. Budgets make this unreachable except through a bug."""


def bson_size(document: BaseModel | Mapping[str, Any]) -> int:
    """Serialized BSON bytes of a model or mapping, with fields stored under their aliases as Beanie writes them.

    Models are flattened here rather than through Beanie's document encoder, which needs an initialized collection,
    so pure construction tests can measure runs without MongoDB.
    """
    if isinstance(document, BaseModel):
        fields = type(document).model_fields
        document = {(fields[name].alias or name): value for name, value in document if not fields[name].exclude}
    return len(bson.encode(Encoder(to_db=True).encode(document)))


def check_run_document_size(run: GuardianRun, *, limit: int = RUN_DOCUMENT_MAX_BYTES) -> int:
    """Return the run's serialized size, or raise when it exceeds the run-document bound."""
    size = bson_size(run)
    if size > limit:
        msg = f"Guardian run {run.id} serializes to {size} bytes, above the {limit}-byte bound"
        raise RunDocumentTooLargeError(msg)
    return size
