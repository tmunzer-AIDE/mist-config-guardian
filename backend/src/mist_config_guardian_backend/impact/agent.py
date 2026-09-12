"""Versioned investigator actions, bounded memory and model request metadata."""

from datetime import datetime
from enum import StrEnum
from hashlib import sha256
from typing import Annotated, Literal
from uuid import UUID

from beanie import PydanticObjectId
from pydantic import AwareDatetime, Field, TypeAdapter

from mist_config_guardian_backend.impact.contracts import (
    Contract,
    InvestigationEvidence,
    ManagedNeighbor,
    NeighborEvidence,
    PortEvidence,
    PortResponseError,
    PortRow,
    Window,
    WlanRemovalPlan,
)
from mist_config_guardian_backend.impact.limits import MAX_CHECKPOINT_EVIDENCE
from mist_config_guardian_backend.impact.wlan_removal import check_windows

MAX_MODEL_CALLS = 21
MAX_CHECKPOINT_CALLS = 3
MAX_INPUT_BYTES = 24_000
MAX_OUTPUT_TOKENS = 1500
MAX_OUTPUT_BYTES = 16_000
MAX_INPUT_BYTES_TOTAL = MAX_MODEL_CALLS * MAX_INPUT_BYTES
PROMPT_VERSION = "impact-investigator.v4"

Handle = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
ShortText = Annotated[str, Field(min_length=1, max_length=500)]


class CheckCapability(Contract):
    ref: Handle
    check_id: Literal["wlan-client-sessions.v1", "switch-port-snapshot.v1", "neighbor-ap-inventory.v1"] = (
        "wlan-client-sessions.v1"
    )
    target_handle: Handle
    phase: Literal["baseline", "followup", "snapshot"]
    window: Window


def capabilities(plan: WlanRemovalPlan, as_of: datetime) -> tuple[CheckCapability, ...]:
    return (
        tuple(
            CheckCapability(
                ref=sha256(f"{target.handle}:{window.model_dump_json()}".encode()).hexdigest(),
                target_handle=target.handle,
                phase=phase,
                window=window,
            )
            for target in plan.targets
            for phase, window in zip(("baseline", "followup"), check_windows(plan, as_of), strict=True)
        )
        + tuple(
            CheckCapability(
                ref=sha256(f"{target.handle}:snapshot:{as_of.isoformat()}".encode()).hexdigest(),
                check_id="switch-port-snapshot.v1",
                target_handle=target.handle,
                phase="snapshot",
                window=Window(start=plan.changed_at, end=as_of),
            )
            for target in plan.port_targets
        )
        + tuple(
            CheckCapability(
                ref=sha256(f"{target.handle}:inventory:{as_of.isoformat()}".encode()).hexdigest(),
                check_id="neighbor-ap-inventory.v1",
                target_handle=target.handle,
                phase="snapshot",
                window=Window(start=plan.changed_at, end=as_of),
            )
            for target in plan.neighbor_targets
        )
    )


class EvidenceView(Contract):
    ref: Handle
    target_handle: Handle
    window: Window
    state: str
    captured_at: AwareDatetime | None = None  # Historical views did not retain collection time.
    # Counts describe the returned sample; partial results cannot prove absence.
    sampled_clients: int | None = Field(default=None, ge=0)
    observed_disconnects: int | None = Field(default=None, ge=0)
    port: PortRow | None = None
    managed_neighbor: ManagedNeighbor | None = None
    response_error: PortResponseError | None = None
    gap: str = Field(max_length=500)


def evidence_view(check: CheckCapability, reading: InvestigationEvidence, changed_at: datetime) -> EvidenceView:
    if (reading.check_id, reading.target_handle, reading.window) != (check.check_id, check.target_handle, check.window):
        msg = "Evidence does not match the authorized check"
        raise ValueError(msg)
    if isinstance(reading, NeighborEvidence):
        return EvidenceView(
            ref=check.ref,
            target_handle=check.target_handle,
            window=check.window,
            state=reading.state,
            captured_at=reading.captured_at,
            managed_neighbor=reading.rows[0] if reading.rows else None,
            gap=reading.reason,
        )
    if isinstance(reading, PortEvidence):
        return EvidenceView(
            ref=check.ref,
            target_handle=check.target_handle,
            window=check.window,
            state=reading.state,
            captured_at=reading.captured_at,
            port=reading.rows[0] if reading.rows else None,
            response_error=reading.response_error,
            gap=reading.reason,
        )
    return EvidenceView(
        ref=check.ref,
        target_handle=check.target_handle,
        window=check.window,
        state=reading.state,
        captured_at=reading.captured_at,
        sampled_clients=len({row.client_mac for row in reading.rows}),
        observed_disconnects=len(
            {
                row.client_mac
                for row in reading.rows
                if row.connected_at < changed_at
                and row.disconnected_at is not None
                and changed_at <= row.disconnected_at <= reading.window.end
            }
        ),
        gap=reading.reason[:500],
    )


class Hypothesis(Contract):
    target_handle: Handle
    statement: ShortText
    supporting_checks: tuple[Handle, ...] = Field(default=(), max_length=8)
    counterevidence_checks: tuple[Handle, ...] = Field(default=(), max_length=8)
    limitations: tuple[ShortText, ...] = Field(default=(), max_length=4)


class AgentProposal(Contract):
    # No model-written ratings, device-failure identities or arbitrary chart data.
    summary: ShortText
    hypotheses: tuple[Hypothesis, ...] = Field(default=(), max_length=4)
    open_questions: tuple[ShortText, ...] = Field(default=(), max_length=4)


class CollectAction(Contract):
    action: Literal["collect"]
    checks: tuple[Handle, ...] = Field(min_length=1, max_length=8)


class ReportAction(Contract):
    action: Literal["report"]
    report: AgentProposal


AgentAction = Annotated[CollectAction | ReportAction, Field(discriminator="action")]
ACTION_ADAPTER = TypeAdapter(AgentAction)


class AgentMemory(Contract):
    source_revision: int = Field(ge=1)
    proposal: AgentProposal


class ModelDispatchDenial(StrEnum):
    PROVIDER_CHANGED = "provider_changed"
    ORGANIZATION_UNAVAILABLE = "organization_unavailable"
    CREDENTIAL_CHANGED = "credential_changed"
    WINDOW_EXPIRED = "window_expired"
    RESERVATION_REJECTED = "reservation_rejected"

    @property
    def explanation(self) -> str:
        return {
            self.PROVIDER_CHANGED: "AI provider configuration changed or was disabled; model dispatch stopped.",
            self.ORGANIZATION_UNAVAILABLE: "Organization access is unavailable or no longer verified.",
            self.CREDENTIAL_CHANGED: "The service credential changed; review organization access.",
            self.WINDOW_EXPIRED: "The investigation collection window expired.",
            self.RESERVATION_REJECTED: "Model reservation rejected by the lease or budget guard; no request was sent.",
        }[self]


class AgentCheckpoint(Contract):
    prompt_version: Literal[
        "impact-investigator.v1", "impact-investigator.v2", "impact-investigator.v3", "impact-investigator.v4"
    ] = PROMPT_VERSION
    source: Literal["model_proposal"] = "model_proposal"
    state: Literal[
        "complete",
        "unavailable",
        "invalid_response",
        "budget_exhausted",
        "context_unavailable",
        "provider_error",
        "dispatch_denied",
    ]
    dispatch_denial: ModelDispatchDenial | None = None
    reason: str = Field(default="", max_length=500)
    proposal: AgentProposal | None = None
    memory: AgentMemory | None = None
    observations: tuple[EvidenceView, ...] = Field(default=(), max_length=MAX_CHECKPOINT_EVIDENCE)
    # These local identities refer to durable model reservations, not model prose.
    request_ids: tuple[UUID, ...] = Field(default=(), max_length=MAX_CHECKPOINT_CALLS)


class ModelRequestRecord(Contract):
    id: UUID
    generation: int = Field(ge=1)
    candidate_revision: int = Field(ge=1)
    reserved_at: AwareDatetime
    prompt_version: Literal[
        "impact-investigator.v1", "impact-investigator.v2", "impact-investigator.v3", "impact-investigator.v4"
    ] = PROMPT_VERSION
    input_hash: Handle
    model: str = Field(max_length=255)
    input_bytes: int = Field(ge=1, le=MAX_INPUT_BYTES)
    output_token_limit: int = Field(ge=1, le=MAX_OUTPUT_TOKENS)
    input_artifact_id: PydanticObjectId | None = None
    input_context_hash: Handle | None = None
    state: Literal["reserved", "complete", "invalid_response", "provider_error"] = "reserved"
    finished_at: AwareDatetime | None = None
    request_tokens: int | None = Field(default=None, ge=0)
    response_tokens: int | None = Field(default=None, ge=0)
    action_artifact_id: PydanticObjectId | None = None
    action_hash: Handle | None = None


class ModelActivity(Contract):
    source: Literal["live_investigation_root"] = "live_investigation_root"
    calls_used: int = Field(ge=0)
    calls_limit: int = MAX_MODEL_CALLS
    input_bytes_reserved: int = Field(ge=0)
    input_bytes_limit: int = MAX_INPUT_BYTES_TOTAL
    records: tuple[ModelRequestRecord, ...] = Field(default=(), max_length=MAX_MODEL_CALLS)
