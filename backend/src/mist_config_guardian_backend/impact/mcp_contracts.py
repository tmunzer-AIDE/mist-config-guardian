"""Generic MCP investigation contracts, independent of deterministic rule coverage."""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, JsonValue, model_validator

from mist_config_guardian_backend.impact.contracts import Contract

McpToolName = Literal[
    "find_mist_entity",
    "get_mist_config",
    "get_mist_constants",
    "get_mist_insights",
    "get_mist_stats",
    "search_mist_data",
]
McpCheckpointState = Literal[
    "complete",
    "unavailable",
    "budget_exhausted",
    "invalid_response",
    "provider_error",
    "dispatch_denied",
    "deadline_exceeded",
    "not_scheduled",
]
Text = Annotated[str, Field(min_length=1, max_length=500)]
Band = Literal["none", "info", "warning", "critical"]
MAX_MCP_CHECKPOINT_CALLS = 8
MAX_MCP_EVIDENCE_BYTES = 12_000
MAX_MCP_ERROR_DETAIL_BYTES = 500
MAX_MCP_BATCH_CALLS = 3


class McpTool(Contract):
    name: McpToolName
    description: str = Field(max_length=16_000)
    input_schema: dict[str, JsonValue]
    schema_hash: str


class McpDispatch(Contract):
    id: UUID
    generation: int
    candidate_revision: int
    tool: str = Field(max_length=80)
    arguments_hash: str
    input_artifact_id: str | None = None
    reserved_at: datetime
    finished_at: datetime | None = None
    state: Literal["reserved", "complete", "partial", "error"] = "reserved"
    artifact_id: str | None = None
    content_hash: str | None = None
    error: Literal["transport", "invalid_response", "tool_error", "response_limit"] | None = None


class McpEvidence(Contract):
    id: UUID
    tool: str = Field(max_length=80)
    arguments: dict[str, JsonValue]
    data: JsonValue
    state: Literal["complete", "partial", "error"]
    captured_at: datetime
    schema_hash: str
    error: Literal["transport", "invalid_response", "tool_error", "response_limit"] | None = None
    # Redacted, byte-bounded tool error text. Untrusted data: shown to the model, never citable.
    error_detail: str | None = Field(default=None, max_length=MAX_MCP_ERROR_DETAIL_BYTES)


class McpFinding(Contract):
    statement: Text
    evidence: tuple[UUID, ...] = Field(min_length=1, max_length=8)
    limitations: tuple[Text, ...] = Field(default=(), max_length=8)


class McpDeviceImpact(Contract):
    device_mac: str = Field(pattern=r"^[0-9a-f]{12}$")
    site_id: UUID
    service: Text
    impact: Band
    evidence: tuple[UUID, ...] = Field(min_length=1, max_length=8)
    explanation: Text


class McpView(Contract):
    evidence_id: UUID
    kind: Literal["table", "bar", "histogram", "timeline"]
    rows_path: tuple[Annotated[str, Field(max_length=80)], ...] = Field(default=(), max_length=8)
    label_key: Annotated[str, Field(max_length=80)]
    value_key: Annotated[str, Field(max_length=80)]


class McpConclusion(Contract):
    summary: Text
    scope: Text
    views: tuple[McpView, ...] = Field(default=(), max_length=4)
    impact: Band
    confidence: Literal["low", "medium"]
    coverage: Literal["complete", "partial"]
    findings: tuple[McpFinding, ...] = Field(default=(), max_length=8)
    impacted_devices: tuple[McpDeviceImpact, ...] = Field(default=(), max_length=50)
    evidence: tuple[UUID, ...] = Field(default=(), max_length=16)
    gaps: tuple[Text, ...] = Field(default=(), max_length=12)

    @model_validator(mode="after")
    def substantiated(self) -> "McpConclusion":
        if self.impact != "info" and not self.evidence:
            msg = "A conclusive assessment requires evidence citations"
            raise ValueError(msg)
        if self.impact == "none" and self.coverage != "complete":
            msg = "No observed impact requires complete evidence for the investigated scope"
            raise ValueError(msg)
        order = {"none": 0, "info": 1, "warning": 2, "critical": 3}
        if any(order[d.impact] > order[self.impact] for d in self.impacted_devices):
            msg = "Overall impact cannot be lower than a listed device impact"
            raise ValueError(msg)
        return self


class McpToolCall(Contract):
    tool: McpToolName
    arguments: dict[str, JsonValue]
    purpose: Text


class McpToolAction(Contract):
    """Single-call form (historical) or up to three independent calls in one model turn."""

    action: Literal["tool"]
    tool: McpToolName | None = None
    arguments: dict[str, JsonValue] | None = None
    purpose: Text | None = None
    calls: tuple[McpToolCall, ...] = Field(default=(), max_length=MAX_MCP_BATCH_CALLS)

    @model_validator(mode="after")
    def one_form(self) -> "McpToolAction":
        single = (self.tool, self.arguments, self.purpose)
        if self.calls and any(value is not None for value in single):
            msg = "Use either tool/arguments/purpose or calls, not both"
            raise ValueError(msg)
        if not self.calls and any(value is None for value in single):
            msg = "A tool action requires tool, arguments and purpose, or a calls list"
            raise ValueError(msg)
        return self

    def requested_calls(self) -> tuple[McpToolCall, ...]:
        if self.calls:
            return self.calls
        return (McpToolCall.model_validate({"tool": self.tool, "arguments": self.arguments, "purpose": self.purpose}),)


class McpDescribeAction(Contract):
    action: Literal["describe"]
    tools: tuple[McpToolName, ...] = Field(min_length=1, max_length=1)


class McpReportAction(Contract):
    action: Literal["report"]
    report: McpConclusion


McpAction = Annotated[McpToolAction | McpDescribeAction | McpReportAction, Field(discriminator="action")]


class McpDiagnostics(Contract):
    """Counters only: no prompt, tool or provider text beyond bounded finish-reason tokens."""

    final_state: str = Field(max_length=40)
    turns: int = Field(default=0, ge=0)
    describes: int = Field(default=0, ge=0)
    tool_calls: int = Field(default=0, ge=0)
    cached_calls: int = Field(default=0, ge=0)
    rejected_actions: dict[str, int] = Field(default_factory=dict)
    results_digested: int = Field(default=0, ge=0)
    results_omitted: int = Field(default=0, ge=0)
    observations_hidden_in_prompt: int = Field(default=0, ge=0)
    prompt_trim_steps: int = Field(default=0, ge=0)
    max_prompt_bytes: int = Field(default=0, ge=0)
    finish_reasons: tuple[Annotated[str, Field(max_length=32)], ...] = Field(default=(), max_length=8)
    elapsed_ms: int = Field(default=0, ge=0)


class McpCarriedConclusion(Contract):
    """The last validated agent conclusion plus exactly the evidence it cites, from an earlier revision."""

    source_revision: int = Field(ge=1)
    conclusion: McpConclusion
    evidence: tuple[McpEvidence, ...] = Field(default=(), max_length=MAX_MCP_CHECKPOINT_CALLS + 1)


class McpCheckpoint(Contract):
    source: Literal["mcp_agent"] = "mcp_agent"
    state: McpCheckpointState
    reason: str = Field(default="", max_length=500)
    conclusion: McpConclusion | None = None
    evidence: tuple[McpEvidence, ...] = Field(default=(), max_length=MAX_MCP_CHECKPOINT_CALLS)
    request_ids: tuple[UUID, ...] = Field(default=(), max_length=8)
    catalogue_hash: str | None = None
    deterministic_evidence: McpEvidence | None = None
    carried: McpCarriedConclusion | None = None
    agent_as_of: datetime | None = None
    diagnostics: McpDiagnostics | None = None
