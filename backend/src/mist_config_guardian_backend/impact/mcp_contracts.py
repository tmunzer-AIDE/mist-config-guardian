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
Text = Annotated[str, Field(min_length=1, max_length=500)]
Band = Literal["none", "info", "warning", "critical"]
MAX_MCP_CHECKPOINT_CALLS = 8
MAX_MCP_EVIDENCE_BYTES = 12_000


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


class McpToolAction(Contract):
    action: Literal["tool"]
    tool: McpToolName
    arguments: dict[str, JsonValue]
    purpose: Text


class McpDescribeAction(Contract):
    action: Literal["describe"]
    tools: tuple[McpToolName, ...] = Field(min_length=1, max_length=1)


class McpReportAction(Contract):
    action: Literal["report"]
    report: McpConclusion


McpAction = Annotated[McpToolAction | McpDescribeAction | McpReportAction, Field(discriminator="action")]


class McpCheckpoint(Contract):
    source: Literal["mcp_agent"] = "mcp_agent"
    state: Literal[
        "complete", "unavailable", "budget_exhausted", "invalid_response", "provider_error", "dispatch_denied"
    ]
    reason: str = Field(default="", max_length=500)
    conclusion: McpConclusion | None = None
    evidence: tuple[McpEvidence, ...] = Field(default=(), max_length=MAX_MCP_CHECKPOINT_CALLS)
    request_ids: tuple[UUID, ...] = Field(default=(), max_length=8)
    catalogue_hash: str | None = None
    deterministic_evidence: McpEvidence | None = None
