# MCP-led impact investigations

This design supersedes the fixed deterministic capability-menu and spend-neutrality
requirements in earlier impact design documents. Deterministic coverage is optional.

- One audit owns the investigation, even when many devices are configured. Every
  meaningful change may start the agent. Recorded configuration diffs, scope,
  deployment events and previous published evidence are context. Known metadata-only
  fields are excluded; unfamiliar functional attributes are retained, not renamed.
- The deployed worker connects to the existing Mist MCP over authenticated HTTP,
  using the organization's service token and cloud. No restore-administrator token,
  desktop credential copying, duplicate Mist API client or change-specific tool pack.
- Discover the existing read-only tools and their schemas. The agent selects calls
  and follow-up discovery. Guardian constrains organization/site authority, pagination,
  time range, response size, request budget and execution fences, not the setting.
  Tool prose, object names and configuration text are untrusted evidence.
- Deterministic evaluation runs when applicable and is supplied as cited input.
  MCP calls can go beyond deterministic collection. The agent owns the final shadow
  assessment; server validation checks report shape and citations, not rule agreement.
- Publication remains immutable and fenced. MCP input/output evidence is redacted,
  bounded and journalled; missing/partial responses cannot imply healthy service.
  Reports identify their source, confidence, impacted devices and limitations. The
  existing report schema and topology view are extended instead of creating another UI.
- Agent failure is explicit; deterministic context must not silently masquerade as an
  agent conclusion. Historical fixed-menu results remain readable, but production
  agent mode uses only the MCP-led path. Legacy production badges/notifications stay
  unchanged during shadow evaluation.
- Validation must include previously unmapped STP and DNS/template changes with no
  new impact rules. Those are examples of generality, not new rule implementations.

## Runtime and deployment decisions (2026-09-13)

`agent_shadow` now selects the MCP-led runtime. There is no live fallback to the old
fixed-menu conversation. The old conversation generator remains a test fixture for
historical artifact compatibility; new runtime tests exercise the production service.
`shadow` continues to run deterministic checks only, and `legacy` remains the default.
Production badges and notifications are still legacy during this evaluation phase.

The default endpoint is `https://mcp.ai.juniper.net/mcp/mist`; override it with
`MIST_MCP_URL` or Helm `config.mistMcpUrl`. The worker sends
`Authorization: Bearer <organization service token>` and
`X-Mist-Base-URL: https://<organization's regional API host>`.
The user's gateway header was verified against `global_02`: initialization,
discovery of seven tools, and a bounded statistics call returning one device-data row
all succeeded. No deployment or organization configuration was modified by these probes.

The read catalogue exposes configuration, constants, entity discovery, insights,
statistics and operational search. Account-wide `get_mist_self` is excluded because
Guardian already owns the organization identity. Tool schemas come from MCP, with
nonlocal JSON-schema references rejected. New settings require no new rule; adding a
new category of MCP tool requires an explicit read-boundary update.

The budget remains 56 combined collection reservations and 21 model requests per audit.
In MCP mode, optional deterministic collection is capped at four checks per checkpoint
(28 across the normal seven checkpoints), leaving room for agent-selected reads.
Missing rule checks remain explicit partial evidence; deterministic-only shadow mode
retains its full required-check sweep.
An individual checkpoint permits up to eight model actions, including its final report.
Catalogue discovery reserves one slot covering its bounded initialization/list handshake;
each operational MCP invocation reserves another slot. A MCP server can make multiple
Mist API requests behind one invocation: these bounds are **not** an exact Mist HTTP-call
count. Repeated identical MCP calls within a checkpoint return cached evidence.
Exhaustion is visible and may prevent later checkpoints from reaching a conclusion.
There is no automatic budget increase or second scheduler.

Follow-up checkpoints retain the previous structured conclusion and bounded evidence
summaries, including query arguments and timestamps even when no report was completed.
They can reuse a previously observed tool when its freshly discovered schema hash is
unchanged. Full sanitized evidence remains in immutable revisions and request artifacts;
it is not repeatedly copied into the root record or the entire model conversation.
Configured device lists are grouped by site/type/outcome, preserving MACs without
creating one agent per device. Any further prompt-size omission is explicit.

Optional deterministic results receive an audit/revision-bound evidence ID. They can
support the agent's report without a duplicated operational MCP query. The deterministic
assessment remains separately retained. Unmapped attributes do not force the agent's
assessment to unknown. Provider failure, missing correlation or evidence, invalid
citations and failed authorization remain explicit gaps.

Reports retain the shared section layout, impact/confidence bands and topology device
associations, with `source=mcp_agent`. The agent must state its investigated scope.
Findings cite recorded evidence; impacted-device identities must occur in their cited
operational evidence. Chart proposals select existing JSON rows/fields; the server
builds the tables, bars, observed-value histograms and timelines. The model cannot
supply invented chart values. Snapshot datasets have no historical query window.
These validations establish provenance and shape, **not proof of causal attribution**.
Agent conclusions remain provisional and require human evaluation before promotion.

MCP request inputs are written before an atomic fenced reservation. Results are written
before journal completion. Unknown acknowledgements prevent dispatch/publication;
unfinished records remain `reserved`. Operator request-detail reads verify organization,
audit access, journal pointers, generation, revision, request identity and content hash.
The existing artifact retention policy applies. Logs contain bounded redacted payloads,
never transport headers or service/provider credentials. Model errors retain fixed
validation categories; unsuccessful untrusted provider text is not stored as a finding.

The existing deterministic acceptance replay explicitly rejects MCP-led revisions.
It cannot certify an agent conclusion by recomputing a rule verdict. A separate reviewed
agent acceptance set remains necessary before promoting production consumers.

Additional validation: one synthetic-change call to the configured `gemma4-26b-a4b`
returned a schema-valid `describe` action for `search_mist_data`. This checks the
provider action format; it is not a live causal-attribution acceptance test. Fresh-process
imports also pass after making snapshot-type imports lazy in the pure impact modules.

Validation at implementation completion: backend formatting/lint/type checks pass;
1,319 backend tests pass with 20 existing skips. 409 frontend component tests and the
production build pass. Helm lint and an `agent_shadow` template render pass.
No cluster deployment or production verdict promotion is part of this commit.
