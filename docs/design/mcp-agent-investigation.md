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
  MCP calls can go beyond deterministic collection. The agent owns the shadow
  assessment; server validation checks report shape and citations, not rule agreement.
  The published verdict is never below a rule-derived warning or critical.
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

Deterministic checkpoints run at +1 minute and then every 10 minutes until +60 minutes.
The agent runs only at the first checkpoint at or after +10, +30 and +60 minutes, so an
audit has at most three agent runs (`impact/mcp_schedule.py`). A run that fails, or a
worker that reserved agent requests and then lost its lease, still spends its band.
Checkpoints between runs publish `state=not_scheduled` and spend no model or MCP budget;
they carry the last validated agent conclusion forward together with exactly the evidence
it cites. A later run that stops without a conclusion carries it forward too.
A run permits up to eight model actions including its report, up to three independent
tool calls per action (`calls`) and at most eight evidence rows; calls beyond the free
rows are rejected as `tool_call_limit`. Catalogue discovery reserves one slot covering
its bounded initialization/list handshake; each operational MCP invocation reserves
another. A MCP server can make multiple Mist API requests behind one invocation: these
bounds are **not** an exact Mist HTTP-call count. Repeated identical MCP calls within a
run return cached evidence without a new reservation. Exhaustion is visible and may
prevent later runs from reaching a conclusion. There is no automatic budget increase.

A run stops itself 140 seconds after it starts: no model turn or tool call starts with
less than five seconds left, and every provider and tool call is bounded by the smaller
of 20 seconds and the remaining time. It then publishes `deadline_exceeded` with its
retained evidence. A 170-second worker safety timeout publishes an `unavailable`
checkpoint (that run's evidence is not retained) rather than losing the revision.

MCP prompts are bounded at 96 KB each; new `agent_shadow` audits reserve 21 × 96 KB,
existing audits keep their stored limit, and the retired fixed-menu agent keeps 24 KB.
Every prompt carries compact schemas for all discovered read tools (types, enums,
required fields and defaults, with 300-character descriptions), so describe is optional
and only adds one tool's full schema. Every prompt also carries explicit
`before_window`/`after_window` epoch ranges of equal duration (the before window never
starts earlier than one hour before the change) and pinned playbooks selected from rule
skills and the change type, at most 6 KB. Over budget, context degrades in re-checked
steps and stops as soon as it fits: configured-device MAC lists become counts, rule
evidence keeps its ID and assessment, older observation payloads are hidden oldest-first
(never the newest observation or evidence cited by the previous conclusion; hidden
payloads stay citable), long changed values are shortened with an explicit gap, and as
a last step the payloads of evidence cited by the previous conclusion are hidden
oldest-first, keeping their ID, tool, arguments, state and capture time. Each hide is
re-checked, and only a context that still does not fit stops the run as
`budget_exhausted`. This step counts as a trim step, and its hidden payloads count as
hidden observations in the diagnostics.

MCP results over 12 KB, or with a row list longer than 50 items, are not dropped: every
returned row passes the organization check and is summarized into a citable `partial`
digest. A digest keeps its first rows plus a `<list>_summary` with the row count,
per-value counts, `change_buckets` splitting each categorical value before and after
the change when rows carry timestamps, numeric count/min/max/average and up to 50 device
identities. Only a result that no digest can bound to 12 KB is omitted, and omitted
results are not citable. Output is capped at the smaller of the configured response
limit and 4,096 tokens; a response that stops at the token limit is rejected as
`truncated` before parsing, so no partial report or tool call executes. Rejected actions
return `Action rejected (<category>): <detail>` (or `Call N rejected (…)` within a batch)
with a fixed category and a bounded, redacted detail. Tool errors keep a redacted
500-byte message that the model sees but cannot cite. Checkpoints that `run_mcp` returns
once it reaches the MCP discovery reservation record `McpDiagnostics` counters (turns,
describes, calls, cached calls, rejections by category, digested/omitted results, hidden
observations, trim steps, largest prompt, finish reasons and elapsed time). Checkpoints
returned before that point, and the worker's safety-timeout `unavailable` checkpoint,
carry no diagnostics. The worker logs one structured `mcp_checkpoint` line for each MCP
checkpoint candidate, including `not_scheduled`, before the fenced publication (so a
candidate that loses its fence is logged but not published), without prompt, tool or
provider text.

The published verdict is the more severe of the agent conclusion and a rule-derived
warning or critical; a rule-only info or none never overrides the agent. A rule-raised
verdict publishes partial coverage with a limitation. A carried conclusion counts as the
agent conclusion with a carried-forward limitation. Without any agent conclusion the
deterministic assessment is published with a rule-derived limitation. The final
checkpoint cannot complete the investigation on a carried conclusion or on rules alone,
so such investigations end `incomplete`. Whenever the published coverage is not complete,
a `none` verdict (agent, carried or rule-derived) is published as `info`, and the report's
`current_impact` is clamped the same way, so partial coverage never presents a clean
outcome. `report.verdict_source` records `mcp_agent`, `combined` or `rule`.

Follow-up checkpoints retain the previous structured conclusion and bounded evidence
summaries, including query arguments and timestamps even when no report was completed.
`previous_report` is the last validated conclusion, including one carried through
`not_scheduled` checkpoints. Evidence cited by the previous conclusion, including a cited
rule-evidence row, keeps its payload (each up to 12 KB) in the next prompt newest-first by
capture time (ties in citation order) until 32 KB of such payloads in total. Older
cited rows keep their ID, tool, arguments, state and capture time, with the payload
hidden. Other previous evidence keeps its payload only up to 600 bytes. Payload sizes are
UTF-8 bytes of non-escaped JSON, the same measure as the 12 KB capture bound. This trims
only the prompt view: previous-checkpoint rows are context and cannot be cited, and the
carried conclusion still stores every cited row in full.
Full sanitized evidence remains in immutable revisions and request artifacts;
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
operational evidence. Chart proposals select existing JSON rows/fields, including digest
summary rows such as `change_buckets`; the server builds the tables, bars, observed-value
histograms and timelines. The model cannot supply invented chart values. A proposal that
does not select returned rows is dropped with a limitation instead of rejecting the report.
Snapshot datasets have no historical query window. A `not_scheduled` or failed checkpoint
that carries a conclusion renders that conclusion's evidence, charts and impacted devices.
Rule-derived and combined verdicts keep the deterministic device rows that justify them.
These validations establish provenance and shape, **not proof of causal attribution**.
Agent conclusions remain provisional and require human evaluation before promotion.

MCP request inputs are written before an atomic fenced reservation. Results are written
before journal completion. Unknown acknowledgements prevent dispatch/publication;
unfinished records remain `reserved`. Operator request-detail reads verify organization,
audit access, journal pointers, generation, revision, request identity and content hash.
The existing artifact retention policy applies. Logs contain bounded redacted payloads,
never transport headers or service/provider credentials. Model errors retain fixed
validation categories and a bounded, redacted detail that never echoes model-supplied
values; unsuccessful untrusted provider text is not stored as a finding.

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

Validation of the evidence-quality revision (2026-09-15): replay tests
(`backend/tests/test_mcp_investigation_replay.py`) drive the production worker and agent
loop with the recorded MCP catalogue schemas, 200-row event searches and 240-point
SLE-like series through fake MCP and model clients that check the prompts they receive.
In that harness the system prompt with its action schema measured about 10.7 KB, the
other fixed prompt data about 6.8 KB (5.6 KB of compact tool schemas), a 200-row event
digest about 10 KB, and a follow-up run with eight event digests plus its cited previous
evidence exceeded 96 KB until older observations were hidden. When a +10 report cited all
eight of its digests, the cited payloads came to about 80 KB. Before the 32 KB protected
cap, the +30 run's first prompt measured about 97.9 KB with nothing left to hide, so the
run stopped as `budget_exhausted` before any model call. With the cap, the same first
prompt measures about 50.4 KB: the three newest cited payloads are shown and five are
hidden with their identity kept. The run completes. No live Mist, MCP or model runs were
performed for this revision; the live checks above predate it.
