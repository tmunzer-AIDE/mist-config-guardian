# Investigation skills and attribute documentation

Status: proposed addition to the hybrid design, 2026-09-12. This document does not
install skills or implement/start an MCP server. The investigator runtime remains
unimplemented. Mist tools were unavailable during the initial draft; a subsequent
bounded read-only probe verified the capabilities recorded in
[Mist MCP capability checks](mist-mcp-capabilities.md).

## Responsibilities

| Component | What it contributes |
| --- | --- |
| Investigation skills | Focused hypotheses, useful checks, counterevidence and stopping conditions |
| Future OAS lookup library / optional MCP adapter | Definitions and constraints for configuration attributes, with source provenance |
| Mist operational MCP / existing collectors | Actual configuration and operational observations, subject to verified tool capabilities |
| Guardian executor | Authorized entities/checks, collection budgets, observation persistence and numeric validation |

Skills and documentation supplement the constrained check catalogue. A documented
endpoint is not an executable capability, and a skill cannot grant access to an
entity or tool. Resolve and enforce capabilities in code as specified in the main
design. Documentation queries may search approved schema identities without tenant
entity handles because they return public definitions, not live organization data.

## Small domain skills

Keep the investigation skills versioned with Guardian as application-owned runtime
assets. Installation as personal Codex skills would not make them available to
Guardian's background worker: the runtime must explicitly discover and load them.
Use a bounded manifest of approved skill IDs, applicability metadata and hashes.
Select from changed object types/paths and load only relevant bodies. Multiple
domains can apply; no skill may exclude checks required by another domain.
Skills run inside the single audit investigation, never as agents instantiated per
device. After the initial collection window (default 60 seconds), they use the
semantic diff and correlated configured-device list to help select relevant cohorts
from resolver-issued candidates. The list describes observed deployment; skills
must also consider resolved downstream dependencies and unconfirmed deployments.

Rule exclusions have precedence over skill/agent-proposed corroboration for that
rule's verdict. The plan compiler emits rule-specific eligibility constraints;
the evaluator rejects excluded evidence contributions before severity, affected
counts or attribution are aggregated. Such observations can be displayed separately
as context. They cannot regain influence by being relabelled as agent-only findings;
a distinct mechanism needs independent evidence. Another rule's positive requirement
is unaffected. This is an executor/evaluator invariant, not a skill instruction alone.

When the investigator runtime exists, start with the four v1 domains:

| Skill | Investigation focus | Counterevidence / important uncertainty |
| --- | --- | --- |
| WLAN lifecycle | Removal/disable, actual serving devices, previous clients and new join activity | Successful reconnection elsewhere; missing occupancy is not zero; unrelated AP health cannot establish attribution |
| WLAN authentication | Changed authentication settings, matching client failures and authorization results | No new authentication attempts; cached sessions; unrelated RADIUS failures; unknown secret comparison |
| Switch PoE | Changed port, powered-device association, power delivery and downstream availability | No attached device, successful alternate power, missing topology; zero clients cannot dismiss confirmed infrastructure loss |
| Port availability | Administrative state, previously active link and known attached entities | Planned removal, redundancy where evidenced, link recovery; avoid inventing VLAN or forwarding paths |

One shared investigation contract specifies evidence references, tool constraints,
handling of concurrent changes, inference versus observation, and final output.
Each domain skill adds only its distinctive reasoning. Keep firmware/assignment/
threshold expansion in the planner, not disguised as terminal impact skills.
All skills use the same [report schema and evidence blocks](impact-investigation-report.md).
They may propose useful charts, tables or histograms over available observations;
the backend validates/materializes data and the UI uses registered renderers.
Skills cannot change report sections, supply invented measurements or promote
excluded contextual evidence through a caption or visual.

For unmatched changes, use the shared contract with explicit `unmapped` coverage;
attribute lookup becomes available only in the later delivery phase below.
Routing, firewall, WAN, VPN and RF skills can be added when
their required checks and resolvers exist; prose cannot supply missing visibility.

Store the chosen skill IDs/hashes with each investigation. Validate skills against
the adjudicated acceptance cases, including misleading device names/descriptions,
unrelated degradation and absent evidence. Judge their resulting queries/findings,
not merely whether their text contains prescribed phrases.

## OAS documentation service

After the investigator runtime exists and unmapped cases demonstrate retrieval
needs, build a documentation-only lookup library for Guardian. Add a thin MCP
adapter only when an external consumer needs it. Neither is a v1 prerequisite.
The library needs no Mist organization token and makes no live Mist API calls.

An inspected local Mist OAS copy reports OpenAPI 3.1.0, document version 2609.1.0
and 2,912 component schemas. These are schema components, not a count of possible
settings. For example, `switch_port_usage.allow_dhcpd` documents different behavior
for true, false and omission depending on port mode. Returning only `type: boolean`
would discard the information the investigator needs.

The upstream repository explicitly describes the specification as documentation
only. Use it for retrieval and source-backed explanations; do not generate live
API execution tools or treat it as proof of runtime behavior. Source:
[Mist OpenAPI](https://github.com/mistsys/mist_openapi).

Proposed library operations and, later, equivalent MCP tools:

| Tool | Inputs | Bounded output |
| --- | --- | --- |
| `mist_docs_search` | Query, optional object/scope filter, limit/cursor | Matching schema/attribute IDs, short descriptions and source locations |
| `mist_docs_describe_attribute` | Returned schema ID, property path, pinned revision | Type, description, constraints, explicit default/required status, conditions, variants and unresolved references |
| `mist_docs_list_attributes` | Schema ID, property prefix, limit/cursor | Immediate children; expand nested maps/arrays on demand |
| `mist_docs_references` | Schema ID, limit/cursor | Schemas and API request/response locations referencing that schema |

Return a content hash, OAS/document version, source URI and exact JSON pointer with
every result. Represent `documented`, `not_documented`, `ambiguous_variant`, and
`unresolved_reference` distinctly. Missing descriptions/defaults remain missing.
Preserve the distinction between configuration request fields and telemetry response
fields. Backreferences describe schema use, not live configuration inheritance or
which deployed devices depend on an object.

Support the source's declared OAS dialect: preserve reference siblings, `allOf`,
`oneOf`/`anyOf`, nullable unions, enums, additional-properties maps and item schemas.
Bound reference expansion and detect cycles. Do not flatten alternatives into a
single supposedly authoritative effective schema. A schema `default` is documented
information; it is not proof of Mist's merge/override behavior. Unknown effective
semantics still mean assume effective, as in the main design.

Use a pinned, locally indexed release. Ingestion may process the entire OAS
mechanically; it does not require manually mapping every attribute to an impact
rule. Pin approved external references at ingestion, and report unresolved ones.
Do not allow query-time arbitrary URL fetches or file reads. Responses have depth,
result-count and byte limits and explicit truncation/cursors.
All four documentation operations also consume the same persisted per-investigation
tool budget as operational checks and resolver expansions. Count every page, retry
and logical cached call; apply elapsed-time and output/token limits as well. The
executor reserves budget atomically before dispatch and preserves usage across
checkpoints/restarts. No separate documentation allowance bypasses the shared cap.
Budget exhaustion leaves the lookup unresolved and coverage incomplete. Public,
pinned documentation is exempt from entity handles, not execution budgets.

Keep any later curated operational notes separate from the OAS text, with their
own references, review status and version. Do not fill documentation gaps with
uncited generated explanations. Skill text can propose a hypothesis from a field's
meaning; the resulting claim still requires operational evidence.

## Delivery boundary

First verify which Mist tools are actually callable: safe identity/site inventory,
SLE discovery and time ranges, client/port evidence, configuration reads and topology.
Record tool schemas, scope/filter support, result limits and error behavior. Do not
fetch secret-bearing full configuration objects merely to inventory capabilities.

Deliver the four v1 rules with four hand-validated, sanitized domain fixtures
covering the specific WLAN and switch-port paths they consume. Keep source revision,
attribute semantics and uncertainty with those fixtures; no general OAS search
index or MCP adapter is needed. Unmatched paths remain explicitly unmapped.

Next implement the investigator's loading and constrained execution contract, and
connect the four versioned domain skills. Gate documentation work behind that
runtime and demonstrated lookup needs from real unmapped cases. Ship the lookup
library first, validating nested references, tri-state descriptions, variants,
unknown paths, cycles, provenance, pagination and the shared investigation budget.
Only implement the MCP adapter when an external consumer needs the library's
operations. An exhaustive attribute inventory is not a delivery prerequisite.
