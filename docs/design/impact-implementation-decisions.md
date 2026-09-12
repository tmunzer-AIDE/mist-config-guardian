# Impact implementation decisions

Owner: Guardian impact workstream. Updated: 2026-09-12.
The user delegated implementation decisions and requested this durable record.
This file records decisions and verified delivery state; proposed features are not
described as implemented. The detailed contracts remain in the linked design docs.

## Decisions

1. **Deliver one complete WLAN-removal slice first.** Connect audit configuration
   versions, owned evidence windows, selective collection, rule verdict and existing
   projections before adding WLAN authentication, PoE and port availability rules.
   Do not let broad session telemetry become audit-attributed evidence by default.
2. **One audit owns one investigation.** Organization/audit uniqueness is enforced
   in storage. Device sessions are shared sources. Provisional receipts collect
   deterministic evidence only; timeout alone never creates per-device agents.
3. **Keep identity and time explicit.** Each check records its entity/cohort and
   baseline/follow-up windows. Missing identity or history is incomplete coverage,
   not zero traffic. Configured events are deployment evidence, not the affected set.
4. **Use the existing worker.** Persist a 60-second initial collection deadline and
   an investigation expiry independent of device sessions. Reuse the worker's
   minute tick; subsequent model opportunities remain bounded near ten-minute
   checkpoints. Late events update the same investigation without resetting budgets.
5. **Publish one assessment.** Changes, Overview, Impact/topology, search and
   notifications consume the audit assessment or an explicitly labelled legacy
   projection. Per-scope movements and affected counts replace group SLE means.
6. **Select checks before collection.** Typed requests constrain metric/source,
   scope and time. Match rule exclusions in code. Deduplicate matching reads;
   legacy broad capture remains isolated until migration is verified.
7. **Use compact durable state.** Evidence and report artifacts are immutable and
   bounded; publish a revision through a conditional root update. Resumed workers
   validate lease generation at dispatch and commit. Summaries can be rebuilt.
8. **Constrain live AI access.** Only approved checks over resolver-issued handles;
   current organization authorization at dispatch, isolated caches, redacted logs,
   and shared budgets. Never use restore-administrator credentials for monitoring.
9. **Keep the agent rollout gated.** No new AI notifications until capability tests
   and human-adjudicated acceptance cases pass. Automated tests are not operator
   labels. Missing labels leave shadow mode enabled, not an inferred pass.
10. **Implement presentation incrementally.** Preserve the common report schema.
    Start with impact/confidence bands, impacted devices, evidence tables/trends,
    gaps and logs. Richer chart types and OAS retrieval follow real consumer needs.
11. **Work in local, reviewable commits.** Preserve the recovery stash. Do not push,
    deploy or change Mist configuration as part of implementation. Record test
    results and remaining limitations at each milestone.

## Delivery ledger

- `17a29e5`: evidence-state contract, relevance evaluator seam, persisted device
  assessment and site/device UI projections; design and MCP capability notes.
- `4a53177`, confidence follow-up: count only complete, selected, comparable observations;
  latest failed comparison keeps confidence low. Eight regression cases; 914
  backend tests passed, 20 skipped; lint/format/type/OpenAPI checks passed.
- `9d0a7a6`, projection and collection follow-up: actual worst before/after pairs remain
  separate for site/device scopes, repeated scope observations are deduplicated,
  affected counts drive recovery, and legacy prose no longer infers causation
  from absence of competing audits. Typed telemetry source selection can omit
  irrelevant endpoints; existing callers retain broad capture until migration.
  918 backend tests passed, 20 skipped; Ruff lint and source type checks passed.
  The repository-wide format check also identifies one pre-existing formatting
  difference in `api/routes/auth.py`, outside this patch.
- WLAN-removal shadow slice: implemented and validated. It has a sparse
  immutable-version compiler, capability-bound historical session collection,
  deterministic assessment, one durable root per audit, immutable evidence
  revisions, existing worker integration and an on-demand Changes preview.
  Validation: 956 backend tests passed, 20 skipped; lint, source type checks and
  OpenAPI consistency passed. Frontend: 385 tests passed,
  production build passed, and a Playwright browser regression passed against a
  fresh isolated development server. The preview was visually inspected.
  CodeRabbit remains signed out; review used local code inspection and tests.
  It is opt-in with `IMPACT_ENGINE_MODE=shadow`; default `legacy` is unchanged.
  The AI tool loop, remaining rules and production report/topology migration are
  still pending. The preview is diagnostic, not the final common report contract.
- Shadow runtime review follow-up: missing groups retain audit roots and publish
  correlation gaps; checkpoint limits count published revisions instead of lease
  generations, with fenced termination after expiry even on checkpoint failure.
  Documented worst-scope field semantics and enumerated production consumers.
  Validation: 960 backend tests passed, 20 skipped; Ruff lint, changed-file format,
  source type and OpenAPI consistency checks passed. Local diff review completed;
  no frontend or API contract changed in this follow-up.
- Shared audit projection: Changes list/detail, Overview feed and the existing
  report preview use one compact published-assessment projector. Added explicit
  provenance, feed-local shadow counts and compact UI presentation; production
  filters, counts and notifications remain isolated. Validation: 980 backend
  tests passed, 20 skipped; 387 frontend tests passed; production build and both
  targeted Playwright tests passed. Changes and mobile Overview screenshots were
  visually reviewed. Ruff lint, source types and OpenAPI consistency passed.
  New API fields are additive; their semantics are documented in
  `docs/impact-monitoring.md`. No live Mist requests or production promotion.
- Deployment receipt evidence: authenticated ingestion normalizes allowlisted
  configuration events, and shadow revisions preserve bounded event/device
  snapshots with explicit correlation and separate occurrence/receipt times.
  The report preview shows deployment outcomes separately from impact findings.
  Validation: 1002 backend tests passed, 20 skipped; 389 frontend tests passed;
  production build and the extended Playwright report test passed. The table was
  visually inspected. Ruff lint, source types and OpenAPI consistency passed.
  The 200-device regression still publishes one report with two WLAN HTTP reads.

## Gates that require external evidence

- Human labels: 20–50 historical changes with a held-out set grouped by deployment
  or outage, including benign and critical cases. No fabricated labels.
- Runtime connection: verify Guardian worker access independently of the desktop
  Mist MCP connection, including allowed historical WLAN/client queries.
- Numeric confidence/impact scores remain deferred; bands and evidence explanations
  are the agreed interface.

## WLAN shadow slice decisions

- Only an actual `audits` receipt can open a root. Device events, even when they
  carry an audit ID, cannot establish the audit baseline. The immutable anchor is
  the audit occurrence timestamp; a missing timestamp uses receipt time with an
  explicit coverage gap. Duplicate receipt delivery uses `$setOnInsert` and never
  extends the hour, initial wait or budget.
- Match site WLAN deletion/disablement using the pre-change version's WLAN UUID.
  Require matching immutable incarnations; do not substitute the logical object's mutable current incarnation. Organization
  WLAN consumers and multiple same-audit versions need further resolution and
  remain gaps. Unknown inheritance remains assumed effective.
  Schedule and SSID-identity changes are explicitly unmapped in this slice;
  the broader matrix row does not imply those variants are implemented.
- Read historical sessions once per WLAN/site/window, never once per AP. Initial
  collection waits 60 seconds; later opportunities occur around +10…+60 minutes
  on the existing worker tick. Configured-device evidence is not required to
  discover the WLAN's clients and is not treated as an exhaustive consumer set.
- Bound v1 to four WLAN targets, eight reads per checkpoint, 56 reads per audit,
  ten published checkpoints (not lease claims), one 1,000-row page per read,
  512 KiB per response and a 20-second wall timeout. Target, row, byte and
  pagination limits produce visible incomplete coverage. The collector does not
  follow provider-supplied pagination URLs.
- A successful historical-session query measures only returned session evidence;
  it does not establish that no new clients attempted to join, that collection
  retention is complete, or that APs failed. Ordinary disconnects and roaming
  remain counterexplanations. This first rule can report possible disruption,
  never critical attribution from session disconnects alone.
- Names, SSIDs, usernames, secrets and tool prose do not enter the rule input.
  Capability and resolver-issued handle validation runs before dispatch. Every
  request rechecks organization status and credential identity and atomically
  reserves its audit budget under the current lease generation.
- Revisions are written before publishing their pointer with a revision/lease
  predicate. Readers fetch only that exact published artifact. Losing writers'
  artifacts are not exposed. Normalized evidence preserves checkpoint context;
  no model conversation is started by this slice.
- The Changes preview shows bands, findings, serving APs and check outcomes.
  Serving APs are not classified as failed devices or painted on topology. The
  preview omits raw client identities. Full cross-view rating projection, typed
  charts, impacted-device topology records, durable pre-dispatch MCP journaling,
  historical report navigation, retention cleanup and the final report schema
  remain rollout work, not claims of this implementation.
- Shadow mode suppresses the existing per-device AI narrator and adds no new
  impact notifications. Legacy deterministic monitoring continues for comparison;
  its broad collection is not yet replaced by the selective path. Thus this stage
  demonstrates bounded new collection but does not claim reduced total production
  query volume while shadow and legacy collectors coexist.

## Review follow-up: correlation, retries and projection ownership

- Persist the audit root even when the change group is temporarily missing.
  Only the existing authenticated `audits` receipt path may open it; configured
  events still cannot open investigations. On each checkpoint, absent correlation
  produces a durable assessment gap and no operational queries. Later correlation
  resumes the same root with its original anchor, deadline and query budget.
  Expiry leaves an incomplete report if correlation never arrives. Until a group
  exists, the group-keyed preview cannot display that root; storage retains it.
- `generation` is exclusively the fencing token. The existing `revision` already
  counts successfully published checkpoints, so it also supplies the checkpoint
  limit without adding a second counter that could drift. Crashed claims and
  orphan artifacts do not consume it. A checkpoint exception after expiry stops
  the root under its current fence, provided the database accepts the update.
  Database unavailability still requires the existing worker retry/recovery path.
- `MetricMovement.baseline/latest` belong to the single worst `scope_id`, while
  `sessions/degraded_sessions` count the distinct comparable population. The
  class contract now explicitly documents this distinction for future consumers.
- Prepare projector migration before adding further presentation consumers, but
  do not promote the WLAN-only shadow assessment to the production verdict for a
  whole audit. Mixed/unmapped changes, report provenance and the adjudication gate
  must remain explicit. This follow-up changes no production severity source.

### Enumerated consumer migration audit

Verified against source on 2026-09-12. Notifications currently read the **group**
projection through `ChangeGroupProjector._announce`, not the session mirror
directly; that group still derives its severity from device assessments (or legacy
session mirrors). Moving a tile alone would therefore leave alerts inconsistent.

| Consumer / implementation | Current source | Migration requirement |
| --- | --- | --- |
| Changes: `ChangeGroupProjector.rebuild`, `serialize_group`, list severity filters in `services/change_groups.py` | Group severity, recovery and evidence rebuilt from sessions | Publish revision identity, source/mode, coverage and bands together; list filters must use that same published projection. |
| Recovery: `resolve_recovery_state` in `services/change_groups.py` | Session incidents/peak/current severity and scoped movements | Preserve observed history separately from current audit attribution; do not borrow another audit's recovery. |
| Overview: `BeanieOverviewReader.change_group_counts` in `services/overview.py` and recent change rows | Group severity/recovery and shared group serialization | Count the same assessment source and revision that Changes presents; unknown must remain distinct from benign. |
| Notifications: `ChangeGroupProjector._announce` → `NotificationService.notify_impact_detected` | Group critical severity and summary; group deduplication | Gate on an accepted published audit assessment, carry its provenance, and decide revision/recovery alert policy before enabling. |
| Impact/device health: `services/site_impact.py` | Persisted session assessment, with legacy fallback | Keep observed device health separate from audit-attributed affected devices; never paint serving APs as failed. |
| Monitoring list/detail: `api/routes/monitoring.py`, `schemas/monitoring.py` | Query filter on session mirror; serializer prefers assessment | Preserve the device-monitoring meaning or explicitly version its replacement; a read-time fallback alone does not fix database filters. |
| Search: `services/search.py` | Group severity label | Use published group projection and its provenance. |
| Point-in-time: `services/point_in_time.py` | Group severity for current views, neutral historical display | Resolve a revision at the selected time before exposing historical impact; never leak a later report backward. |
| Shadow preview: `services/investigation_reads.py` | Exact published artifact pointer plus revision and organization | Retain strict publication/tenant scoping when extracting the shared report projection. |
| Session writers: `services/impact_analysis.py`, `services/monitoring.py` | Authoritative assessment plus current/peak mirrors and timeline | Keep as device evidence during shadow; remove attribution consumers before retiring compatibility fields and broad polling. |

The shared shadow projection is now implemented as described below. Production
promotion remains a separate acceptance-gated switch, not an implicit side effect
of adding that read path.

## Shared Changes/Overview projection decisions

- Add `AuditImpactSummary` alongside the existing legacy assessment. It carries
  explicit shadow mode/source, root status, exact report identity/revision, policy,
  evidence timestamp, impact/confidence bands, coverage and gap/unmapped counts.
  Legacy badge/filter/count sources are explicitly labelled in the API and UI.
  This is the compact projection of the deterministic WLAN slice, not a promotion
  or a claim that the final common report contract is complete.
- Batch at most 500 distinct audit identities, using one root query and at most
  one artifact query per page. Both queries require the current organization.
  The artifact query matches the exact captured report ID, investigation ID and
  revision; no lookup of a vaguely "latest" artifact, no raw session rows, and no
  additional Mist calls. Root publication may advance between requests; each
  response identifies the exact checkpoint it displays. Database read failures
  expose `unavailable` instead of failing the production page or showing clean.
- Use the same projector for Changes list/detail, Overview feed and the detailed
  investigation preview. A missing root is `not_recorded`, an unpublished root is
  pending, and missing/foreign artifacts or terminal roots without a report are
  unavailable. Partial/unmapped evidence is never counted as no observed
  disconnect. A possible disruption can coexist with partial coverage; an
  incomplete runtime preserves the prior checkpoint's timestamp and coverage but
  cannot present that checkpoint's clean result as completed investigation coverage.
- Derive six mutually exclusive shadow counts from the exact returned Overview
  feed projections. These are feed-local (maximum 50), not window totals, and no
  second query can race their source rows. They include all returned rows before
  the frontend's local impacting/mine filter. Existing production counts remain
  legacy and the cheap counts-only endpoint does not read shadow collections.
- Historical views withhold shadow projections and counts, even though evidence
  revisions exist: selecting a historically published root still needs a durable
  publication history, not merely an artifact creation timestamp. Default legacy
  mode also avoids all new shadow batch reads. Restores, topology and notifications
  do not consume this shadow field.
- Keep the Changes table compact, with full timestamp/policy/gap detail in the
  detail panel and Overview card. Render all text through Angular interpolation.
  Browser checks use mocked APIs; they validate presentation, not Mist data access
  or the human acceptance gate. CodeRabbit remains signed out; local source and
  diff review checks the publication boundary and production isolation.

## Deployment receipt evidence decisions

- Normalize configuration changed/configured/failed/reverted events from the
  existing allowlist at authenticated receipt ingestion, before background device
  monitoring. Store only event kind, device type, validated site UUID/MAC,
  occurrence time, outcome and typed gap messages. No names, SSIDs, secrets or
  provider prose enters this contract. Normalization applies in both runtime modes
  and makes no external calls; deployment snapshot collection is shadow-only.
- Use existing durable receipts rather than add another event collection. Preserve
  the encrypted source and existing deduplication behavior. New receipts distinguish
  a normalized non-deployment event from an older unnormalized receipt. Older
  receipts are not silently backfilled: a report that encounters them records a
  gap. Add an organization/audit/receipt-time index for bounded audit reads.
- Explicit audit ID plus a known event time within the audit's checkpoint window
  establishes reported deployment association. Missing/invalid timestamps, an
  approximate audit anchor and out-of-window events remain ambiguous. Event time
  is never replaced with receipt time, and future-dated success is not presented
  as already applied. This association does not validate inventory membership or
  establish outage attribution; future operational checks must still resolve an
  authorized entity handle.
- For events without audit IDs, only receipt IDs actually linked from sessions
  naming this audit are candidates. Even a currently single-audit session is not
  sufficient proof of association. A shared session may supply candidates to
  several investigations; each shows unknown deployment outcome for those
  candidates. An explicit different audit ID excludes the event. Session-only
  correlation never becomes confirmed merely because it is the sole candidate.
- Keep one device entry per site/MAC before computing any device count. For
  explicitly associated events, occurrence time orders outcomes, so a delayed
  failure cannot overwrite a later configured event. Conflicting outcomes at the
  same occurrence time or uncertain ordering yield unknown. Preserve individual
  receipt references and both timestamps; duplicate deliveries do not multiply
  the device count. An observed failed or reverted deployment is not an outage.
- Bound each checkpoint to 500 sessions with 32 receipt references each, 4,000
  candidate receipt IDs, 2,000 event observations and 500 device entries. Read one
  extra item to detect each source cap and expose gaps; do not load encrypted
  payloads or raw session telemetry. Database failure yields unavailable deployment
  evidence without changing the WLAN assessment. Expected device count remains
  unknown; coverage is always `observed_receipts_only`, including an empty set.
- Store deployment evidence inside the same immutable artifact published under
  the existing root fence. The preview reads that artifact, not a recomputed live
  device list. Later checkpoints preserve prior snapshots. The initial 60-second
  wait, audit expiry, SLE plan and query budget are unchanged; 200 configured
  devices never trigger 200 checks. Later arrivals are included at the next
  scheduled checkpoint if one remains. Receipts arriving after terminal completion
  remain stored but do not reopen the report or extend monitoring.
- Add a nullable `deployment` field to the detailed investigation response.
  Null means this revision did not collect deployment evidence. The bounded
  device/event tables show candidate association, unknown expectations and timing;
  they do not populate impacted-device topology records or alter production
  severity, notifications, Changes/Overview counts or the WLAN rule's inputs.
  Full dispatch journaling and lifecycle cleanup remain separate work. Local
  source review was used; CodeRabbit remains signed out.

## Deployment review follow-up

- A session candidate with a different outcome from the latest explicitly
  associated event for the same site/MAC makes the device row `unknown` with
  `ambiguous` association. Apply this conservatively even to older or untimed
  candidates: occurrence order cannot resolve their audit association. Preserve
  the explicit event timestamp and all receipt references without promoting the
  candidate to confirmed deployment. Matching candidates and events for another
  device do not cancel an explicit outcome. Simultaneous contradictory explicit
  outcomes also mark association ambiguous.
- Keep the newest 2,000 receipt arrivals, ordered by descending receipt time and
  ID, with one extra row to detect truncation. The gap explicitly says earlier
  history may be missing. Event occurrence time still determines outcomes within
  the retained set; newest arrival does not necessarily mean newest event.
  Session/candidate discovery caps remain separately bounded and gap-reporting.
  This changes only local Mongo selection and the deployment projection, with
  no additional Mist requests or changes to impact evaluation.
- Validation: 1,008 backend tests passed, 20 skipped; six additional regression
  cases cover candidate conflicts and overflow retaining late failure/revert
  events, including receipt-time ties. Ruff lint, changed-file formatting and
  source type checks passed. Local source/diff review completed; CodeRabbit
  remains signed out. No frontend implementation or API schema changed.

## Dispatch journal decisions

- Bring the durable dispatch journal forward before enabling another operational
  rule. This completes the missing crash-observability boundary for the existing
  WLAN consumer rather than introducing an unused logging service. The new rule
  itself is not implemented in this milestone.
- Correct the initial evidence assessment: current port statistics alone cannot
  reconstruct a historical baseline, but device-event history can provide port
  transitions. The user identified this source. A read-only Mist MCP constants
  query confirmed `SW_PORT_UP`, `SW_PORT_DOWN`, `SW_POE_PORT_ENABLED`,
  `SW_POE_PORT_DISABLED` and chassis/controller PoE alarms. The local OAS exposes
  bounded device-event search with device MAC, event type, start/end and cursor
  parameters. Use these alongside targeted current port state for the next rule;
  do not infer pre-change state from an empty or truncated history. PoE enablement
  events alone do not prove that a downstream device was receiving power.
- Embed at most 56 journal records on the audit root. Reserve one budget unit and
  append its record in the same fenced Mongo update. No extra await separates a
  successful reservation from the collector's HTTP call. A denied, failed or
  uncertain reservation does not dispatch. Legacy budget consumption without
  records remains visible as `unlogged_reservations`; never fabricate old logs.
- Each record names the fixed check, resolver handle, site/WLAN, evidence window,
  random attempt identity, worker generation and candidate revision. A candidate
  revision is not proof of publication. `reserved` means execution outcome unknown:
  the process may have stopped before sending, during the request, or after a
  response but before recording the result. Never relabel it successful or failed
  merely because a lease expired.
- After collection, update only that attempt's still-reserved record, matching
  audit-root ID, organization, attempt ID and owning generation. A stale worker may
  record the factual result of its own request but cannot dispatch again or publish
  over the new worker. Completed records cannot be overwritten. Check, handle and
  window must match the reservation. A completion-write failure stops checkpoint
  publication; the next bounded retry retains the unresolved reservation and pays
  for any new request. Cancellation likewise leaves an explicitly unknown outcome.
- Store HTTP status, bytes consumed, parsed row count, terminal collection state
  and result-recording time. No request headers, tokens, configuration, client
  identifiers, raw responses, cursor URLs or provider/error prose are journal
  fields. This is metadata for today's direct Mist HTTP checks, not a claim that
  a model/MCP runtime or full raw-response archive exists. BSON round-trip tests
  cover native writes and UUID encoding; live Mongo concurrency remains untested.
- Expose the bounded journal through the existing authorized investigation preview.
  The UI labels it **Live collection activity**, independently of the immutable
  published assessment/deployment snapshot. It includes orphan attempts and can be
  read before the first successful publication. Compact Changes/Overview reads
  continue excluding journal records; no new Mist calls or Mongo read queries are
  added. Two successful WLAN reads add two result-metadata Mongo updates. Root
  retention cleanup, a future generalized capability catalogue and remaining rules
  stay in the queue. Local source/diff review was used; CodeRabbit remains signed out.
- Validation: 1,025 backend tests passed, 20 skipped; 391 frontend tests passed.
  Ruff lint, source types, changed-file formatting and OpenAPI consistency passed.
  Production build and the isolated Playwright investigation-preview regression
  passed; the activity table was visually inspected. Seventeen new backend cases
  cover reservation acknowledgement loss, result-write failure, cancellation,
  stale-worker logging, finite journal size, response metadata, immutable completed
  records, result identity, legacy gaps and excluded secret-bearing fields.

## Dispatch-denial review follow-up

- Replace the collector's boolean reservation result with an explicit denial enum
  (or `None` only after successful atomic reservation). New evidence uses
  `dispatch_denied` plus `dispatch_denial`: unavailable/unverified organization,
  changed service credential, expired collection window, lost lease, exhausted
  request budget, full journal, or rejected reservation with unknown cause.
  Preserve the old `budget_exhausted` evidence state for historical artifacts;
  do not guess its original cause. The preview exposes the nullable discriminant
  and a fixed human-readable explanation, with “Not dispatched” in the UI.
- Successful reservations keep their existing atomic budget/journal write and
  make no new read. After a definite zero-match rejection, perform at most one
  organization-scoped root read, projected to generation, lease, budget and one
  journal sentinel record. This is a snapshot of the currently visible blocker,
  not proof of which predicate failed earlier. Prefer a lost lease over budget,
  and budget over journal when several blockers are visible. Missing roots,
  changed-but-unexplained state and database read errors remain
  `reservation_rejected`; never retry HTTP on the strength of diagnostic reads.
  An uncertain reservation acknowledgement still raises before HTTP and is not
  converted into a definite denial.
- Stop collecting at the first denial. Publish incomplete evidence only through
  the existing fence; a worker that lost its lease cannot replace the current
  report. Denials spend no budget and create no request journal record. The
  evidence contract prevents a denial from carrying rows or transport metadata.
  Credential preflight/decryption failures outside reservation retain their
  existing behavior; this change classifies dispatch authorization decisions.
- Clarify that response bytes measure content actually read. An HTTP error can
  supply a status with no byte count because its body was not consumed. A blank
  value is not measured zero, and an unfinished journal entry does not establish
  whether a body was read before the worker stopped.
- This is a bounded review follow-up, not the next switch rule. Port/PoE event
  history remains the next rule's historical evidence source. Local source/diff
  review completed; CodeRabbit remains signed out.

- Validation: 1,038 backend tests passed, 20 skipped; 392 frontend tests passed.
  Thirteen added backend cases cover denial reasons through the preview API,
  zero HTTP/budget use, diagnostic-read failure and invalid denial/result
  combinations. The added frontend regression distinguishes changed credentials
  from spending limits. Ruff lint, source types, changed-file formatting and
  OpenAPI consistency passed. No production build or browser rerun was needed
  for the label/help-text changes; the frontend suite compiled the templates.

## Agent-first sequencing correction

- The user challenged why use cases still require manual definition. The goal is
  an agent that investigates changes, not an exhaustive hand-maintained mapping
  from every attribute to every possible outage. The deterministic foundation
  was necessary, but completing all four initial rules must not gate the first
  investigator runtime. This supersedes the earlier next-switch-rule sequencing.
- Keep the WLAN rule as a tested reference and exclusion boundary. Treat the
  remaining scenarios as regression cases and useful capability extensions,
  rather than prerequisites or the complete universe of allowed hypotheses.
  Build the first bounded shadow investigator over existing checks next.
- Humans implement reusable evidence capabilities, trusted entity resolvers,
  budgets, evidence/report validation and acceptance cases. The investigator
  interprets a diff, proposes hypotheses, selects relevant authorized entities
  and checks, examines counterevidence and updates a structured report. Skills
  guide these tasks; they are not a mandatory rule for every changed attribute.
- Keep execution enforcement: the agent cannot invent entity handles or check
  IDs, bypass explicit rule exclusions, or turn a novel hypothesis into a
  production verdict. Separate model-proposed attribution from validated
  observations. Unmapped changes can receive an investigation hypothesis; if
  available capabilities cannot test it, report the missing capability and
  insufficient evidence. Do not imply that the initial WLAN-only capability
  set can investigate arbitrary switch, gateway or routing changes.
- Add capabilities incrementally from concrete investigator gaps, including
  port/PoE event history and physical dependencies. Introduce pinned OAS lookup
  when the running investigator needs attribute semantics. OAS descriptions
  alone do not establish actual dependencies or causal impact. Retain shared
  call budgets, audit-owned context and human-adjudicated promotion gates.

## First bounded investigator runtime

- Implement `agent_shadow` as the third, mutually exclusive engine mode. `legacy`
  remains the default; `shadow` remains deterministic. Both shadow modes suppress
  the old device narrator and use the existing audit-root scheduler. No environment
  was enabled, provider credential changed, live provider called, deployment made
  or production verdict promoted in this milestone.
- The agent uses the configured OpenAI-compatible provider through the existing
  application adapter. Implement a provider-neutral JSON action/result loop with
  `collect` and `report` actions, rather than requiring provider-native function
  calling support. The application validates and executes actions. This follows
  the application-execution boundary described in the official
  [function calling guide](https://developers.openai.com/api/docs/guides/function-calling).
  No SDK dependency or desktop Mist MCP credential borrowing is introduced.
- The current catalogue contains only the existing WLAN session check. Capability
  references derive from audit-bound target handles and fixed baseline/follow-up
  windows. Model-selected paths, URLs, new identities and unlisted checks cannot
  execute. Validate the entire action before any selected check; validate returned
  evidence identity before supplying it to the model. Deduplicate repeated checks
  within a checkpoint, including deterministic fallback. A cache hit still consumes
  the model call which requested it. Do not reuse old follow-up evidence as fresh.
- Supply removal/disable semantics from immutable configuration, opaque target
  handles, explicit exclusions, bounded coverage gaps and an unmapped-change count.
  Do not send raw configuration, secret values, SSID/device names, client MACs or
  arbitrary tool prose. The first runtime does not yet interpret arbitrary unmapped
  configuration diffs. That requires broader resolvers, redacted change context and
  operational capabilities; this limitation remains visible rather than implied
  to have been solved by adding a model.
- Collect the deployment snapshot once before the model and persist that exact
  snapshot with the revision. Supply at most 20 pseudonymous deployment candidate
  entries, their association/outcome/timing and an explicit omitted count. Expected
  fleet size remains unknown. Those context handles are not executable capabilities
  or impacted-device records; the model cannot cite them as WLAN check evidence.
- Keep required WLAN evidence outside model discretion. The model may choose
  check order and batch requests; omitted checks still run through the same cache
  and journal after a normal model stop/failure. Invalid output, unavailable provider
  or exhausted model budget cannot cancel those requirements. A collection denial
  stops further evidence dispatch. Database uncertainty, result-journal failure,
  cancellation or the 120-second collection-phase deadline stops publication;
  existing lease/expiry handling and durable reservations expose unfinished work.
- Bound each checkpoint to three model requests, each with at most 24,000 UTF-8
  input-content bytes and 1,500 requested output tokens (or a lower configured
  output limit). Stream at most 65,536 response-envelope bytes and accept at most
  16,000 completion-content bytes. Provider I/O timeout is 20 seconds and each
  model call has a 25-second wall deadline, within the 120-second collection phase
  and existing three-minute lease. The general provider adapter now also bounds
  completion envelopes to 1 MiB for its other consumers.
- Reserve at most 21 model calls and 504,000 input-content bytes per audit; the
  maximum requested output allocation is 31,500 tokens. Persist initial policy
  limits on the root and honor lower existing limits. Counters and one model request
  record are written atomically under the audit fence before provider dispatch.
  `$ifNull` permits older roots without counters to start at zero without a budget
  reset. Failed and uncertain writes never dispatch. Missing provider token usage
  remains unknown; reported invalid/negative/bool counts are ignored. Byte admission
  is not a claim of exact billed input tokens or calibrated cost.
- Record request identity, candidate revision, generation, configured model,
  prompt version, bounded normalized input context, fingerprint and requested output
  bound. Complete only the exact still-reserved attempt, preserving token usage and
  validated action. A stale worker can complete its own factual log but cannot issue
  another guarded call or publish. Unknown raw/invalid model responses and provider
  exception prose are not retained. Provider/organization/credential/window denials
  are distinct; a rejected atomic lease/budget guard is explicitly unresolved.
  Read the fresh provider configuration and verified organization/service credential
  before every model request. No restore-administrator credential is used.
- Resume only the root's exact published artifact identity (organization, report,
  investigation and revision), with matching audit IDs. Carry bounded structured
  memory with its source revision, plus previous observed samples, separately from
  newly collected evidence. Missing/foreign/unreadable context prevents model work,
  while deterministic evidence can still proceed. Never append an unbounded chat
  transcript or promote a historical model summary into current facts. The shared
  lease/publication fence remains the single investigation ownership mechanism.
- Publish model output as `model_proposal`: summary, scoped hypotheses, supporting
  and counterevidence references, limitations and open questions. Validate referenced
  checks against current supplied observations and matching target handles. No
  model-written ratings, arbitrary chart series or failed-device identity fields
  exist in this contract. Schema/reference validity is not factual adjudication;
  the UI explicitly labels explanations as hypotheses. Deterministic assessment
  bands and all production decisions remain independent of this proposal.
- The existing authorized preview exposes the revision-pinned proposal and a
  separately labeled live model journal, including unfinished attempts. Raw
  configuration/provider transcripts and credentials are excluded. Compact
  Changes/Overview projections do not load the journal. This audit-owned model
  activity is not yet mirrored into the separate global AI-request audit list.
  Local source/diff review completed; CodeRabbit remains signed out.

- Validation: 1,077 backend tests passed, 20 skipped; 394 frontend tests passed.
  Thirty-five investigator regressions cover real action/result ordering, bounded
  loops, cached checks, invalid/foreign references, provider failures, credential
  changes, context ownership/resumption, legacy gating, budget reservation and
  unfinished model calls. Four provider cases cover response-size bounds and
  invalid usage values. UI tests preserve hypothesis labeling, unknown usage,
  source revisions and escaped output. Ruff, source types, changed-file formatting,
  OpenAPI consistency, production build and the isolated browser preview passed.
  The rendered activity view was inspected. No live provider quality calibration
  or live Mongo concurrency test was performed; these are not adjudicated labels.

## Model request artifacts and on-demand inspection (2026-09-12)

- Keep the audit root bounded to request metadata, budgets, content digests and
  artifact references. Move both normalized input context and validated actions
  to separate `impact_model_request_artifacts` documents. The service inserts
  artifacts without updating them; no raw provider responses or credentials are
  added. The existing prompt/context fingerprint remains distinct from the new
  digest of the stored input body.
- Insert input before the final fenced budget/journal reservation, leaving no
  additional artifact write between that reservation and provider dispatch.
  Failed or uncertain input insertion prevents reservation and dispatch. A
  rejected reservation can leave an orphan input artifact. Insert a validated
  action before conditionally completing its exact reserved journal entry;
  failed insertion leaves the request unfinished and prevents selected checks
  and report publication. Unreferenced artifacts cannot be fetched through the
  request endpoint. Retention and orphan cleanup remain queued.
- Exclude legacy embedded input/action fields from worker lease-claim and preview
  root reads. Existing compact Changes/Overview reads already exclude the journal.
  This avoids transferring historical payloads on those reads without deleting
  history or running a bulk migration; old stored roots are not physically shrunk.
- Load context/action only when an operator requests one journal entry. The new
  viewer-protected, organization-scoped request endpoint first resolves the audit
  group and selects just that request from its root. Follow only journal-linked
  artifact IDs and verify organization, investigation, request, generation,
  candidate revision, kind and content digest before returning a body. Missing,
  foreign, altered or unreadable data stays unavailable. Legacy embedded bodies
  are returned only on explicit lookup and labeled as lacking an independently
  recorded content digest. Changing organizations clears the UI and discards
  pending responses from the previous selection; output remains escaped text.
- API compatibility: `model_activity.records` no longer embeds `input_json` or
  `action`; it contains their nullable artifact references/digests instead. Clients
  inspecting this preview API must use the new per-request endpoint for bodies.
  The first-party UI and exported OpenAPI schema change together.
- The reviewed `dispatch_denied` branch is live: `SessionEvidence.state` explicitly
  includes it and requires a matching `DispatchDenial`. Keep that guard and pin
  the state in the lost-lease agent regression rather than deleting it.
- Preserve agent spend neutrality when adding discovery: resolve a shared, bounded
  capability menu and use that identical set for model selections and the required
  deterministic sweep, with one collection cache. New discovery dependencies must
  enter this shared plan and its budget; do not add model-only operational calls.
  One agent remains owned by one audit, regardless of its deployment fleet size.
- Validation: 1,093 backend tests passed, 20 skipped; 398 frontend tests passed.
  Sixteen new backend cases cover artifact identity/digests, unavailable and legacy
  reads, orphan access, failed/uncertain writes and legacy read projections. Four
  UI cases cover lazy loading, organization changes, legacy labels and mismatched
  request identities. Ruff, source types, changed-file formatting, OpenAPI
  consistency, production build and the isolated browser preview passed; the
  rendered view was inspected. Local source/diff review completed; CodeRabbit
  remains signed out. No live model-quality or Mongo concurrency validation was
  performed. Production promotion and broader capabilities remain deferred.

## General change context and local device candidates (2026-09-12)

- Start broader investigation with the immutable versions already read for the
  audit, rather than adding another Mist inventory scan. Compile a separate typed
  `ChangeContext` and pin it alongside the WLAN plan on the report revision. The
  existing request artifact retains the exact context supplied to each model call.
  This is the first increment of discovery, not a physical dependency resolver.
- Supply registered object type, scope, recorded operation, baseline comparability,
  top-level changed-attribute labels and before/after key presence. Use the stored
  `changed_fields` contract, which records top-level changes. Withhold all values,
  including numbers/booleans, nested keys, device names and SSIDs. Expose only a
  fixed presentation vocabulary for keys; mask unknown dynamic keys and secret
  attributes. This vocabulary provides no severity mapping or check authorization.
  Nested change semantics and safe value-level interpretation remain future work.
- Reject foreign audit/organization versions and missing immutable identities.
  Multiple versions of the same object stay unresolved rather than choosing a net
  change. Missing or cross-incarnation baselines remain explicit. All context uses
  `assume_effective`: this projection does not resolve inheritance or merge rules.
  Version number one alone cannot establish creation; require the stored created
  event. Limit the supplied set to eight objects and six attributes per object,
  inspecting at most 64 sorted versions; record omitted/unresolved object counts
  and omitted attribute counts. Existing version-fetch calls are unchanged and
  still read the audit's versions before this in-memory cap.
- Resolve direct changed-device candidates only from validated MAC, site UUID and
  device type in immutable configuration. Comparable pre/post identities must
  agree. Do not repair missing identity using today's mutable logical object.
  Pseudonymize device/site identities per audit. Reuse the same device-handle
  derivation as deployment receipts so matching observations can be associated.
  Neither observation proves impact, expected fleet coverage, template consumption,
  physical adjacency or a route/service dependency. No live discovery was added.
- Permit one audit-owned agent to inspect this general context in `agent_shadow`
  even when there is no WLAN check. With an empty capability set it can return a
  summary and open questions; the existing validator rejects all hypothesis targets
  and collect references outside the executable menu, including context handles.
  Deterministic assessment remains `unmapped`/`info` for unsupported changes.
  Uncorrelated audits still start no conversation. Existing call/byte budgets,
  credential checks, memory validation and publication fences remain in force.
- Keep the capability generator and deterministic sweep unchanged. Context adds
  zero Mist calls and no model-only operational checks. A 200-device configuration
  audit remains one investigation with a bounded context, not 200 conversations.
  Broader audits can now spend model calls under the existing per-audit cap; spend
  neutrality refers specifically to Mist collection, not zero additional AI cost.
- Bump new model requests/checkpoints to `impact-investigator.v2`; retain v1 in
  the read contract for historical records and memory. The existing preview and
  on-demand context viewer need no UI schema changes beyond accepting that version.
- Fix an integration mismatch discovered while checking the registry: snapshot
  capture persists WLAN type `wlans`, while the terminal rule matched only `wlan`.
  Accept both, preserve the sparse rule's exclusions, and test the production
  registry spelling through the complete checkpoint and required evidence sweep.
- Validation: 1,118 backend tests passed, 20 skipped; 398 frontend tests passed.
  Twenty-five new regressions cover immutable identities, secret/dynamic-key
  masking, ownership, baseline ambiguity, limits, candidate/deployment association,
  unauthorized model handles, no provisional agent, 200 distinct device candidates,
  shared WLAN collection and production registry compatibility. Ruff, source types,
  changed-file formatting and OpenAPI consistency passed. Local source/diff review
  completed; CodeRabbit remains signed out. No live model-quality, Mist discovery
  or Mongo concurrency validation was performed.

## Next implementation queue

1. Extend the general change context and local candidate foundation into operational
   discovery: resolve trusted physical dependencies and build the shared capability
   plan. Keep one investigator per audit; do not add a manual rule for every attribute.
2. Expand reusable resolvers and collectors as needed, starting with targeted
   port/PoE event history and physical dependencies. Add regression scenarios
   and domain skills; avoid requiring a bespoke rule for every attribute.
3. Complete the common report/topology integration and retention cleanup; add
   bounded OAS retrieval for demonstrated knowledge gaps. Build operator
   adjudication/replay before promotion.
4. Promote all enumerated consumers, including notifications, to the same audit
   assessment revision and retire broad per-device collection after acceptance.
