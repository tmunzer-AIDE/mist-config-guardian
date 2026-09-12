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

## Next implementation queue

1. Extend resolvers and checks for the remaining three rules without modifying
   shared device plans. Resolve device scope from immutable configuration and
   authorized inventory; deployment candidates alone cannot issue checks.
2. Add retention cleanup and durable dispatch journaling, then complete the common
   report schema and topology attribution records. Keep serving-device evidence
   distinct from device failure.
3. Add the bounded agent tool loop over the tested capability boundary. Extract
   rule packs/skills from working checks; add OAS retrieval only for a demonstrated
   unmapped-path consumer. Build operator adjudication/replay before promotion.
4. Promote all enumerated consumers, including notifications, to the same audit
   assessment revision and retire broad per-device collection after acceptance.
