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
- Read historical sessions once per WLAN/site/window, never once per AP. Initial
  collection waits 60 seconds; later opportunities occur around +10…+60 minutes
  on the existing worker tick. Configured-device evidence is not required to
  discover the WLAN's clients and is not treated as an exhaustive consumer set.
- Bound v1 to four WLAN targets, eight reads per checkpoint, 56 reads per audit,
  ten checkpoint attempts including crash retries, one 1,000-row page per read,
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

## Next implementation queue

1. Carry configured-event identities and deployment outcomes into the audit
   evidence contract, preserving occurrence/receipt times and ambiguity. Extend
   resolvers for the remaining three rules without modifying shared device plans.
2. Add retention cleanup and durable dispatch journaling, then complete the common
   report schema and topology attribution records. Keep serving-device evidence
   distinct from device failure.
3. Add the bounded agent tool loop over the tested capability boundary. Extract
   rule packs/skills from working checks; add OAS retrieval only for a demonstrated
   unmapped-path consumer. Build operator adjudication/replay before promotion.
4. Migrate all enumerated consumers, including notifications, to the same audit
   assessment revision and retire broad per-device collection after acceptance.
