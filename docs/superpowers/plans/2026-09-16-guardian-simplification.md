# Guardian Simplification Implementation Plan

> **For agentic workers:** Execute this plan task by task. Keep
> `guardian_enabled=false` until the replacement passes its end-to-end and
> replay gates. Do not delete the legacy impact engine before the replacement
> API and frontend are green.

**Goal:** Replace the current audit impact engine with one monitoring-backed,
plug-in-driven Guardian that can publish a defensible `none`, retain peak and
current impact, and give a bounded MCP agent one repairable report loop.

**Architecture:** New code lives in a small `guardian` package and two new Mongo
collections. Pure functions build change atoms, resolve coverage obligations,
replay monitoring, pair deployment events, and compose verdicts. Rule plug-ins
add deterministic obligations and evidence through one guarded Reader. A
claim-token-fenced service runs at most one early and one final run, with one
retry each. The existing impact engine remains present but unreachable until the
replacement is complete, then is deleted in one cleanup task.

**Tech stack:** Python 3.13, FastAPI, Beanie/MongoDB, Pydantic v2, Celery,
httpx, OpenAI-compatible providers, Angular 21, Vitest, Playwright, Helm.

**Spec:** `docs/superpowers/specs/2026-09-16-guardian-simplification-design.md`

**Plan status:** ready for implementation after Task 1 records its verification
decisions.

## Global constraints

- Work on the current worktree branch. Do not create another branch.
- `guardian_enabled` defaults to `false` in Python, Docker Compose, and Helm.
- New code never reads or writes the legacy impact collections.
- Keep the legacy engine compiling until Task 11. Intermediate commits must be
  deployable with Guardian disabled.
- All tenant reads include `organization_id`; all published run pointers also
  verify `investigation_id` and run kind.
- Every claim transition is fenced by its token and phase. A committed phase
  also matches the recorded attempt number.
- Every run finalization requires `_id=token AND state=running`.
- Recover an expired claim before evaluating or leasing new work for that root.
- Use MongoDB `$$NOW` for every authoritative root-time predicate and
  assignment. Worker time is allowed only for the indexed due query, read-only
  trigger evaluation, and the webhook's initial scheduling hint.
- Capture one fixed `as_of` after attempt commit. Start the local monotonic
  deadline immediately before sending that commit.
- Configuration text, MCP results, provider output, error text, object names,
  and plug-in hints are untrusted at the model boundary.
- No credential, transport header, secret configuration value, unmatched
  neighbor MAC, or unredacted provider output may be stored or logged.
- Source and aggregate byte budgets are enforced before persistence and before
  model dispatch. The final serialized-size assertion is a backstop, not the
  normal compaction mechanism.
- Historical change-group reads do not expose live Guardian results.
- Production monitoring verdicts, badges, and notifications remain unchanged.
- Each task ends with focused tests plus:

  ```bash
  cd backend
  uv run ruff format .
  uv run ruff check .
  uv run ty check src
  ```

- API schema changes regenerate `docs/openapi.json` in the same task:

  ```bash
  cd backend
  uv run python ../scripts/export-openapi.py
  uv run python ../scripts/export-openapi.py --check
  ```

- Frontend tasks end with:

  ```bash
  cd frontend
  npm test -- --watch=false
  npm run build
  ```

- Each implementation task is a separate green commit with the repository's
  required Copilot co-author trailer.

## Target module layout

New backend modules should converge on this layout. Keep contracts free of
Beanie and transport imports so pure tests remain fast.

```text
backend/src/mist_config_guardian_backend/
  guardian/
    __init__.py
    contracts.py
    change.py
    evidence.py
    ledger.py
    monitoring.py
    deployment.py
    composition.py
    reader.py
    agent.py
    report.py
    plugins/
      __init__.py
      base.py
      wlan_removal.py
      wlan_auth.py
      switch_port.py
      dns.py
  models/guardian.py
  schemas/guardian.py
  services/guardian.py
  services/guardian_reads.py
```

The exact split may be adjusted when a module would otherwise contain only a
trivial re-export, but pure domain logic must not move into the service layer.

---

## Task 1: Verify external contracts and freeze fixtures

**Purpose:** Resolve the five facts the design intentionally leaves for
planning before implementation bakes assumptions into plug-ins or tests. This
task is a blocking decision gate: later tasks may build generic infrastructure,
but DNS mappings and exact DNT-NTR replay expectations cannot be finalized until
all five decisions are recorded.

**Files:**

- Create: `docs/design/guardian.md`
- Create: `docs/design/guardian-verification.yaml`
- Create: `backend/tests/fixtures/guardian/` recorded, redacted fixtures
- Modify: `docs/superpowers/specs/2026-09-16-guardian-simplification-design.md`
  only if a verified fact changes a stated mapping
- Test: `backend/tests/test_guardian_verified_contracts.py`

- [ ] Enumerate every Mist object type and top-level attribute that can carry
  DNS settings from the provider schema and representative redacted API
  responses. For each `(object_type, attribute)`, record one of
  `management_resolution`, `client_resolution`, or `unverified`. Include the
  schema/version/source used. `unverified` mappings remain uncovered.
- [ ] Inspect raw, redacted device-event receipts and the provider contract for
  sequence or ordering fields. Record the usable timestamp precision and
  whether same-second conflicts must remain ambiguous.
- [ ] In a non-production Mist site, deploy a template change whose rendered
  switch configuration is unchanged and capture the switch events through the
  30-minute pairing bound. Record whether `SW_CONFIGURED` is emitted. If a
  controlled test cannot be run or is inconclusive, record `unknown`; the
  deployment precondition remains unsatisfied rather than assuming success.
- [ ] Discover the configured MCP catalogue, normalize and hash each accepted
  input schema, then freeze the initial
  `(tool, discriminator) -> evidence_kind` allowlist fixture. Unknown
  combinations remain unavailable.
- [ ] Probe the configured provider with the exact versioned Guardian action
  schema. Record `json_schema`, `json_object`, or `unsupported`, the provider
  fingerprint, and the redacted validation result.
- [ ] Store all five decisions in `guardian-verification.yaml` with source,
  observed-at, result, and fixture hash. Make the test fail if a required
  decision is absent or a fixture hash drifts.
- [ ] Fix both DNT-NTR expected results only after the DNS and
  `SW_CONFIGURED` decisions are recorded. Keep invariant assertions independent
  of the chosen mapping and mark an inconclusive provider result honestly.
- [ ] Add tests that reject an unknown DNS attribute and an MCP tool or
  discriminator absent from the frozen allowlist.
- [ ] Document every verified decision in `docs/design/guardian.md`.
- [ ] Do not proceed to the DNS plug-in or final replay assertions until this
  task is green and reviewed.

**Focused test:**

```bash
cd backend
uv run pytest tests/test_guardian_verified_contracts.py -q
```

**Commit:** `test: freeze Guardian external contracts`

---

## Task 2: Add Guardian contracts, persistence, and disabled configuration

**Purpose:** Establish the new collections and API-neutral contracts without
wiring any production path.

**Files:**

- Create: `backend/src/mist_config_guardian_backend/guardian/contracts.py`
- Create: `backend/src/mist_config_guardian_backend/models/guardian.py`
- Create: `backend/src/mist_config_guardian_backend/schemas/guardian.py`
- Modify: `backend/src/mist_config_guardian_backend/models/__init__.py`
- Modify: `backend/src/mist_config_guardian_backend/config.py`
- Modify: `backend/src/mist_config_guardian_backend/services/investigation_retention.py`
- Modify: `backend/src/mist_config_guardian_backend/tasks/investigation_retention.py`
- Modify: `docker-compose.yml`
- Modify: `helm/mist-config-guardian/values.yaml`
- Modify: `helm/mist-config-guardian/questions.yaml`
- Modify: `helm/mist-config-guardian/templates/configmap.yaml`
- Test: `backend/tests/test_guardian_contracts.py`
- Test: `backend/tests/test_guardian_models.py`
- Test: `backend/tests/test_investigation_retention.py`

- [ ] Define frozen Pydantic contracts for bands, coverage, recovery, evidence,
  obligations, ledger rows, conclusions, run budgets, compact impacted devices,
  and the root result.
- [ ] Model claims as
  `{token, kind, lease_until, attempt, started_at, final_forced}`. Keep
  `attempt` and `started_at` null until commit; store `final_forced` from the
  server-time lease decision.
- [ ] Enforce cross-field invariants: current cannot exceed peak, terminal runs
  have `finished_at`, failed/abandoned runs have a bounded safe reason, and
  successful runs have a verdict.
- [ ] Add `GuardianInvestigation` with collection
  `guardian_investigations`, the unique identity index, due index, and TTL.
- [ ] Add `GuardianRun` with collection `guardian_runs`, run lookup indexes, and
  TTL. Its `_id` is the claim token. Keep root/result fields small and place
  full evidence only on runs.
- [ ] Make terminal run state immutable through repository methods and tests.
  Publication state remains derived from root pointers rather than copied onto
  the run.
- [ ] Add `guardian_enabled: bool = False` and Helm
  `config.guardianEnabled=false`. Do not remove `impact_engine_mode` yet because
  legacy modules still import it.
- [ ] Extend retention and organization-deletion cleanup to the new
  collections without changing legacy retention behavior.
- [ ] Add BSON serialized-size helpers used by later finalization tests.
- [ ] Add a small raw-PyMongo repository boundary for the pipeline updates and
  `$expr` predicates that Beanie cannot express clearly. Unit-test generated
  filters and updates, including `$$NOW`; do not duplicate lifecycle predicates
  in service code.
- [ ] Prove old and new collections are disjoint and Guardian remains dormant
  when disabled.

**Focused tests:**

```bash
cd backend
uv run pytest tests/test_guardian_contracts.py tests/test_guardian_models.py \
  tests/test_investigation_retention.py -q
```

**Commit:** `feat: add Guardian persistence contracts`

---

## Task 3: Implement change atoms, evidence budgets, ledger, and coverage

**Purpose:** Build the pure deterministic core before adding Mist or model I/O.

**Files:**

- Create: `backend/src/mist_config_guardian_backend/guardian/change.py`
- Create: `backend/src/mist_config_guardian_backend/guardian/evidence.py`
- Create: `backend/src/mist_config_guardian_backend/guardian/ledger.py`
- Modify: `backend/src/mist_config_guardian_backend/services/diff.py`
- Modify: `backend/src/mist_config_guardian_backend/snapshots/canonical.py`
- Test: `backend/tests/test_guardian_change.py`
- Test: `backend/tests/test_guardian_evidence.py`
- Test: `backend/tests/test_guardian_ledger.py`

- [ ] Extract `changed_paths` from the existing redacted diff walker. Return
  tuple segments and an explicit completeness flag; never return values.
- [ ] Reuse one canonical metadata ignore set for snapshot hashing, visible
  diffs, top-level changed fields, and Guardian atoms. Include
  `modified_time`.
- [ ] Build stable atom IDs and preserve masked before/after values only in the
  bounded prompt/report view.
- [ ] Implement segment-aware prefix coverage for obligations and exclusions.
- [ ] Resolve every atom-target row as claimed, atom-and-target-specific
  excluded, or uncovered. Truncated paths always leave the row uncovered.
- [ ] Merge duplicate monitoring obligations and apply the strictest
  `empty_policy`.
- [ ] Add an unsatisfied core `anchor` precondition when only receipt time is
  available.
- [ ] Add deployment preconditions only for devices targeted by at least one
  obligation. Exclusion-only targets receive no deployment precondition.
- [ ] Implement the four-row deterministic coverage table exactly.
- [ ] Add the common evidence registry that assigns stable E-ids to database,
  rule, and MCP evidence.
- [ ] Implement per-source aggregate budgeting and count-only digests. Test
  deterministic priority ordering and prove compaction never changes coverage.
- [ ] Build a worst-case 1,000-device ledger and prove the change,
  deterministic, monitoring, deployment, ledger, conclusion, device, and step
  views fit their assigned budgets.

**Focused tests:**

```bash
cd backend
uv run pytest tests/test_guardian_change.py tests/test_guardian_evidence.py \
  tests/test_guardian_ledger.py -q
```

**Commit:** `feat: add Guardian coverage ledger`

---

## Task 4: Implement monitoring replay and deployment pairing

**Purpose:** Produce deterministic peak/current evidence without using stored
legacy assessments.

**Files:**

- Create: `backend/src/mist_config_guardian_backend/guardian/monitoring.py`
- Create: `backend/src/mist_config_guardian_backend/guardian/deployment.py`
- Modify only if a shared helper is required:
  `backend/src/mist_config_guardian_backend/services/impact_analysis.py`
- Test: `backend/tests/test_guardian_monitoring.py`
- Test: `backend/tests/test_guardian_deployment.py`
- Test fixture: DNT-NTR receipts and monitoring sessions

- [ ] Select expected devices only from audit-linked change events and resolve
  each run's anchor in order: audit event time, earliest audit-linked device
  trigger, then receipt time.
- [ ] Classify sessions as exclusive/shared and terminal/active without
  mutating monitoring records.
- [ ] Evaluate required metric checks using the exact measured/no-data/error
  treatment table.
- [ ] Compute metric peak/current from the monitoring session's recorded
  observations through fixed `as_of`, incident peak/current from incident
  lifetimes, and finding peak/current from comparisons. Compose the three
  independently. Equal before/after windows apply only to Guardian rule and MCP
  queries, not to stored monitoring observations.
- [ ] Normalize provider timestamps at their actual precision.
- [ ] Pair an outcome carrying `audit_id` only to the latest preceding trigger
  for that same audit and device. Apply time fallback to the latest preceding
  trigger within 30 minutes only when the outcome has no `audit_id`.
- [ ] Handle duplicate, conflicting, delayed, receipt-time-only, failed,
  configured, and reverted sequences.
- [ ] Project deployment state separately into obligation status and
  peak/current severity.
- [ ] Add the 242 ms regression and same-second conflict matrix.
- [ ] Verify no shared-session observation contributes a severity floor.

**Focused tests:**

```bash
cd backend
uv run pytest tests/test_guardian_monitoring.py \
  tests/test_guardian_deployment.py -q
```

**Commit:** `feat: replay Guardian monitoring evidence`

---

## Task 5: Add the guarded Reader and structured-output capability

**Purpose:** Put every new external read and provider capability behind one
bounded, tenant-safe path.

**Files:**

- Create: `backend/src/mist_config_guardian_backend/guardian/reader.py`
- Modify: `backend/src/mist_config_guardian_backend/integrations/ai_provider.py`
- Modify: `backend/src/mist_config_guardian_backend/integrations/mist_mcp.py`
- Modify: `backend/src/mist_config_guardian_backend/models/application_configuration.py`
- Modify: `backend/src/mist_config_guardian_backend/schemas/application_configuration.py`
- Modify: `backend/src/mist_config_guardian_backend/services/application_configuration.py`
- Modify: `backend/src/mist_config_guardian_backend/api/routes/application_configuration.py`
- Test: `backend/tests/test_guardian_reader.py`
- Test: `backend/tests/test_ai_provider.py`
- Test: `backend/tests/test_application_configuration.py`
- Test: `backend/tests/test_application_configuration_api.py`

- [ ] Replace the provider's `json_object: bool` with a typed response-format
  contract supporting text, JSON object, and JSON Schema.
- [ ] Probe the exact Guardian action schema and validate returned content, not
  only HTTP acceptance.
- [ ] Store mode, fingerprint, schema version, and test time. Invalidate on
  provider URL, model, or schema-version change.
- [ ] Extend settings responses without exposing API-key material.
- [ ] Implement one Reader budget/reservation API for rule and MCP reads.
- [ ] Validate discovered MCP schemas, reject nonlocal references, inject
  `org_id`, and enforce the frozen tool/discriminator allowlist.
- [ ] Fix site authority at attempt start. Site-scoped investigations never
  expand to another site through org-wide result data.
- [ ] Accept only exact before, after, or combined equal windows; reject
  `duration`. Restrict later current reads to approved snapshot operations.
- [ ] Separate the 1 MB transport cap from 4 KB persisted evidence digests.
- [ ] Cache successful canonical calls only; transient errors remain retryable.
- [ ] Redact before logging, persistence, feedback, and hashing where the hash
  could otherwise expose secret material.

**Focused tests:**

```bash
cd backend
uv run pytest tests/test_guardian_reader.py tests/test_ai_provider.py \
  tests/test_application_configuration.py \
  tests/test_application_configuration_api.py -q
```

**Commit:** `feat: add bounded Guardian reader`

---

## Task 6: Port deterministic rule plug-ins

**Purpose:** Preserve the useful deterministic behavior while deleting its
specialized orchestration and clients.

**Files:**

- Create: `backend/src/mist_config_guardian_backend/guardian/plugins/base.py`
- Create: `backend/src/mist_config_guardian_backend/guardian/plugins/wlan_removal.py`
- Create: `backend/src/mist_config_guardian_backend/guardian/plugins/wlan_auth.py`
- Create: `backend/src/mist_config_guardian_backend/guardian/plugins/switch_port.py`
- Create: `backend/src/mist_config_guardian_backend/guardian/plugins/dns.py`
- Create: `backend/src/mist_config_guardian_backend/guardian/plugins/__init__.py`
- Test: `backend/tests/test_guardian_plugin_wlan.py`
- Test: `backend/tests/test_guardian_plugin_switch_port.py`
- Test: `backend/tests/test_guardian_plugin_dns.py`
- Reuse fixtures from existing impact WLAN, auth, port, neighbor, and AP tests

- [ ] Define a small plug-in protocol with static IDs, versions, max reads,
  bounded agent hints, planning, collection, and evaluation.
- [ ] Enforce both each plug-in's declared `max_reads` and the attempt-wide
  limit of eight rule reads through the Reader reservation API.
- [ ] Port WLAN lifecycle cohort/session semantics and retain the original
  positive-disruption tests.
- [ ] Port authentication before/after semantics, including no-attempts as
  `not_exercised`.
- [ ] Port switch port, PoE, event history, and managed-neighbor evaluation.
- [ ] Route every read through the Reader; plug-ins never call Mist clients
  directly.
- [ ] Keep LLDP neighbor MACs in memory. Persist only a matched managed AP
  identity.
- [ ] Implement only the DNS mappings verified in Task 1. Unknown object/field
  combinations remain uncovered.
- [ ] Require every plug-in claim to account for all handled paths. Mixed nested
  edits leave unhandled paths uncovered.
- [ ] Isolate planning, collection, and evaluation failures into bounded gaps
  without stopping other plug-ins.

**Focused tests:**

```bash
cd backend
uv run pytest tests/test_guardian_plugin_wlan.py \
  tests/test_guardian_plugin_switch_port.py \
  tests/test_guardian_plugin_dns.py -q
```

**Commit:** `feat: port Guardian rule plugins`

---

## Task 7: Implement verdict composition, agent loop, and report builder

**Purpose:** Complete one in-memory attempt without yet scheduling or
publishing it.

**Files:**

- Create: `backend/src/mist_config_guardian_backend/guardian/composition.py`
- Create: `backend/src/mist_config_guardian_backend/guardian/agent.py`
- Create: `backend/src/mist_config_guardian_backend/guardian/report.py`
- Test: `backend/tests/test_guardian_composition.py`
- Test: `backend/tests/test_guardian_agent.py`
- Test: `backend/tests/test_guardian_report.py`

- [ ] Implement the base/floor/agent maximum, confidence, recovery, sources,
  and gap rules as one pure function.
- [ ] Validate all cited IDs, visibility, evidence kind, impacted-device
  identity, severity ordering, and complete coverage for agent `none`.
- [ ] Build the one-call/one-report discriminated action schema.
- [ ] Implement 10 turns, at most 7 calls, and report-only mode for the last 3.
- [ ] Return bounded categorized feedback and preserve one disallowed action,
  one rejected report, and one repair turn.
- [ ] Reject an uncited severity increase, confidence increase, or agreement
  with `none`. Accept an uncited `info` report only as a no-op.
- [ ] Build each prompt from the fixed 48 KB view plus visible rule/MCP payloads.
  Withhold oldest MCP then rule payloads, list each as withheld and non-citable,
  and persist the visibility manifest.
- [ ] Redact and cap stored model output and error details.
- [ ] Skip the agent explicitly when runtime, MCP endpoint, or a matching
  capability record is unavailable.
- [ ] Render every report section from immutable run state. Never invent empty
  section prose or measurement values.
- [ ] Add a worst-case prompt and run-construction test against the 96 KB and
  256 KB limits.

**Focused tests:**

```bash
cd backend
uv run pytest tests/test_guardian_composition.py tests/test_guardian_agent.py \
  tests/test_guardian_report.py -q
```

**Commit:** `feat: add Guardian agent and verdict`

---

## Task 8: Add the fenced orchestrator and worker lifecycle

**Purpose:** Persist, retry, publish, and exhaust attempts safely while the
feature remains disabled by default.

**Files:**

- Create: `backend/src/mist_config_guardian_backend/services/guardian.py`
- Modify: `backend/src/mist_config_guardian_backend/services/webhook_processing.py`
- Modify: `backend/src/mist_config_guardian_backend/tasks/monitoring.py`
- Modify: `backend/src/mist_config_guardian_backend/services/monitoring.py`
- Test: `backend/tests/test_guardian_runtime.py`
- Test: `backend/tests/test_guardian_runtime_mongo.py`
- Test: `backend/tests/test_webhook_ingestion.py`

- [ ] Implement idempotent `ensure` with fixed changed time, retention, and the
  initial `next_check_at=max(worker_now, changed_at)+1 min` scheduling hint.
- [ ] Implement the plain indexed worker-time due query, sorted by
  `next_check_at` and capped at 20 roots. Treat it only as candidate selection;
  every mutation rechecks authoritative conditions with MongoDB `$$NOW`.
- [ ] Before evaluating triggers, recover any expired claim while the root still
  points to its exact token. Stop processing that root after recovery.
- [ ] Implement recovery by claim phase:
  - uncommitted and expired: CAS-clear token plus `attempt=null`;
  - committed and missing/running run: create or mark an immutable abandoned
    run from claim metadata;
  - committed and succeeded run: adopt it through normal publication;
  - committed and failed/abandoned run: publish the failure transition.
- [ ] Implement the lease without consuming an attempt. Its server-time pipeline
  sets a fresh token, a 300-second lease, null attempt/start, and
  `final_forced=($$NOW >= changed_at + 120 min)` for final runs.
- [ ] Revalidate cross-collection conditions under the lease. A final requires
  no active linked session unless `final_forced`; an early requires the
  append-only degradation transition. Release an uncommitted lease on failure.
- [ ] Commit the attempt with one phase-fenced pipeline update: token and null
  attempt, unexpired server lease, waiting status, attempt count below two, and
  for early runs the server-time +45 cutoff and null early pointer. Increment
  once and atomically record attempt, `started_at`, and renewed lease.
- [ ] Never retry an ambiguously acknowledged attempt commit. Read the root:
  continue only when the same token now carries an attempt number; otherwise
  stop.
- [ ] Start the local monotonic deadline immediately before sending the attempt
  commit, then capture fixed wall-clock `as_of` for execution. A slow response
  shortens rather than extends the usable deadline.
- [ ] Treat an early monitoring transition only as a signal; attribution still
  comes from exclusive evidence. After +45 minutes, a failed early commit
  releases its lease and later processing uses the final trigger.
- [ ] End rule collection by +90 seconds, external agent work by +210 seconds,
  and finalization/publication by +240 seconds. Bound each provider/tool call to
  the lesser of 20 seconds and remaining phase time.
- [ ] Run change building, planning, rule collection, replay, pairing, agent,
  composition, finalization, and root CAS in the specified phase windows.
- [ ] Finalize only from `state=running`; a stale worker that loses this update
  never publishes.
- [ ] Publish with a root CAS on the same token, the run's attempt number, and
  waiting status. Set the matching run pointer and result, clear the claim, and
  set final status/reason atomically. Recovery uses this same publication path.
- [ ] Apply every `next_check_at` transition, including failed attempts and
  exhaustion.
- [ ] Run exhaustion only after recovery and only with no claim. Use the last
  final run's recorded failure reason and preserve any published early result.
- [ ] Keep deterministic publication when the agent fails or is skipped.
- [ ] Gate only the new root creation and new worker polling on
  `guardian_enabled` in this intermediate commit. Preserve existing legacy
  gates until Task 11 switches all surfaces atomically.
- [ ] Test every crash boundary and both orders of recovery races, two committed
  attempts missing run inserts, ambiguous commit responses before/after apply,
  worker clock skew, mismatched publication attempts, early lease before +45
  with commit after +45, final revalidation, server-evaluated `final_forced` at
  +119/+120, post-publication idempotence, retry isolation, and final
  exhaustion.

**Focused tests:**

```bash
cd backend
uv run pytest tests/test_guardian_runtime.py tests/test_webhook_ingestion.py -q
MONGO_TEST_URL=mongodb://localhost:27018 uv run pytest \
  tests/test_guardian_runtime_mongo.py -q
```

**Commit:** `feat: orchestrate Guardian investigations`

---

## Task 9: Add Guardian read models and API

**Purpose:** Add the tenant-safe Guardian read path alongside the legacy API so
the frontend can migrate without a broken intermediate commit.

**Files:**

- Create: `backend/src/mist_config_guardian_backend/services/guardian_reads.py`
- Modify: `backend/src/mist_config_guardian_backend/schemas/guardian.py`
- Modify: `backend/src/mist_config_guardian_backend/schemas/change_group.py`
- Modify: `backend/src/mist_config_guardian_backend/schemas/overview.py`
- Modify: `backend/src/mist_config_guardian_backend/schemas/impact.py`
- Modify: `backend/src/mist_config_guardian_backend/api/routes/change_groups.py`
- Modify: `backend/src/mist_config_guardian_backend/services/change_groups.py`
- Modify: `backend/src/mist_config_guardian_backend/services/overview.py`
- Modify: `backend/src/mist_config_guardian_backend/services/site_impact.py`
- Modify: `docs/openapi.json`
- Test: `backend/tests/test_guardian_api.py`
- Test: `backend/tests/test_audit_impact_projection.py`
- Test: `backend/tests/test_overview.py`
- Test: `backend/tests/test_site_impact.py`

- [ ] Project root `guardian` summaries in bounded batches for current views
  only. A failed read returns unavailable, never a clean result.
- [ ] Add
  `GET /organizations/{org}/change-groups/{id}/guardian` with root, published
  runs, rendered reports, and derived attempt publication state.
- [ ] Add
  `GET /organizations/{org}/change-groups/{id}/guardian/runs/{run_id}` for one
  full bounded run, published or not. Verify organization and investigation
  ownership before returning it.
- [ ] Verify organization, change-group, root, run pointer, and run tenant on
  every detailed read.
- [ ] Keep legacy investigation/history/request/adjudication/acceptance routes
  through Task 10 so the old frontend remains deployable.
- [ ] Add `guardian` response fields alongside `shadow_impact` temporarily.
  Guardian projections must not read legacy collections.
- [ ] Feed overview and changes pages from root summaries.
- [ ] Feed site impact from compact published-run device rows and expose omitted
  counts honestly.
- [ ] Keep historical reads free of current Guardian outcomes.
- [ ] Regenerate and verify OpenAPI.

**Focused tests:**

```bash
cd backend
uv run pytest tests/test_guardian_api.py \
  tests/test_audit_impact_projection.py tests/test_overview.py \
  tests/test_site_impact.py -q
uv run python ../scripts/export-openapi.py --check
```

**Commit:** `feat: expose Guardian investigation API`

---

## Task 10: Replace the frontend investigation experience

**Purpose:** Move all current Guardian/shadow UI surfaces onto one badge and one
panel before deleting old backend code.

**Files:**

- Create: `frontend/src/app/core/guardian.model.ts`
- Create: `frontend/src/app/shared/guardian-badge.ts`
- Create: `frontend/src/app/features/changes/guardian-panel.ts`
- Create corresponding component specs
- Modify: `frontend/src/app/core/change-group.model.ts`
- Modify: `frontend/src/app/features/changes/changes-page.ts`
- Modify: `frontend/src/app/features/impact/site-impact.model.ts`
- Modify: `frontend/src/app/features/impact/site-impact.service.ts`
- Modify: `frontend/src/app/features/impact/site-impact-page.ts`
- Modify: overview components consuming change-group summaries
- Delete the superseded components listed in the design after replacement tests pass

- [ ] Model waiting, done-with-result, done-without-result, unavailable, early,
  final, recovered, and omitted-device states explicitly.
- [ ] Show one Guardian badge without changing legacy production severity
  filters or notifications.
- [ ] Render Early and Final tabs, deterministic and AI summaries, coverage,
  devices, findings, evidence, gaps, and collapsed attempts.
- [ ] Load full attempt steps, rejections, and visible/withheld evidence IDs
  lazily from the run endpoint when an attempt is expanded.
- [ ] Label AI text and incomplete/early results unambiguously.
- [ ] Render omitted device counts without implying omitted identities belong to
  the selected site.
- [ ] Replace every `shadow_impact` consumer and remove dead component imports.
- [ ] Update the changes-page disclaimer.
- [ ] Add component tests for pending, none, info, warning/recovered, exhausted
  final with an early result, withheld evidence, and omitted devices.

**Focused tests:**

```bash
cd frontend
npm test -- --watch=false
npm run build
```

**Commit:** `feat: add Guardian investigation UI`

---

## Task 11: Remove the legacy engine and add cleanup tooling

**Purpose:** Delete the duplicate architecture only after the replacement is
green end to end.

**Files:**

- Delete the backend impact, service, model, schema, route, integration, test,
  and frontend files enumerated in the design
- Create: `scripts/drop-legacy-impact-collections.py`
- Modify: `backend/src/mist_config_guardian_backend/models/__init__.py`
- Modify: `backend/src/mist_config_guardian_backend/api/routes/change_groups.py`
- Modify: `backend/src/mist_config_guardian_backend/config.py`
- Modify: `backend/src/mist_config_guardian_backend/worker.py`
- Modify: Helm values, questions, config map, README, release documentation
- Modify: `docs/design/guardian.md`
- Modify: `docs/openapi.json`
- Test: `backend/tests/test_drop_legacy_impact_collections.py`

- [ ] Port every still-used helper before deleting its source. Search imports
  after each deletion batch.
- [ ] Remove `impact_engine_mode` and its Helm enum only now; retain
  `guardian_enabled=false`.
- [ ] Switch webhook ingestion, worker polling, change projections, site impact,
  and legacy monitoring-AI suppression to the boolean in the same commit.
- [ ] Remove legacy document models from Beanie registration.
- [ ] Remove old routes, `shadow_impact` fields, and schemas, then regenerate
  OpenAPI.
- [ ] Remove old frontend components and models not already deleted in Task 10.
- [ ] Implement an explicit, idempotent cleanup command that drops only the five
  named legacy collections: `impact_investigations`,
  `investigation_revisions`, `impact_model_request_artifacts`,
  `impact_adjudications`, and `neighbor_bindings`. It must never run at startup.
- [ ] Require an explicit operator invocation and print the collections affected.
- [ ] Update retention tasks, Celery includes, Docker Compose, Helm, README, and
  release notes.
- [ ] Replace superseded Guardian design docs with `docs/design/guardian.md`;
  retain monitoring and site-workspace documentation.
- [ ] Assert no production source imports deleted modules and no configuration
  surface references `impact_engine_mode` or `shadow_impact`.

**Focused validation:**

```bash
if rg -n "impact_engine_mode|shadow_impact|ImpactInvestigation|InvestigationRevision|ModelRequestArtifact" \
  backend/src frontend/src helm README.md; then
  echo "legacy impact references remain"
  exit 1
fi
cd backend
uv run pytest tests/test_drop_legacy_impact_collections.py \
  tests/test_guardian_runtime.py tests/test_guardian_api.py -q
uv run python ../scripts/export-openapi.py --check
```

**Commit:** `refactor: remove legacy impact engine`

---

## Task 12: Run replay, release, and full validation gates

**Purpose:** Prove the replacement outcome and deployment artifacts before
enabling it anywhere.

**Files:**

- Test: `backend/tests/test_guardian_replay.py`
- Modify: release documentation and `docs/design/guardian.md`
- Modify generated OpenAPI only if the check detects drift

- [ ] Replay the recorded DNT-NTR audit through the production orchestrator with
  fake provider/MCP boundaries and real domain functions.
- [ ] Assert the verified mapping's exact as-recorded and configured outcomes,
  plus the invariant deployment and obligation checks.
- [ ] Exercise provider absent, MCP absent, plugin failure, model failure,
  deadline, retry, and final-exhaustion paths.
- [ ] Run the worst-case size and prompt-budget construction.
- [ ] Run tenant-isolation API tests and secret-regression scans.
- [ ] Render Helm once with Guardian disabled and once enabled.
- [ ] Keep chart/default activation disabled after all tests.

**Full backend gate:**

```bash
cd backend
uv run ruff format --check .
uv run ruff check .
uv run ty check src
MONGO_TEST_URL=mongodb://localhost:27018 uv run pytest
uv run python ../scripts/export-openapi.py --check
```

**Full frontend gate:**

```bash
cd frontend
npm test -- --watch=false
npm run build
npx playwright test
```

**Helm gate:**

```bash
helm lint helm/mist-config-guardian
helm template guardian helm/mist-config-guardian \
  --set config.guardianEnabled=false >/dev/null
helm template guardian helm/mist-config-guardian \
  --set config.guardianEnabled=true >/dev/null
```

**Final inspection:**

```bash
git status --short
git diff --check
```

**Commit:** `test: validate Guardian simplification`

## Completion criteria

- Guardian is disabled by default and can be enabled with one boolean.
- One audit creates at most one early and one final publication, with one retry
  each and claim-token-safe recovery.
- No stale or abandoned attempt can publish.
- Monitoring, deployment, rules, and the agent remain separately inspectable.
- `none` requires complete deterministic coverage.
- Shared sessions, missing deployment, unknown mappings, truncation, and errors
  cannot become clean outcomes.
- The agent has a bounded, visible evidence view and one report-repair chance.
- Root, run, prompt, evidence, and external-call budgets pass worst-case tests.
- Current API/UI surfaces use `guardian`; legacy impact code and collections are
  absent from runtime.
- Production monitoring verdicts, badges, and notifications are unchanged.
- Backend, frontend, OpenAPI, Helm, replay, tenant, and secret gates are green.
