# Guardian: a simpler, trustworthy audit impact investigation

Status: approved
Date: 2026-09-16

## Problem

Guardian is the audit-level impact investigation that runs next to per-device
monitoring (today `IMPACT_ENGINE_MODE=agent_shadow`). It does not produce
trustworthy results, and it has become too complicated to fix in place.

A production audit shows both problems. A network template `dns_servers` edit at
site DNT-NTR reached 7 devices. Monitoring watched all of them for an hour and
found nothing beyond noise. Guardian published `insufficient_evidence`, and
that result came from the rule engine's default. Guardian found nothing:

1. **It never saw the monitoring results.** The investigation reads no monitoring
   session metrics. The rule engine covers only WLAN removal/auth and switch
   port/PoE, so a DNS change produced no targets, no checks and no playbook. The
   agent had no device list and ran two org-wide `dns_failure` searches that
   returned zero rows.
2. **The agent could not legally conclude.** It tried to report "no impact" in
   all three runs. The validator correctly required complete, cited evidence,
   and nothing the agent could collect met that bar.
3. **Every rejection landed on the last available call.** Runs at +10/+30/+60 min
   shared 21 model calls (8 + 8 + 5). The final run had 5 calls, wasted 2 on
   malformed actions, and got its report rejected on call 5. The budget guard then
   refused call 6. Runs that did not conclude discarded their evidence. 11 of the
   21 calls produced nothing.
4. **Correctness bugs.** A 242 ms boundary compared second-precision device events
   against a millisecond `changed_at`, so all 7 devices showed as deployment
   "unknown". `modified_time` counted as a changed field. `policy_version:
   wlan-removal.v1` was a field default. `stop_reason` stayed empty at expiry.
   Report section explanations were fixed strings.

Complexity makes all of this hard to fix. Guardian is about 7,000 lines of Python.
On top of that come about 1,000 lines of rule-only Mist clients, about 1,300
lines of frontend and about 8,000 lines of tests. The parts overlap:

- a rule engine;
- a retired fixed-menu agent, kept only to read old records;
- the MCP agent, with schedule bands, carried conclusions and a five-step
  prompt-trimming ladder;
- two dispatch journals and two budgets;
- two change-context builders and two impact projections;
- an acceptance replay that rejects every MCP investigation.

## Goals

- Publish a trustworthy verdict per audit, including a trustworthy `none`.
- Make monitoring first-class evidence, and use deterministic rules as plug-ins
  so new rules are easy to add.
- Give the agent a real chance to conclude: its own budget per attempt, a
  guaranteed chance to repair a rejected report, and evidence handed to it up front.
- Keep the core KISS/DRY. The remaining complexity sits in three deterministic,
  table-tested functions: coverage, monitoring replay and deployment pairing.

## Non-goals

- Backward compatibility. Existing Guardian records, endpoints and settings are
  dropped. They are shadow evaluation data only.
- Changing the monitoring subsystem, its verdicts, badges or notifications.
  Production consumers stay on the legacy monitoring assessment.
- Confirming deployment by reading device configuration. This is a possible future
  plugin, see "Verification items".

## Settled decisions

| Decision | Choice |
|---|---|
| Architecture | Monitoring + deployment + rule plug-ins + MCP agent; no schedule bands or carried conclusions |
| Agent runs | One early run on a monitoring degradation signal (merged into the final run after +45 min) and one final run; attribution is decided inside the run |
| Clean verdict | `none` needs complete deterministic coverage; the agent alone cannot establish it |
| Monitoring-backed `none` | Allowed, at low confidence (medium when the agent concurs with cited service-health evidence) |
| Persistence | Small root per audit plus one document per attempt; claim-token fencing |
| Old data | New collection names; old collections removed by a separate idempotent command |
| Activation | `guardian_enabled: bool` replaces `impact_engine_mode`; off by default |
| Structured output | Capability detected at setup time and bound to a fingerprint; no runtime fallback |

## Architecture

```text
audit webhook ──► guardian_investigations (waiting)
                          │  one-minute worker tick
                          ▼
                 due? early / final ──► claim (token, lease)
                          │
                          ▼  one attempt, monotonic deadline
   ChangeSet ─► plugins.plan ─► ledger ─► plugins.collect (Reader)
        │                                     │
        │      monitoring replay ◄────────────┤
        │      deployment pairing ◄───────────┤
        ▼                                     ▼
  deterministic conclusion ─────────► agent (MCP via Reader)
                          │
                          ▼
                 compose verdict ─► finalize guardian_runs doc ─► CAS publish root
```

## Activation and rollout

- `guardian_enabled: bool = False` (Helm `config.guardianEnabled`) replaces
  `impact_engine_mode`. It maps one-to-one onto every current
  `impact_engine_mode != "legacy"` gate:
  - webhook ingestion ([webhook_processing.py:95](../../../backend/src/mist_config_guardian_backend/services/webhook_processing.py));
  - the worker tick ([tasks/monitoring.py:32](../../../backend/src/mist_config_guardian_backend/tasks/monitoring.py));
  - change-group projections;
  - site impact;
  - skipping the legacy per-session monitoring AI assessment.
- Guardian is not always on. When enabled, external spend per audit is bounded by
  2 runs × 2 attempts × (10 model turns + 7 MCP calls + 8 rule reads), plus one
  MCP catalogue discovery per attempt. Release notes state this bound.
- New code reads and writes only `guardian_investigations` and `guardian_runs`.
  The old collections (`impact_investigations`, `investigation_revisions`,
  `impact_model_request_artifacts`, `impact_adjudications`, `neighbor_bindings`)
  are never touched by new code. A separate idempotent command,
  `drop-legacy-impact-collections`, removes them; release notes say to run it
  after rollout. Retention cleanup targets only the new collections.

## Persistence

### `guardian_investigations` (root, small, one per audit)

| Field | Meaning |
|---|---|
| `organization_id`, `audit_id` | Identity, unique together |
| `changed_at`, `anchor_known` | Audit time from the audit payload; receipt time with `anchor_known=false` when absent. Used for trigger timing; each run resolves its own anchor (see "Attempt execution") |
| `status` | `waiting` or `done` |
| `status_reason` | Always set when `done` |
| `next_check_at` | When the tick next evaluates triggers |
| `claim` | `{token, kind, lease_until, attempt, started_at, final_forced}` or null; `attempt` and `started_at` stay null until the attempt is committed, and then suffice to rebuild the attempt record; `final_forced` is the server-evaluated +120 min branch |
| `attempts` | `{early: int, final: int}` |
| `early_run_id`, `final_run_id` | Published run pointers |
| `result` | Published summary (below), null while pending |
| `retained_until`, timestamps | Retention |

`result`:
- `run_id`, `run_kind`, `evaluated_at`;
- `peak`, `current` (`none|info|warning|critical`) and `recovery`
  (`none|recovered|unrecovered`);
- `confidence` (`low|medium`) and `coverage`
  (`complete|partial|insufficient|not_applicable`);
- `sources`;
- `impacted_devices`, capped at 20, plus `impacted_device_count`;
- `summary`.

### `guardian_runs` (one document per attempt)

| Field | Meaning |
|---|---|
| `_id` | The claim token |
| `organization_id`, `investigation_id`, `audit_id` | Tenant-safe lookup and cleanup |
| `kind`, `attempt` | `early|final`, 1-based |
| `state` | `running`, `succeeded`, `failed`, `abandoned` |
| `started_at`, `finished_at`, `deadline_at` | Timing |
| `failure_reason` | Set when `failed` or `abandoned` |
| `change` | ChangeSet atoms, including `ChangedPaths.complete` |
| `evidence` | Evidence envelopes, in E-id order |
| `ledger`, `obligations` | Rows and statuses |
| `monitoring`, `deployment`, `rules`, `agent` | Separately retained conclusions |
| `verdict` | Composed result |
| `steps` | Agent turns and calls (see "Agent") |
| `budget` | Model turns, MCP calls and rule reads used |
| `retained_until`, timestamps | Retention |

The report is not stored. One pure builder renders it from the run on read.

A run document is immutable once terminal (`succeeded`, `failed`, `abandoned`).
Its size is bounded by construction: every source has an aggregate byte budget
and degrades to a count-only digest that always fits (see "Limits"). The budgets
sum below the run-document bound. A serialized-size assertion checks that
construction in tests and at finalization. It can fire only on a bug, never on a
large audit.

Whether a run is published is **derived, not stored**: a run is published if and
only if the root points to it.

### Claim, execution, publication

Nothing uses transactions. Each step is one conditional update. Every root update
that touches a claim filters on that exact token **and on the claim's phase**
(uncommitted: `claim.attempt` null; committed: `claim.attempt` equals the run's
attempt), so no two transitions can both apply to the same claim. A crash between
any two steps leaves a state that the next tick can finish.

**One clock for root time.** Every temporal predicate and assignment in a root
CAS uses MongoDB's `$$NOW` through `$expr` filters and pipeline updates
(MongoDB 8). That covers:
- comparisons: `next_check_at`, lease expiry, the early cutoff, the final minimum,
  and the forced-final threshold;
- assignments: `next_check_at` (retry and idle delays), `lease_until`,
  `started_at`, `claim.final_forced`.

Examples are `$claim.lease_until > $$NOW` and `lease_until = $$NOW + 300 s`.
"Unexpired" at commit, "expired" at recovery, "before +45 min" and "forced at
+120 min" are therefore judged on one clock, whatever the workers' clock skew or
pauses.

Worker time is used only for non-authoritative hints that a server-time CAS
re-checks:
- **read-only trigger evaluation;**
- **the due query:** a plain indexed query on `(status, next_check_at)` for
  candidate selection;
- **the initial `next_check_at`** written by the webhook's `$setOnInsert` upsert.
  `$$NOW` isn't available in a classic update, and an insert-then-pipeline split
  could crash and leave a root that is never selected. Skew only shifts the first
  check, because the lease CAS compares `next_check_at <= $$NOW`.

Branches of the trigger rule that change what revalidation requires are recorded
in the lease on server time, never taken from the worker's evaluation.

Local phase deadlines stay monotonic. Their clock starts from a monotonic
timestamp taken just before the commit is sent, so they always end before the
server-side lease that the commit sets.

**Tick procedure** for one root selected by the due query (below):

1. **Resolve an expired claim** first, while the root still holds it (see "Claim
   recovery"). The tick then stops for this root, and the next tick continues from
   the resolved state.
2. **Exhaust** if `attempts.final == 2` and `final_run_id` is null. A CAS on
   `claim` null and `status=waiting` sets `status=done`, `next_check_at=null` and
   `status_reason="Final run failed after 2 attempts: <failure_reason of the last
   final run>"`. That run always exists, because recovery runs first. `result`
   keeps the early result if one exists, and its `run_kind=early` tells the UI to
   show it as an early assessment.
3. **Evaluate triggers** read-only (see "Triggers"). If nothing is due, a CAS on
   `claim` null sets `next_check_at = $$NOW + 1 min`.
4. **Lease.** A CAS on `status=waiting`, `claim` null, `next_check_at <= $$NOW`,
   `attempts.<kind> < 2` and the root-local trigger conditions for the kind:
   - `early`: `early_run_id` null and `$$NOW < changed_at + 45 min`;
   - `final`: `$$NOW >= changed_at + 60 min`.

   It sets `claim={token: new ObjectId, kind, lease_until: $$NOW + 300 s, attempt:
   null, started_at: null, final_forced}`. For `final`, `final_forced = ($$NOW >=
   changed_at + 120 min)`; for `early` it is `false`. No attempt is consumed yet.
5. **Revalidate** the kind's cross-collection trigger conditions under the lease,
   using the branch recorded in the claim. `final` requires no `active` linked
   session unless `claim.final_forced` is true; `early` requires the degradation
   transition.
   If they no longer hold, the worker **releases** the lease, and no attempt is
   consumed. The release is a CAS on `claim.token == token` and `claim.attempt`
   null that sets `claim=null` and `next_check_at = $$NOW + 1 min`. It is
   idempotent with an uncommitted recovery of the same token.
6. **Commit the attempt.** A CAS on all of:
   - `claim.token == token` and `claim.attempt` null;
   - `$claim.lease_until > $$NOW`;
   - `status=waiting` and `attempts.<kind> < 2`;
   - for `early`, also `$$NOW < changed_at + 45 min` and `early_run_id` null.

   It increments `attempts.<kind>` and sets `claim.attempt = attempts.<kind> + 1`,
   `claim.started_at = $$NOW` and `claim.lease_until = $$NOW + 300 s`. The attempt
   deadline is measured from a monotonic timestamp taken just before the commit is
   sent.
   - **No match:** the worker issues the release CAS from step 5 and stops. If the
     claim was still uncommitted (the early cutoff passed during a pause, the lease
     expired, or attempts ran out), the release frees it without incrementing, and
     a later tick proceeds with the final trigger. If recovery already cleared it,
     the release matches nothing.
   - **Ambiguous response** (timeout or connection error after sending): the
     worker never retries the update. It reads the root instead. The commit
     applied if `claim.token == token` and `claim.attempt` is not null, and the
     worker continues with that attempt; otherwise it stops. A retry therefore
     can't increment the counter twice, and a lost commit can't run unrecorded.
7. **Create the run** with `_id=token`, `state=running`, from the claim. If the
   insert hits a duplicate key, recovery has already resolved this token, and the
   worker stops.
8. **Execute** within the attempt deadline.
9. **Finalize** the run to `succeeded` or `failed` with a conditional update on
   `_id == token` and `state == running`. This happens before publication, so the
   root never points at a non-terminal run. If nothing matches, recovery has
   already marked it `abandoned`, and the worker stops without publishing.
10. **Publish** (below).

**Publication** is a CAS on `claim.token == token`, `claim.attempt == run.attempt`
and `status=waiting`. It always clears `claim` and is idempotent: the worker and a
recovering tick may both try it for the same run, and at most one matches.
- **A `succeeded` run:** set the kind's run pointer and `result`. For `final`, also
  set `status=done`, `status_reason` and `next_check_at=null`; for `early`, set
  `next_check_at = $$NOW + 1 min`.
- **A `failed` run:** set no pointer, leave `result` unchanged, and set
  `next_check_at = $$NOW + 1 min`. The run's `failure_reason` stays visible through
  the attempt summaries.
- **A failed CAS** leaves the terminal run unpublished, which is derived as
  superseded.

Every external call (rule read, MCP call, provider request) starts only if the
local monotonic clock is before its phase deadline. The phase deadline is always
before the lease end. A lease is taken over only after it expires and its token is
resolved, so a live local lease implies the token still matches, and no database
read is needed per call.

### Claim recovery

An expired claim `T` is resolved while the root still holds it. Only the final
step clears or replaces it, and always with a CAS on `claim.token == T`. A
recovering worker that crashes midway leaves `T` on the root for the next tick.

1. **Uncommitted** (`claim.attempt` null): no attempt was consumed. A CAS on
   `claim.token == T`, `claim.attempt` null and `$claim.lease_until <= $$NOW` clears
   the claim.
   - If a stale worker's commit wins first, `claim.attempt` is set, the clear
     matches nothing, and the next tick sees a live, committed lease.
   - If the clear wins first, the stale commit matches nothing, and the worker
     stops. Either way, no consumed attempt loses its claim metadata.
2. **Committed** (`claim.attempt == n`, `$claim.lease_until <= $$NOW`): read run `T`
   and act on its state. Run states only move from `running` to terminal, so at
   most two passes are needed. The closing publication or clear filters on
   `claim.token == T` and `claim.attempt == n`.

| Run `T` | Action |
|---|---|
| missing | insert an `abandoned` run from the claim (kind, attempt, `started_at`, reason "Lease expired before the attempt finished"); on a duplicate key, read it again |
| `running` | conditional update to `abandoned` with the same reason; if nothing matches, read it again |
| `succeeded` | publish it exactly as its worker would have |
| `failed` or `abandoned` | publish it as a failed run: clear the claim and set `next_check_at = $$NOW + 1 min` |

A succeeded run whose worker paused before publication is therefore adopted, never
discarded. Every committed attempt ends with a terminal run record.

### Scheduling transitions

| Event | Root update |
|---|---|
| Audit webhook (`ensure`, upsert with `$setOnInsert`) | `status=waiting`, `next_check_at = max(worker now, changed_at) + 1 min` (a hint; see "One clock for root time") |
| Nothing due | `next_check_at = $$NOW + 1 min` (CAS on `claim` null) |
| Lease | `claim` set with `attempt` null and `final_forced` evaluated on `$$NOW`; `next_check_at` unchanged |
| Revalidation fails, or commit matched nothing | `claim=null`, `next_check_at = $$NOW + 1 min` (release CAS on token, `attempt` null) |
| Attempt committed | `attempts.<kind>` incremented; `claim.attempt`, `claim.started_at`, `claim.lease_until` set (CAS on token, `attempt` null, lease unexpired by `$$NOW`, `status=waiting`, attempts below 2; early also `$$NOW` before +45 min) |
| Early published, succeeded or failed | `claim=null`, `next_check_at = $$NOW + 1 min` |
| Final succeeded | `claim=null`, `status=done`, `status_reason`, `next_check_at=null` |
| Final failed with attempts left | `claim=null`, `next_check_at = $$NOW + 1 min` |
| Final exhausted | `status=done`, `status_reason`, `next_check_at=null` (CAS on `claim` null) |
| Uncommitted claim recovered | `claim=null` (CAS on token, `attempt` null, lease expired by `$$NOW`) |
| Crash, lease loss | no root update; `next_check_at` is already due, so the next tick after `lease_until` resolves the claim |

The due query is `status=waiting`, `next_check_at <= worker now`, and `claim` null
or `claim.lease_until <= worker now`, sorted by `next_check_at`, limit 20. It is a
plain query that uses the `(status, next_check_at)` index and only selects
candidates. A candidate picked early by a fast worker clock fails the server-time
CAS and is skipped until a later tick. Every claim-changing step re-checks its own
conditions.

### Indexes

| Collection | Index | Purpose |
|---|---|---|
| `guardian_investigations` | unique `(organization_id, audit_id)` | Identity, `ensure` upsert, change-group reads |
| `guardian_investigations` | `(status, next_check_at)` | Due-claim lookup |
| `guardian_investigations` | TTL `retained_until` (partial: field exists) | Retention |
| `guardian_runs` | `(organization_id, investigation_id, kind, attempt)` | Tenant-safe reads and attempt summaries |
| `guardian_runs` | TTL `retained_until` (partial: field exists) | Retention |

### Retention

Both collections carry `retained_until`, derived from the organization's
`monitoring_retention_days` as today. The existing retention job and
organization-deletion cleanup switch to the two new collections.

## Triggers

The one-minute worker tick evaluates up to 20 `waiting` investigations with
`next_check_at <= now`. Linked sessions are `monitoring_sessions` whose
`audit_ids` contains the audit.

| Kind | Due when |
|---|---|
| `final` | `now >= changed_at + 60 min` and no linked session is `active`; or `now >= changed_at + 120 min` |
| `early` | no early run published, early attempts not exhausted, `now < changed_at + 45 min`, and a linked session has an `ASSESSMENT_WARNING` or `ASSESSMENT_CRITICAL` timeline transition at or after `changed_at` |

- `final` wins when both are due, so an early degradation after +45 min
  merges into the final run.
- **Root-local conditions** (time, attempts, `early_run_id`) are repeated in the
  lease CAS, and the early cutoff again in the commit CAS, all on server time.
- **Cross-collection conditions** (linked-session transitions and activity) are
  revalidated under the lease before the attempt is committed. Whether the final
  is forced past +120 min comes from `claim.final_forced`, which is set on server
  time. The early signal is
  an append-only timeline transition, so it can't become false once seen. The final
  run's "no linked session is `active`" can, when a late device event opens a new
  session. Revalidation narrows that window to the lease step; a session opening
  after revalidation leaves its devices `unsatisfied` ("monitoring still active").
- One claim at a time: a final run waits while an early attempt holds the lease.
- Early and final attempts are counted separately. An exhausted early run never
  blocks or consumes the final run.
- The timeline transitions are used only as a trigger. They were computed with
  `legacy_all` and never feed the verdict.
- If nothing is due, `next_check_at = $$NOW + 1 min`. The table above is the read-only
  evaluation, where `now` is the worker clock; the CAS steps re-check it on server time.

## Attempt execution

**Evidence instant.** An aware wall-clock `as_of` is captured once when attempt
execution starts. Monitoring, deployment, rule and MCP windows use that fixed
instant throughout the attempt; later phases never move the evidence boundary.

**Anchor.** Each run resolves the change time used by every window in this
specification (written `changed_at` in formulas):
1. `source=audit`: the audit payload's event time (`anchor_known=true`);
2. `source=device_trigger`: otherwise, the earliest occurrence time of a
   `*_CONFIG_CHANGED_BY_USER` event carrying this `audit_id`;
3. `source=receipt`: otherwise, the audit receipt time.

`source=receipt` adds a core `anchor` precondition, "change time is unknown", which is
always unsatisfied. Coverage can't be `complete`, so a receipt-anchored run can
never publish `none`. The anchor and its source are stored on the run.

**Deadline.** The attempt deadline is measured on the local monotonic clock,
starting from a monotonic timestamp taken just before the attempt commit (tick
step 6) is sent. A slow or ambiguous commit response only shortens the remaining
time; it never extends past the lease:

| Phase | Ends at | External calls |
|---|---|---|
| Build change set, plugin plans, ledger | — | none |
| Rule collection | +90 s | rule reads |
| Monitoring replay, deployment pairing, deterministic conclusion | — | none (database reads only) |
| Agent | +210 s | MCP calls, provider requests |
| Compose, finalize, publish | +240 s | none |

- Every provider and tool call timeout is `min(20 s, phase deadline − now)`. The
  final 30 seconds make no external calls. The 300 s lease leaves a 60 s margin.
- **Failure isolation:** a plugin exception or timeout produces error evidence,
  leaves that plugin's obligations `unsatisfied`, adds a gap, and lets other
  plugins and the agent continue. A monitoring or deployment phase that fails
  adds an unsatisfied core observation of its own, because such a phase may own
  no planned obligation at all: coverage therefore never reads `complete` over a
  phase that did not run, and the agent's deterministic view is told so before it
  reasons. An agent failure (provider, MCP, deadline)
  records the reason and the attempt still composes a deterministic verdict.
  Only failures in change-set construction, the ledger, composition or
  persistence invariants fail the attempt.
- The agent is skipped with an explicit reason when:
  - no AI runtime is configured;
  - `MIST_MCP_URL` is unset;
  - no valid structured-output capability record exists for the current
    fingerprint.

## Change model

- **`ChangeAtom`** `A<n>` = (logical object, version, top-level functional
  attribute), with `paths: tuple[tuple[str, ...], ...]` and `paths_complete: bool`.
- A pure helper extracted from the diff walker in `services/diff.py` returns
  `changed_paths(before, after, ignored) -> ChangedPaths(paths, complete)`. It
  returns paths only, never values. `complete=False` when the walker's 5,000-entry
  cap truncated.
- Metadata fields (`DEFAULT_IGNORED_FIELDS`: `created_time`, `modified_time`,
  `last_seen`) never form atoms or paths. The same exclusion is applied where
  `changed_top_level_fields` feeds versions today, fixing `modified_time` noise.
- Path prefix matching is segment-aware (tuple prefixes), so `ports[1]` never
  covers `ports[10]`.
- **Applicable targets** of an atom:
  - for an org- or site-level object: the expected devices (see "Monitoring");
  - for a device object: that device.
- One secret-safe `ChangeSet` builder replaces `change_context.py` and
  `mcp_context.py`. It serves the ledger, the prompt (masked values) and the report.

## Evidence

```text
Evidence
  id              E<n>, assigned by the server when the call is reserved; never renumbered
  source          monitoring | deployment | rule:<plugin> | mcp:<tool>
  kind            service_health | deployment | configuration | reference   (server-owned)
  title, captured_at, window {start, end} | null, scope {site_ids, device_macs}
  collection      complete | partial | error
  representation  full | digest        # digest counts are computed from the full validated result
  payload         within its source budget (see "Limits"), validated by a typed model per source; MCP payloads stay generic
  detail          error text or what the digest omitted
```

- Evidence is citable when `collection != error`. Agent citations must also be
  visible in the turn's evidence view (see "Agent"). Server-side rule conclusions
  have no view restriction.
- `kind` is assigned by the server: monitoring → `service_health`, deployment →
  `deployment`, rule reads → declared by the plugin per read. MCP results come
  from an explicit table keyed by tool and, for multi-purpose tools, the
  discriminating argument (for example `search_type`). Events, statistics, SLE,
  insights and operational searches are `service_health`; configuration and
  schema reads are `configuration`; constants and documentation are `reference`.
  A tool or argument combination missing from the table is not allowlisted.
- **Monitoring evidence:** full per-device items are added in priority order
  (severity of warning or above, then unsatisfied obligations, then the rest)
  until the aggregate monitoring budget is reached. Every remaining device goes
  into one digest item with counts per treatment. Coverage is always evaluated
  over all devices. Full items show each required check's before and after state
  and values, its treatment, session exclusivity and the deployment treatment,
  kept separate from exclusivity.
- **Impacted devices** are kept separately on the verdict as compact rows (`mac`,
  `site_id`, `name`, `peak`, `current`), up to the impacted-devices budget, plus an
  omitted count. The site overlay filters these rows by site and shows the omitted
  count.
- **Deployment evidence:** one item. Devices whose precondition is unsatisfied or
  that carry a deployment warning get full rows (trigger, outcomes, correlation,
  peak and current state); the rest are counted in the same item's digest.
- A raw MCP response above the 1 MB transport bound, or one that fails validation
  before it can be digested, is `collection=partial` or `error` and cannot
  satisfy an obligation.

## Reader (the single path for external reads)

Rule reads and MCP calls pass through one guard that does all of the following:
- checks the phase deadline;
- charges the per-attempt budget (the plugin's `max_reads`, a total of 8 rule
  reads, 7 MCP calls);
- assigns the E-id at reservation;
- enforces the organization;
- redacts secrets;
- bounds and digests the result into an `Evidence`.

MCP calls additionally require all of the following:
- **Tool allowlist:** the tool (and argument discriminator) is in the read-only
  allowlist.
- **Schema:** arguments validate against the discovered MCP input schema.
- **Organization:** `org_id` is injected by Guardian, and any other organization
  is rejected.
- **Site:** the initial scope is fixed from expected devices and changed objects.
  - A site-scoped change can never gain another site merely because an org-wide
    result mentioned it.
  - Evidence may add devices or services only inside an already-authorized site.
  - An explicitly org-scoped change may use organization scope, but every result
    still passes the organization boundary and the normal result and budget limits.
- **Time:** a historical time range must equal exactly `before`, exactly `after`,
  or their combined interval. `duration = min(60 min, as_of − changed_at)`,
  `before = [changed_at − duration, changed_at]`, and `after = [changed_at,
  changed_at + duration]`, all given to the agent as epoch seconds. `duration`
  arguments are rejected. Current state after the window is read through
  snapshot tools that take no time range.
- **Transport:** the response is valid JSON, within the transport bound, and is
  normalized with bounds.

Only successful MCP results are cached, keyed by (tool, canonical arguments), and a
cache hit returns the existing E-id at no budget cost. A failed call can be
retried.

## Rule plug-ins

```python
class RulePlugin(Protocol):
    id: str
    version: str
    max_reads: int
    agent_hint: str                       # optional guidance shown to the agent

    def plan(self, change: ChangeSet, devices: list[ExpectedDevice]) -> RulePlan | None: ...   # None: not applicable
    async def collect(self, plan: RulePlan, reader: Reader) -> list[Evidence]: ...
    def evaluate(self, plan: RulePlan, evidence: list[Evidence]) -> RuleConclusion: ...
```

```text
RulePlan
  obligations     [Obligation]          # rule observations and monitoring observations
  exclusions      [Exclusion]
  incident_types, finding_kinds          # relevant to monitoring replay for its targets

Obligation   id O<n>, owner, change_ref A<n>, paths (prefixes), role, kind, target, metric?, empty_policy?
Exclusion    owner, change_ref A<n>, paths (prefixes), target, reason
role         precondition | observation
kind         anchor | deployment | monitoring | rule     # anchor and deployment are core-owned preconditions
target       {device_mac?, site_id?, port_id?, wlan_id?}
empty_policy not_exercised | incomplete            # monitoring observations only

RuleConclusion
  statuses        {obligation_id: Status}          # for its own rule obligations
  peak, current, findings [(text, severity, evidence_ids)],
  impacted_devices [(mac, severity, evidence_ids)], gaps
Status            satisfied | not_exercised | unsatisfied(reason), evidence_ids
```

- `satisfied` always means the target is fully covered. Partial target coverage is
  `unsatisfied` with a reason (for example "3 of 5 ports").
- The server validates every `RuleConclusion` exactly like an agent report:
  - cited IDs exist and are citable;
  - `current <= peak`;
  - each impacted device's MAC appears in a cited evidence item's scope or rows.
    This allows devices outside the expected set, such as a neighbor AP.
- A plugin with no rule reads (such as `dns`) emits only monitoring obligations.
  Its `collect` and `evaluate` return nothing, and it never claims rule coverage it
  did not collect.

### Initial plug-ins

| Plug-in | Applies to | Obligations | Ported from |
|---|---|---|---|
| `wlan-removal` | Site WLAN deleted or disabled | Client sessions for the WLAN, before vs after (2 reads) | `impact/wlan_removal.py`, `integrations/mist_wlan_evidence.py` |
| `wlan-auth` | WLAN authentication attributes | Auth success/failure events, before vs after; `not_exercised` with no attempts | `integrations/mist_auth_evidence.py`, `impact/domain_evaluation.py` |
| `switch-port` | `port_config` / `port_config_overwrite` `disabled`, `poe_disabled` paths | Port snapshot, port events, managed neighbor AP state | `impact/port_scope.py`, `impact/domain_evaluation.py`, `integrations/mist_port_*.py`, `mist_neighbor_evidence.py`, `mist_ap_evidence.py` |
| `dns` | DNS attributes, per object type | Monitoring observations only (see below) | new |

- Semantics are ported from the current modules and their tests, which are then
  deleted. The six-class evidence-client inheritance chain collapses into plain
  plugin reads through the `Reader`.
- **Neighbor privacy:** the neighbor MAC read from LLDP is used only in memory,
  within the attempt, to look up the organization inventory. Only a matched managed
  AP identity is persisted. Unmatched MACs are never stored or shown. There is no
  binding store.
- **The `dns` plugin has no generic mapping.** For each object type and
  attribute, the plugin decides whether the setting affects the device's own
  management resolution or client resolution. Management resolution gets
  infrastructure-connectivity obligations (`empty_policy=incomplete`). Client
  resolution gets client connection, DNS-failure or application-health obligations
  (`empty_policy=not_exercised`). Mappings are verified against the Mist
  configuration schema during planning; unverified attributes stay unhandled, and
  therefore uncovered.
- The playbook text in `impact/skill_assets/` moves into the matching plugin's
  `agent_hint`.

## Coverage ledger

Rows are every change atom × applicable target. Each row resolves one way:

| Row | Condition |
|---|---|
| Claimed | The union of path prefixes from obligations and exclusions targeting this row covers every changed path of the atom, and the atom's `paths_complete` is true |
| Uncovered | Otherwise; it adds an unsatisfied observation, "no plugin addressed A<n> <paths> on <target>" |

- An obligation or exclusion **targets** a row when its target equals the row
  target, or when it has a `site_id` and no `device_mac` and the row device is at
  that site.
- An exclusion applies only to its atom, paths and target, never to a whole device.
- When several plugins claim the same row, all distinct obligations are kept, and
  duplicate monitoring obligations for the same device and metric merge to the
  strictest `empty_policy` (`incomplete` over `not_exercised`).
- The core adds one **deployment precondition** for every device targeted by at
  least one obligation (monitoring or rule), including devices contained in a
  site-level obligation target. A target that only appears in exclusions gets no
  precondition: an excluded device isn't claimed to be exposed.
- An expected device that no plugin targets or excludes remains an uncovered row.

**Deterministic coverage:**

| Condition | Coverage |
|---|---|
| No observation obligations | `insufficient` |
| Any precondition or observation unsatisfied | `partial` |
| All preconditions satisfied and all observations `not_exercised` | `not_applicable` |
| All preconditions satisfied, every observation satisfied or `not_exercised`, at least one satisfied | `complete` |

## Monitoring evaluation

- **Expected devices:** devices with a `*_CONFIG_CHANGED_BY_USER` receipt carrying
  this `audit_id`. If there are none, the gap reads "No audit-linked device
  deployment events were observed."
- **Exclusive session:** the device's linked session has `audit_ids == [audit_id]`.
  A shared session is usable evidence and a gap, never a floor, and it leaves that
  device's monitoring observations `unsatisfied` ("shared session").
- **Terminal:** the session is no longer `active`. Otherwise the observation is
  `unsatisfied` ("monitoring still active"), so early runs never publish `none`.
- **Window rule:** monitoring uses the session's own recorded observations,
  incidents and comparisons up to `as_of`.
  - The equal before/after windows govern only Guardian's own historical queries
    (rule reads and MCP calls).
  - Monitoring compares each SLE observation with the session baseline exactly as
    monitoring recorded it.
  - A terminal session records nothing after it ends, so a forced final run at
    +120 min adds no data beyond the session. Incidents that were still unresolved
    when the session ended count as active at `as_of`.
- **Required check treatment**, using the device's latest observation:

| Before | After | Treatment |
|---|---|---|
| measured | measured | satisfied (comparable) |
| no_data | no_data | `not_exercised` if `empty_policy=not_exercised`, else unsatisfied |
| measured | no_data | unsatisfied (disappearance may be impact) |
| no_data | measured | unsatisfied (no before/after comparison) |
| error / missing / pending / unsupported / disabled | any | unsatisfied |
| any | error / missing / pending / unsupported / disabled | unsatisfied |

  `no_data` is produced only after a valid SLE response with zero samples
  ([mist_sle.py:191](../../../backend/src/mist_config_guardian_backend/integrations/mist_sle.py)).
  A not-exercised check stays listed with its zero-sample evidence.
- **Severity by components**, for exclusive devices only. It uses the metrics,
  incident types and finding kinds selected by that device's obligations. Each
  component is computed independently, so no component waits for a later SLE
  observation:

| Component | Peak | Current |
|---|---|---|
| Metrics | max over every observation of `assess_impact(baseline, observation, [], relevance_plan=RelevancePlan(mode="selected", metrics=…))` | the same call on the final observation |
| Incidents | max severity of relevant incidents with `changed_at <= occurred_at <= as_of` | max severity of relevant incidents active at `as_of` (not `resolved_at <= as_of`) |
| Device state | max severity of each comparison's initial `findings` of selected kinds | max severity of `current_findings` of selected kinds |

  Device peak and current are the maximum over these components. Stored
  `peak_impact_severity` and `ASSESSMENT_*` transitions are never used.

## Deployment pairing

Inputs are normalized device-event receipts for the expected devices, over
`[changed_at − 30 min, as_of]`.

- **Triggers:** `AP_CONFIG_CHANGED_BY_USER`, `SW_CONFIG_CHANGED_BY_USER`,
  `GW_CONFIG_CHANGED_BY_USER`, `AP_CONFIG_CHANGED_BY_RRM`.
- **Outcomes:** `*_CONFIGURED` (configured), `*_CONFIG_FAILED` (failed),
  `*_CONFIG_REVERTED` (reverted).
- **Timestamps:** provider occurrence time at its native precision (seconds).
  Receipt time is a fallback that adds a gap, and a pairing based on it can never
  satisfy a precondition.

Assigning each outcome to a trigger:

1. **Exact link:** the outcome carries an `audit_id`. It pairs only with a trigger
   carrying the same `audit_id` on the same device that is not after it; with
   several, the latest at the provider's timestamp precision. Beyond 30 min it is
   accepted with a delay gap.
   - It pairs with this audit's trigger only when that ID is this audit.
   - An outcome linked to another audit never pairs with this audit's trigger.
   - An outcome whose audit has no matching trigger for the device is ignored,
     with a gap.
2. **Time fallback, only when the outcome has no `audit_id`:** the outcome goes to
   the latest trigger for that device at or before it, within 30 min. That trigger
   may belong to any audit, or to RRM.
3. **Ambiguous:** triggers from different audits in the same second, an outcome
   outside the bound, or receipt-time-only ordering.
4. **One trigger per outcome:** each outcome belongs to exactly one trigger and is
   never assigned backward.

The per-trigger state machine for this audit's trigger:

| Outcomes | Peak | Current | Precondition |
|---|---|---|---|
| none | — | unknown | unsatisfied |
| configured | — | configured | satisfied |
| failed or reverted anywhere | warning | last outcome | satisfied only if the last outcome is configured |
| configured → reverted | warning | reverted | unsatisfied |
| failed → configured | warning | configured (recovered) | satisfied |
| duplicate outcomes of one kind in one second | idempotent | — | — |
| conflicting outcomes in one second | warning | ambiguous | unsatisfied |

Deployment state projects to severity for composition:

| Paired outcomes | Deployment peak | Deployment current | Precondition |
|---|---|---|---|
| Only `configured` | `none` | `none` | satisfied |
| `failed` or `reverted`, later `configured` | `warning` | `none` | satisfied |
| Latest outcome `failed` or `reverted` | `warning` | `warning` | unsatisfied |
| None, or ambiguous | no floor | no floor | unsatisfied |

Only exact-linked or unambiguously paired outcomes project severity. Deployment
evidence is `kind=deployment`: it proves exposure, not service health.

## Verdict composition

This is one pure function. Monitoring, deployment, rule and agent conclusions are
stored separately on the run.

Severity order is `none < info < warning < critical`.

1. **Base** from deterministic coverage:
   - `complete` gives `none`;
   - `not_applicable` gives `info`, with the summary "The change was not exercised
     during the window";
   - `partial` and `insufficient` give `info`.
2. **Floor:** `floor.peak` / `floor.current` = max over exclusive monitoring
   replay, deployment pairing and rule conclusions, counting only `warning` and
   `critical`.
3. **Agent contribution:** an accepted agent report contributes its peak and
   current only if it cites at least one `service_health` evidence item. An uncited
   `info` report is kept for display and changes nothing.
4. `peak = max(base, floor.peak, agent.peak)` and `current = max(base,
   floor.current, agent.current)`, omitting a non-contributing agent. A cited
   agent assessment lower than the published peak adds the gap "AI assessment
   (<agent peak>) was below the published verdict (<peak>)".
5. **Confidence** is `medium` only when the contributing agent report's peak equals
   the published peak; otherwise `low`.
6. **Recovery** is `recovered` if peak ≥ warning and current < warning, and
   `unrecovered` if current ≥ warning; otherwise `none`.
7. **Sources** are the inputs that set the published peak or current: the
   coverage inputs (monitoring, deployment, applicable rules) when the base
   decides it, otherwise the floor inputs or the agent.
8. **Agent did not conclude:** the gap "AI agent did not conclude: <reason>".

## Agent

### Structured-output capability

- "Test connection" in the AI settings probes Guardian's **actual action schema**
  with `response_format: json_schema`, and validates the returned content against
  it, because some servers accept the parameter and ignore it.
- It stores `{mode: json_schema | json_object, fingerprint, tested_at}` on the
  application configuration. The fingerprint covers provider base URL, model and
  Guardian action-schema version.
- `json_object` is recorded when the schema probe is rejected or not honored but a
  JSON-object probe, prompted with the schema, returns content that validates. If
  neither validates, no record is stored.
- A fingerprint change invalidates the record. With no valid record the agent is
  skipped with a reason. If provider behavior later changes, that attempt's agent
  fails explicitly; there is no runtime fallback.
- The provider gains a typed `response_format` parameter (text, `json_object`,
  `json_schema`) in place of `json_object: bool`
  ([ai_provider.py:159](../../../backend/src/mist_config_guardian_backend/integrations/ai_provider.py)).

### Protocol

One JSON object per turn:

```json
{"action": "call", "tool": "<allowlisted>", "arguments": {}, "purpose": "…"}
```

```json
{"action": "report",
 "peak_impact": "none|info|warning|critical", "current_impact": "none|info|warning|critical",
 "confidence": "low|medium", "summary": "…", "evidence": ["E1"],
 "findings": [{"text": "…", "impact": "…", "evidence": ["E3"]}],
 "impacted_devices": [{"mac": "…", "impact": "…", "evidence": ["E3"]}],
 "gaps": ["…"]}
```

- There is no `describe`, batching, `coverage`, `scope`, views or `org_id`.
- **Turns:** at most 10 model turns and 7 MCP calls per attempt. A report is
  accepted on any turn. While `turns_left <= 3`, calls are rejected as
  `report_required`. Seven calls fit in the first seven turns, and the last three
  leave room for one disallowed action plus a report and its repair.
- **Rejections** are returned as `Action rejected (<category>): <bounded, redacted
  detail>`. Categories: `json_invalid`, `schema_mismatch`, `tool_not_allowed`,
  `argument_invalid`, `out_of_scope`, `call_budget`, `report_required`,
  `citation_invalid`, `citation_required`, `coverage_required`,
  `device_not_in_evidence`, `severity_order`.
- **Report validation:**
  - `peak_impact=none` is rejected as `coverage_required` unless deterministic
    coverage is `complete`. An accepted AI summary can therefore never claim
    "no impact" next to a published `info`.
  - Every cited ID exists, is citable and was visible in this turn's evidence view.
  - `peak_impact` or `current_impact` of `warning` or `critical`, `peak_impact` of
    `none`, and `confidence=medium` each require at least one cited
    `service_health` item; otherwise `citation_required`. Deployment,
    configuration and reference evidence may be cited alongside, but never
    satisfy this alone.
  - Warning and critical findings cite at least one item.
  - Each impacted device's MAC appears in its cited evidence.
  - `current <= peak`, and no device exceeds the overall peak.

### Prompt and evidence view

- **System prompt:** about 3 KB. It carries the protocol, citation rules and
  severity semantics. The deterministic floor, and the fact that `none` needs
  deterministic coverage, are explained as facts, not as instructions to agree.
- **Data:**
  - change atoms with paths and masked values;
  - the deterministic conclusion: floors, coverage, unsatisfied obligations and
    uncovered rows, capped with counts;
  - the evidence view;
  - allowlisted tools as compact schemas without `org_id`;
  - the before and after windows and `turns_left`;
  - `feedback`;
  - plugin `agent_hint`s.
- **Cap:** one 96 KB prompt cap.
  - The fixed part is bounded by construction and never withheld: system prompt,
    tool catalogue, change view, deterministic conclusion, monitoring evidence,
    deployment evidence, feedback. Its budgets sum to at most 48 KB (see "Limits").
  - Rule and MCP payloads fill the rest: 8 × 4 KB + 7 × 4 KB = 60 KB at most.
  - When the total exceeds the cap, the oldest MCP payloads are withheld first,
    then the oldest rule payloads. A withheld item appears as `E5: withheld (not
    citable)`, and citations to it are rejected.
  - A catalogue that doesn't fit its budget after compaction drops the tools that
    don't fit from the allowlist for that attempt, with a gap.

### Stored steps

Each turn records:
- its action kind, and the raw model output redacted and truncated to 3 KB
  **before storage**;
- any rejection category and detail;
- `prompt_version`, `prompt_hash`, `prompt_size`;
- `visible_evidence_ids` and `withheld_evidence_ids`.

Each call records its E-id, redacted arguments, duration and collection state.
Prompts are not stored.

## Report (rendered on read)

| Section | Content |
|---|---|
| Header | peak, current, recovery, confidence, coverage, sources |
| Summary | Deterministic sentence from composition, plus the agent summary labelled AI |
| Change | Atoms with paths |
| Coverage | Ledger rows and obligation statuses; digest beyond display limits |
| Devices | Deployment state, monitoring treatment, peak/current per device |
| Findings | Rule and agent findings with evidence links |
| Evidence | E-id tables with kind, collection and representation |
| Gaps | Every gap with its source |
| Attempts | Collapsed summaries (kind, attempt, state, failure reason, budget); expanding one loads its full run through the run endpoint: steps, rejections, visible and withheld IDs |

Every empty section explains why from state (for example "No rule plugin applied to
A2 on 3 devices"). There are no fixed boilerplate strings.

## API

- Change-group summary and detail: `guardian: {status: waiting | done,
  status_reason, result} | null` replaces `shadow_impact`. It is used by the changes, overview and site
  impact pages.
- `GET /organizations/{org}/change-groups/{id}/guardian` returns:
  - the root;
  - the published early and final runs with rendered reports;
  - attempt summaries (id, kind, attempt, state, failure reason, budget).
- `GET /organizations/{org}/change-groups/{id}/guardian/runs/{run_id}` returns
  one full, bounded run document (published or not) with its rendered report.
  The run must belong to that organization and to the change group's
  investigation.
- Site impact overlay: the published run's compact impacted-device rows filtered
  by site, plus the omitted count; not the capped root list.
- The AI settings response exposes the structured-output capability (mode, whether
  it matches the current fingerprint, `tested_at`).
- **Removed:** `/investigation`, `/investigation/history`,
  `/investigation/model-requests/{id}`, `/investigation/mcp-requests/{id}`,
  `/investigation/adjudication`, `/investigation/acceptance`.
- `docs/openapi.json` is regenerated.

## Frontend

- `GuardianBadge` replaces `shared/audit-impact-summary.ts` on the changes,
  overview and site impact pages. It shows pending, peak/current/recovery and
  confidence.
- `GuardianPanel`, with Early/Final tabs and the report sections above, replaces:
  - `features/changes/shadow-investigation.ts`;
  - `shared/agent-investigation.ts`, `mcp-investigation.ts`, `dispatch-log.ts`,
    `model-request-details.ts`;
  - `impact-report.ts`, `deployment-evidence.ts`, `domain-findings.ts`;
  - `port-snapshot.ts`, `port-events.ts`, `managed-neighbor.ts`, `ap-adjacency.ts`,
    `impact-adjudication.ts`;
  - and their specs.
- `core/guardian.model.ts` replaces `audit-impact.model.ts`,
  `impact-report.model.ts` and `deployment-evidence.model.ts`.
- The changes page disclaimer is updated. Legacy badges and notifications are
  unchanged.

## Deletions

**Backend, `impact/`:**
- `agent.py`, `contracts.py`, `dispatch.py`, `limits.py`;
- `mcp_schedule.py`, `mcp_report.py`, `mcp_views.py`, `mcp_context.py`,
  `mcp_contracts.py`, `mcp_scope.py`;
- `change_context.py`, `report.py`, `acceptance.py`, `knowledge.py` and
  `knowledge_assets/`, `skills.py` and `skill_assets/`;
- `deployment.py`, `neighbor_identity.py`;
- after porting to plugins: `wlan_removal.py`, `domain_evaluation.py`,
  `port_scope.py`.

Useful pieces of `mcp_scope.py`, such as redaction and schema compaction, move into
the Reader rather than being rewritten.

**Backend, `services/`:**
- `impact_agent.py`, `mcp_impact_agent.py`, `mcp_dispatch.py`;
- `impact_investigations.py`, `impact_acceptance.py`;
- `investigation_reads.py`, `audit_impact_reads.py`, `published_revision.py`;
- `deployment_evidence.py`, `neighbor_bindings.py`.

**Backend, models, integrations and config:**
- `models/investigation.py`, `models/adjudication.py`, `models/neighbor_binding.py`,
  and the matching schemas and routes;
- `integrations/mist_{wlan,auth,port,neighbor,ap}_evidence.py` and
  `mist_port_history.py` after porting;
- `impact_engine_mode` and its Helm validation.

**Tests:** tests of deleted modules, and `tests/legacy_agent_fixture.py`.

**Docs:** Guardian-specific design docs superseded by one new
`docs/design/guardian.md`. The exact list is confirmed during planning; monitoring
docs such as `impact-monitoring.md` and `site-impact-workspace.md` stay.

## Limits

| Constant | Value |
|---|---|
| Lease | 300 s |
| Attempt deadline / rule phase end / agent phase end | +240 s / +90 s / +210 s |
| Provider and tool call timeout | min(20 s, phase deadline − now) |
| Attempts per kind | 2 |
| Model turns / report-only window | 10 / last 3 |
| MCP calls per attempt | 7 (plus 1 catalogue discovery) |
| Rule reads per attempt | 8 total; per plugin `max_reads` |
| MCP transport bound | 1 MB |
| Root impacted devices | 20 plus count |

Aggregate budgets (serialized UTF-8 bytes). Each source degrades to a count-only
digest that always fits its budget.

| Source | Budget | Stored in run | In prompt |
|---|---|---|---|
| System prompt | 3 KB | — (version and hash) | fixed |
| Tool catalogue (compact schemas) | 8 KB | — | fixed |
| Change view (atoms, paths, masked values) | 6 KB | yes | fixed |
| Deterministic conclusion view (floors, coverage, unsatisfied obligations, uncovered rows) | 6 KB | yes | fixed |
| Monitoring evidence (all items, including digest) | 18 KB | yes | fixed |
| Deployment evidence | 4 KB | yes | fixed |
| Feedback | 1 KB | in steps | fixed |
| Rule evidence | 4 KB per item, 8 items | yes | withholdable |
| MCP evidence | 4 KB per item, 7 items | yes | withholdable |
| Ledger rows and obligation statuses | 24 KB | yes | — |
| Monitoring, deployment, rule and agent conclusions | 8 KB | yes | — |
| Impacted devices (compact rows) | 12 KB | yes | — |
| Steps (model output ≤3 KB per turn, 10 turns, plus call records) | 40 KB | yes | — |

- **Prompt:** fixed part ≤ 48 KB, plus withholdable payloads ≤ 60 KB, capped at
  96 KB.
- **Run document:** the stored budgets sum to 180 KB, plus about 8 KB of envelope
  fields, against an asserted bound of 256 KB.
| Deployment pairing bound | 30 min |
| Early cutoff / final minimum / final maximum | +45 / +60 / +120 min |

## Testing

**Table-driven unit tests (pure functions):**
- **Change model:** `changed_paths` completeness and truncation; segment-aware
  prefixes; ignored metadata fields.
- **Ledger:** path unions, site containment, per-atom exclusions, strictest
  `empty_policy`, truncated paths preventing `none`, and exclusion-only targets
  getting no deployment precondition.
- **Anchor:** audit, device-trigger and receipt sources; a receipt anchor
  preventing `complete` coverage.
- **Coverage:** each row of the coverage table; precondition vs observation roles.
- **Monitoring:** every treatment row; exclusivity; non-terminal sessions.
- **Monitoring severity components:** metric peak over observations and current
  from the final observation; an incident after the last observation still sets
  incident peak and current; incident activity at `as_of`; findings peak vs
  current; a forced +120 min final uses only the terminal session's recorded data.
- **Deployment pairing:**
  - every state-machine row and every severity-projection row, including
    same-second duplicates and conflicts;
  - exact-link validation and delay gaps;
  - the 30 min bound;
  - receipt-time fallback;
  - the 242 ms regression from the DNT-NTR payload;
  - an outcome linked to another audit never confirming this audit's trigger;
  - time fallback applied only to outcomes without an `audit_id`.
- **Composition:** floors; `none`, `not_applicable` and `info` rules; uncited agent
  severity and confidence ignored or rejected; agent below the floor; recovery;
  sources.
- **Evidence and budgets:** `kind` assignment table; digest counts;
  transport-bound partial; a worst-case construction (every source at its limit,
  1,000 expected devices, 10 turns) stays within every aggregate budget, the
  96 KB prompt cap and the 256 KB run bound.
- **Reader:** allowlist, schema, org injection, site authority, time ranges
  accepted only as exactly `before`, `after` or both (including at +120 min, where
  the windows stay equal); org-wide results cannot expand a site-scoped
  investigation; success-only caching, budget, phase deadline.

**Agent loop** (fake provider and fake MCP):
- turn arithmetic: seven calls then a disallowed call, a rejected report and a
  repaired report all fit in ten turns;
- `report_required` in the last three turns, and report repair after a rejection;
- `coverage_required` for `peak_impact=none` under non-complete deterministic
  coverage;
- `citation_required` for uncited severity, `none` or medium confidence;
- citations to withheld evidence rejected;
- redaction of raw output before storage;
- visible and withheld manifests persisted;
- an expired phase deadline stopping further calls;
- a provider failure leaving a deterministic verdict.

**Capability:** probe with the real action schema; a server ignoring
`response_format` is recorded as unsupported; fingerprint invalidation; agent
skipped without a valid record.

**Plugins:**
- ported fixtures for `wlan-removal`, `wlan-auth` and `switch-port`;
- `dns` mappings per verified object type and attribute;
- exception and timeout isolation;
- neighbor MACs never persisted unless matched.

**Mongo integration:**
- claim and CAS publication;
- **Crash at every step boundary of the tick procedure**, each followed by a later
  tick. Before publication, the root still holds the token and the later tick
  finishes recovery. After publication, the claim is already clear and the later
  tick observes the idempotent terminal state:
  - between lease and commit: no attempt consumed, claim cleared;
  - between commit and run insert: an `abandoned` run carrying the attempt number;
  - between finalize and publish: a `succeeded` run is adopted and published, and
    a `failed` run is published as failed;
  - after publication: no duplicate pointer, result, attempt or retry is created;
  - a recovering worker crashing between marking the run `abandoned` and clearing
    the claim: the next tick completes the clear.
- **Two committed attempts that each crash before creating their run:** exhaustion
  finds two `abandoned` records and uses the last one's reason.
- **Recovery versus a stale commit, in both orders:** the commit winning (the
  uncommitted clear matches nothing, and the claim stays committed with its
  metadata); the clear winning (the commit matches nothing, and the worker stops
  without a run or attempt increment).
- **An ambiguous commit response:** a simulated timeout after the update applied
  (the worker reads the root and continues with exactly one increment, its
  deadline still measured from before the send) and before it applied (the worker
  reads the root and stops).
- **Lease comparisons under worker clock skew:** a worker clock ahead or behind
  the server can't make a lease both unexpired at commit and expired at recovery.
- **A publication whose `claim.attempt` doesn't match the run** matches nothing.
- **Races between recovery and a stale worker:** recovery marking the run
  `abandoned` before the stale worker finalizes (the finalization matches nothing,
  and the worker never publishes); the stale worker finalizing `succeeded` first
  (recovery adopts it; both publications are tried, exactly one matches).
- **Triggers:**
  - a stale decision can't lease after an early run was published, can't start a
    second early run, can't skip the retry delay, and can't lease an early run
    after +45 min;
  - an early lease acquired before +45 min whose commit is attempted after +45 min:
    the commit matches nothing, the release frees the lease without incrementing
    `attempts.early`, and the final trigger later proceeds normally;
  - a final whose linked session became active again fails revalidation without
    consuming an attempt;
  - a worker clock running ahead leases a final at server +119 min:
    `final_forced` is false, so an active linked session still fails revalidation;
    at server +120 min `final_forced` is true, and the final proceeds;
  - a candidate selected by a fast worker clock before `next_check_at` or lease
    expiry on server time matches no CAS and changes nothing.
- every scheduling-transition row, including `next_check_at` after succeeded
  and failed attempts;
- indexes created as specified;
- attempt caps;
- early exhaustion not blocking final;
- the +45 min merge;
- a failed final keeping the early result;
- retention on both collections;
- `drop-legacy-impact-collections` being idempotent and untouched by new code.

**End to end:** webhook, then triggers, then early and final runs, then the published
root projection and API, including the run endpoint's tenant and investigation
checks.

**Replay fixture:** the DNT-NTR payload. Both outcomes depend on the `dns`
mapping verified during planning. For example, a client-facing mapping that
legitimately excludes the switches creates no switch deployment preconditions. The
invariants hold regardless:
- same-second precision no longer produces a false deployment `unknown`;
- any targeted switch without a confirming outcome has an unsatisfied deployment
  precondition;
- the verdict, as recorded and with `SW_CONFIGURED` outcomes added, matches the
  expected result fixed in the plan for the chosen mapping. That expected result
  names every unsatisfied obligation. For example, `switch-health` has no data in
  both windows, so an infrastructure obligation with `empty_policy=incomplete`
  stays unsatisfied.

**Frontend:** component tests for `GuardianBadge` and `GuardianPanel`.

## Verification items for planning

These are facts the design depends on that could not be established from the code:

1. Whether Mist device events carry a trustworthy sequence field for same-second
   ordering. The design assumes not.
2. Whether Mist emits `SW_CONFIGURED` when a switch's rendered configuration is
   unchanged. If it doesn't, switch-bearing audits stay `info` until a
   config-confirmation plugin exists.
3. DNS attribute semantics per object type (management vs client resolver), from
   the Mist configuration schema.
4. The MCP catalogue's tools and discriminating arguments for the `kind` table,
   from the recorded catalogue fixtures.
5. Whether the configured provider (currently `gemma4-26b-a4b`) honors
   `json_schema`.
