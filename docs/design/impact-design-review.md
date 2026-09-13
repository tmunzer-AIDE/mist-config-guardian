# Review before implementing step 3

Reviewed 2026-09-12 against commit `17a29e5` and the four design documents.
These are proposed amendments, not an expansion of v1's four rule domains.
Follow-up: the pure baseline-confidence function now counts only complete selected
comparisons and requires a usable latest comparison, with regression tests. This
fix is independent of the still-proposed projector rewrite. The remaining items
are design recommendations, not implemented behavior.
CodeRabbit remains signed out; this review used local source inspection, two small
in-process reproductions, and the primary references cited below. It is not an
exhaustive security audit or a new live Mist capability probe.

The architecture is suitable: one investigation per audit, deterministic evidence,
bounded agent checks, explicit unknowns, and shared report/topology projections.
The main remaining risks are where that design meets existing collection,
projection and persistence paths. Address items 1–3 as part of step 3's foundation;
items 4–7 belong before the investigator rollout. Item 8 reduces delivery cost.

## 1. Replace the Changes projection's independent assessment path

**Priority: high; before rules become authoritative.** Steps 1–2 consolidated the
device/site assessment paths, but the Changes projector still bypasses them:

- `services/change_groups.py:750` averages raw baseline/latest values without
  consulting selected evidence, comparability, scope identity or sample weights.
- `resolve_baseline_confidence` previously graded confidence from baseline presence
  and follow-up count alone. The follow-up fix reuses evidence eligibility/coverage
  and does not count failed, unselected or incomparable collections.
- `:701` says a regression is attributable to a change when no competing change
  was found. Absence of a competing audit is not evidence of causation.
- `:878` rebuilds the group's metrics, recovery, confidence and prose using those
  paths and session-wide mirrors. This can survive even after new rules exist.

Local reproductions confirmed the gaps without database/network access:

| Input | Authoritative evaluator | Existing Changes projection |
| --- | --- | --- |
| Baseline device A = 99, follow-up device B = 0 | Delta null; insufficient coverage | Delta −99 |
| Baseline present; six follow-ups contain only collection errors | No usable follow-up samples | Baseline confidence high |

The first reproduction deliberately put different observation scope IDs inside one
session; it did not join one session's baseline to another's follow-up. The more
representative aggregation defect is two individually valid session comparisons:
99→99 and 99→0 become 99→49.5, a movement no individual device experienced. A
site-scoped session and a device-scoped session can also enter that same mean.
Recovery reads the blended delta, so the issue affects verdict presentation and
recovery behavior, not just chart formatting. The confidence reproduction describes
the pre-fix behavior; error-only follow-ups now return low confidence.

**Amendment:** give the Changes projector the audit assessment reference. Derive
all impact labels, recovery, metric tiles and attribution prose from that revision.
Retain per-scope movements and identify the worst eligible movement with its actual
baseline/latest values, scope and deduplicated affected/assessed counts. Keep site
and device scopes separate; do not average them or invent a group measurement.
Evaluate recovery per relevant finding, then aggregate status without averaging
away an unrecovered device. Retain explicit legacy presentation for old groups,
without asserting causation. The consumer inventory below makes this migration
reviewable. It extends the single-source-of-truth contract, not a new evaluator.

**Acceptance:** the same audit shows identical evidence eligibility and attribution
across Changes, Impact, report and topology; failed collections cannot increase
confidence, and unknown identity cannot yield a numeric delta anywhere.

### Enumerated assessment consumers

Paths below are relative to `backend/src/mist_config_guardian_backend` unless
prefixed with `frontend/`. This inventory includes direct session-mirror consumers
and downstream group consumers; they are not all independent evaluators.

| Consumer | Current source/use | Required migration check |
| --- | --- | --- |
| `services/change_groups.py`: `_rebuild_once`, `resolve_recovery_state`, `_collect_evidence`, `build_assessment`, `build_evidence`, `build_summary` | Session severity/peak/degraded metrics, raw observations/incidents and poll counts → persisted group verdict/prose | Audit assessment reference owns verdict, per-scope movements, recovery and attribution; qualify any legacy summary |
| `services/change_groups.py`: `_summarize`, `get_group`, `build_metrics`, `build_impact_label` | Group fields plus freshly recomputed raw movements → list/detail tiles and labels | Render one pinned revision; no read-time reconstruction of new verdict evidence |
| `services/change_groups.py`: `build_criteria`; `models/webhook.py`: group severity index | Indexed group severity/recovery filters and summary search | Index mirrors must correspond to the published assessment revision; filters cannot disagree with rendered rows |
| `services/change_groups.py`: `_announce` → `services/notifications.py`: `notify_impact_detected` → `emit` | Group critical severity and summary → stored “Harmful change detected” notification | Gate on eligible audit findings and their attribution; pin source revision/finding/transition and deduplicate delivery |
| `services/overview.py`: `change_group_counts`, `recent_groups`; `frontend/src/app/features/overview/overview-page.ts` | Group severity/recovery → aggregate counts, highlights, feed and restore affordances | Counts and cards use the same projection policy/revision; no new interpretation of raw metrics |
| `services/search.py` | Group severity → search-result metadata | Read published group projection; preserve organization scope |
| `services/point_in_time.py` | Group severity → current timeline summaries, masked for historical mode | Preserve historical masking; later serve only an eligible retained revision at the requested instant |
| `api/routes/monitoring.py`: `list_monitoring_sessions`, `_change_refs` | Session mirror severity → database filter; group summary → linked change title | Preserve explicit device-window semantics and mirror consistency; audit verdicts come from audit references |
| `schemas/monitoring.py`: `MonitoringSessionResponse.from_document` | Stored assessment for current values; session mirrors for legacy fallback and historical peak | Keep fallback labelled and peaks consistent; do not substitute device severity for audit attribution |
| `services/site_impact.py`: `session_projection`, `impact_from_session`; `frontend/src/app/features/impact/site-impact.model.ts`, `site-impact-page.ts` | Stored/legacy device assessments → site change health, topology/details/filtering | Replace audit-related overlay with validated impacted-device records while preserving lifecycle error and historical handling |
| `services/monitoring.py`: incident, recovery, timeout and poll paths | Write mirrors/assessment; read severity and peak for transition events | Keep telemetry transitions separate from audit verdict transitions; never let a later audit overwrite another audit's evidence |
| `integrations/impact_ai.py` via `services/monitoring.py` | Completion-time stored assessment → legacy AI narrator | Retire under the mutually exclusive investigator mode; do not keep another attribution path |
| `frontend/src/app/features/changes/changes-page.ts`; `frontend/src/app/core/change-group.model.ts` | Group severity, confidence, recovery and prose → rows, counts, detail | Render published audit values and retain explicit coverage/attribution |
| `frontend/src/app/features/impact/impact-page.ts`, `impact-page.html`, `monitoring.model.ts` | Session response severity/peak/summary, metric evidence, legacy AI and confidence helpers → device view | Keep device-window versus audit-result labels explicit; no frontend regrading |

The notification path is an indirect mirror consumer, not a direct read of
`session.impact_severity` in `notifications.py`. Current delivery deduplicates on
`impact-detected:{change_group_id}` and insertion ignores an existing notification.
A later corrected projection does not rewrite the previously issued message.
Before enabling rule-derived notifications, test that unrelated or unmapped evidence
cannot reach `_announce`; a corrected/withdrawn finding must produce an explicit
linked correction transition where a notification was already issued. Deduplicate
by meaningful transition, not every report checkpoint, and do not announce replay
or historical recomputation as a new live incident.

## 2. Audit-owned plans also need audit-owned evidence windows and deadlines

**Priority: high; define before association models.** Merely moving the plan off
`MonitoringSession` does not isolate the evidence. A session still has one SLE
baseline and combined incident history. `_add_comparison` adds operational snapshots
without an audit/receipt identity on `DeviceStateComparison` itself. A second audit
can therefore inherit a baseline or interruption that predates that second change
unless the association explicitly owns its evidence selection.

The design also allows an audit investigation with no configured events, while
deriving investigation lifetime from device windows and ending work when those
windows terminate. With no sessions there is no timer authority. The current poll
service selects only device sessions; it cannot by itself discover such an audit.

**Amendment:** each audit/check/cohort plan entry pins its original configuration
versions, baseline observation references, baseline window, follow-up window and
deployment-time uncertainty. Shared data can be reused only when these match.
Never label a current-state capture made after deployment as a pre-change snapshot.
Use available historical evidence or retain the missing baseline explicitly.

Give the investigation its own first-seen, initial-review and bounded expiry times.
The same existing 60-second worker tick queries due investigations independently
of device sessions. Device deployment windows inform explicit bounded extensions;
they do not prevent an audit-only investigation from reaching an incomplete final
result. This adds no second scheduler and no per-device agent.

Distinguish latest operational state/recent complete metric buckets from cumulative
impact since deployment. Preserve actual source intervals and ingestion time; a
ten-minute source bucket fetched twice is not two independent samples, and a
cumulative depressed average is not proof that an outage remains active.

**Acceptance:** overlapping A/B audits keep distinct before/after comparisons;
an audit with no device event starts once and terminates; late events cannot reset
its budget; recovery cannot erase a transient outage or be blocked by stale averages.

## 3. Make selection reduce collection, not just evaluation

**Priority: high; part of the four-rule implementation.** The current relevance
plan filters the evaluator, but `MistSleClient.capture` discovers/fetches its full
metric family. `MistTelemetryClient.capture` takes broad device snapshots and may
fetch evidence regardless of the changed attribute. AP capture requests device,
WLAN and client data; the switch/gateway branch also requests ports, BGP and OSPF.
Do not describe BGP/OSPF requests as occurring for every AP: the branch is conditional
on device type, although its routing checks remain unconditional within that branch.
One agent for 200 devices can still produce thousands of unnecessary API requests.

**Amendment:** compile rules to typed check requests consumed by collectors, with
explicit signal, entity/cohort, filters, time window and required/optional status.
Keep `legacy_all` only for the legacy path. Reuse the narrow allowlisted operational
adapters already available; neither a YAML loader nor MCP is required for this seam.

Make the shared-query identity concrete: organization, credential authorization
scope/version, adapter/check version, entity/cohort, filters, window and source
definition. Coalesce simultaneous identical requests. A site-level WLAN read should
not repeat once per AP. Cache capability discovery with bounded freshness and
invalidate it on relevant unsupported/permission responses; never cache an error
as an empty healthy dataset. Required collection gets capacity before optional
agent corroboration. Apply organization-wide concurrency limits, bounded retry
backoff and a total deadline so a slow tenant cannot occupy the whole poll loop.

**Acceptance:** a PoE-only plan performs no BGP/OSPF/RF checks; duplicate consumers
share identical reads; another organization never reuses their data; a rate-limit
burst yields partial coverage and bounded attempts, not unbounded retries.

## 4. Make publication atomic without one enormous investigation document

**Priority: before the persisted investigator runtime.** The design says state,
summary, report and cursor publish as one logical commit but leaves its storage
mechanism unspecified. Existing sessions embed observations/comparisons. Extending
that pattern to hundreds of devices plus tool payloads and report revisions would
create a growing document and expensive rewrites. MongoDB has a 16 MiB document
limit. [MongoDB limits](https://www.mongodb.com/docs/manual/reference/limits/).

**Amendment:** keep the investigation root small. Store immutable bounded evidence
records and revision artifacts separately. Write artifacts first, then publish
their references and cursor with a conditional single-root update matching the
expected revision and lease generation. Readers follow only the committed manifest;
cleanup may remove orphan artifacts after a grace period. This fits MongoDB's
single-document atomicity without assuming cross-document transactions are configured.
[MongoDB atomicity](https://www.mongodb.com/docs/manual/core/write-operations-atomicity/).

A lease generation must also be checked at tool dispatch, not only final commit:
an expired worker that resumes must not keep consuming the organization's budget.
An already in-flight response can be retained as evidence, but the stale worker
cannot publish a verdict. Idempotent reservations/results remain separately durable
as the current journal design specifies; this does not promise exactly-once networks.

## 5. Extend the tool boundary to credentials, transport and caches

**Priority: before operational agent tool access.** Resolver handles and catalogue
checks constrain model requests, but security also depends on the executor's
connection and cached data. The current design mentions scoped credentials and
organization validation without defining how revocation affects a resumed turn.

**Amendment:** bind every handle and cached result to organization and authorization
scope/version. Recheck current authorization at dispatch and dataset/log retrieval;
invalidate capabilities after credential revocation or changed permissions. Use a
dedicated monitoring connection with only the required reads. Never borrow restore
administrator credentials to repair an unavailable telemetry check.

Keep approved MCP endpoints/regions and adapter definitions application-owned;
tool responses cannot change the destination. Pin the validated capability schema
for each revision and require review before accepting new executable capabilities.
Validate returned organization/site/entity identities where present, and document
the endpoint's scoped identity guarantee where records omit them. Mismatched data
is quarantined as an error, not accepted because the original handle was valid.
Apply destination validation to authentication discovery and redirects as well as
ordinary calls; follow the server's documented authentication mechanism without
blindly forwarding unrelated credentials. These are consistent with the MCP
guidance on scope minimization, token handling and SSRF.
[MCP security guidance](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices).

**Acceptance:** revoked credentials between turns, handles reused across tenants,
changed tool schemas and responses for another site are rejected without losing
existing evidence. No automatic escalation to a restore credential is possible.

## 6. Make useful stopping rules explicit

**Priority: before live investigator calls.** Budgets limit worst-case cost but do
not tell the agent when another query has no value. An unresolved hypothesis alone
can currently justify a model wake at every checkpoint, even if no new capability
or evidence can resolve it.

**Amendment:** each check names the hypothesis it tests, possible outcomes and the
evidence that would change its finding. Persist terminal reasons such as unsupported
source, unavailable historical baseline or deferred resolver. Do not retry those
at every turn unless the relevant capability/input changes. Wake on meaningful new
evidence, an actionable due check or finalization. Deterministic mandatory monitoring
continues while model reasoning sleeps. This is planner state, not another agent.

## 7. Strengthen evaluation without pretending the acceptance set is large

**Priority: before enabling agent-derived notifications.** Preserve the existing
small held-out precision/recall gate, but group related audits by deployment or
underlying outage before splitting. Otherwise repeated devices or checkpoints from
one incident leak effectively the same case into development and acceptance sets.

Add controlled variants to test invariants: inject unrelated AP-health movement;
remove a baseline; duplicate/reorder an event; make a tool unavailable; change an
attacker-controlled device name; replay late recovery. These variants test
robustness, not new independent statistical ground-truth cases.

Fixed tool responses make executor replay reproducible, not model decisions
deterministic. Repeat a bounded selection of critical/benign cases and report verdict
and query-cost variation. If a model requests an unrecorded query, return an explicit
replay coverage miss; never substitute empty evidence or make a live call silently.

## 8. Deliver the report UI incrementally

**Priority: delivery improvement, not a correctness gate.** Keep the common report
schema and typed-block registry. Start with the report header, impacted-device table,
basic time series, evidence gaps and minimal call/error inspection. Add histograms,
rich timelines and exports when a real investigation supplies the required data.
The current plan makes all six visualization types part of the initial runtime/UI
delivery. That couples engine validation to frontend work that some cases cannot
use. The full visualization capability remains planned, but is not a prerequisite
for evaluating the four rules or shadow investigator.

## Recommended next implementation slice

Implement one end-to-end WLAN-removal case first: audit-owned evidence/window
references, selected collection, rule evaluation and the Changes/Impact projection.
Its acceptance case is the original bug: unused WLAN removed, unrelated AP health
falls, no supported change-attributed critical result. Then add the other three
rules through the same contracts. This should expose schema mistakes earlier than
building all resolvers and all evaluators in separate phases.
