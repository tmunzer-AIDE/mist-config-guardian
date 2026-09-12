# Structured investigation reports and evidence views

Status: proposed, 2026-09-12. This defines the report/UI work required by the
[hybrid impact design](rule-driven-impact-analysis.md); it does not implement a
report API, renderer or investigator. Existing device assessment views remain in
place until the audit-owned report is available.

## One report contract

Every investigation uses the same versioned `InvestigationReport` contract and
section order. Domain skills contribute findings and evidence views inside that
contract; they cannot invent a different report format. The agent selects useful
visualizations from registered block types. The application owns layout, validated
data, verdict badges and rendering.

A report belongs to the audit investigation, not each configured device. Initial,
intermediate and final reports are revisions of that same report. Each revision
pins its assessment and evidence snapshot so a historical chart cannot silently
show newer measurements than its conclusion.
Reports are projections of persisted investigation state, not the agent's working
memory. Between turns, the agent resumes from structured state, a bounded summary
and referenced historical/new evidence as defined in the main design. Summary
compaction does not remove report evidence or reset impact/confidence history.

| Required envelope field | Meaning and ownership |
| --- | --- |
| `schema_version` | Contract version; validated by the backend |
| `investigation_id`, `audit_id` | Canonical ownership, assigned by the backend |
| `revision`, `generated_at`, `evidence_as_of` | Immutable revision and freshness, assigned by the backend |
| `status` | Collecting, investigating, completed or incomplete; assigned by workflow |
| `assessment_ref` | Persisted validated verdict used throughout the application |
| `ratings` | Backend projection of the referenced assessment's impact and confidence bands, including state, policy version and explanation |
| `impacted_devices` | Explicit, validated device impact records for the report table and topology overlay |
| `device_impact_coverage` | Completeness of device attribution, unresolved cohorts and reasons; an empty list alone is not a clean result |
| `sections` | The fixed typed sections below; required even when empty or pending |
| `datasets` | Bounded backend-materialized evidence datasets referenced by blocks |
| `provenance` | Rule/skill/model/plan versions and source observation references |

The `sections` object has named fields, not an arbitrary list whose ordering the
model controls. Its UI order is:

| Section | Consistent content across all domains |
| --- | --- |
| `summary` | Impact and confidence bands followed by a short conclusion; separate potential risk, current/peak observed impact, deployment outcome, attribution and coverage |
| `change` | What changed, relevant before/after values, effective-change decisions and uncertainty |
| `scope` | Configured devices observed after the initial collection window, expected consumers, selected monitored cohorts, downstream dependencies, selection reasons and scope gaps |
| `findings` | Tested hypotheses, measured facts versus inference, supporting/counterevidence, affected scope and current/recovered state |
| `evidence` | Charts, tables and other approved blocks linked to those findings |
| `timeline` | Change, per-device deployment, outage/recovery and collection/checkpoint events; distinguish occurrence and receipt times |
| `context` | Unrelated or excluded observations, visibly separate from attributed findings |
| `gaps_and_next_checks` | Unmapped paths, missing/unsupported/stale evidence, untested hypotheses and proposed remaining read-only checks |

Each section carries a state (`ready`, `pending`, `unavailable`, `not_applicable`)
and a reason where appropriate. An empty findings list with pending coverage must
not render as “no impact.” Summary classifications come from the referenced
assessment, not from model-written text or chart colors. Finding records carry
stable IDs, rule/hypothesis IDs, attribution status, evidence references and
eligibility for verdict contribution. Existing explicit exclusions apply to every
report section, caption and visual; excluded evidence belongs in `context`.

## Impact and confidence bands

Show two common indicators on each change row/card, in the impact view and at the
top of the report: for example **Impact: Critical** and **Confidence: Low**.
Use the existing impact vocabulary (`none`, `info`, `warning`, `critical`), with
`info` rendered as insufficient evidence rather than minor confirmed disruption.
Confidence uses `low`, `medium` or `high`, backed by component explanations. It
is an evidence-strength assessment, not a statistical probability or the model's
self-reported certainty. Keep attribution and coverage labels beside the bands.

The backend computes and persists both in the authoritative assessment; all three
views read the same assessment revision. The agent supplies referenced findings,
not final ratings. Report generation, chart rendering and frontend sorting must
not recompute them. Record the evaluation-policy version, component assessments,
source findings and a short explanation accessible from either indicator.

| Rating contract field | Meaning |
| --- | --- |
| `impact.band` | Nullable impact severity; headline peak observed impact during this investigation |
| `impact.current_band` | Nullable latest assessable impact, so recovery remains visible |
| `impact.state`, `impact.current_state` | `available`, `provisional`, `pending`, `insufficient` or `not_applicable` |
| `confidence.band` | Nullable `low`, `medium` or `high`; evidence strength for the current revision's headline peak-impact claim and its attribution |
| `confidence.state` | `available`, `pending`, `insufficient` or `not_applicable` |
| `confidence.components` | Structured evidence-quality and attribution factors with reasons and evidence references |
| `assessment_revision`, `policy_version`, `evaluated_at` | Shared provenance for both ratings |
| `explanation`, `limitations` | Why these bands were assigned and what remains unknown |

Use peak impact as the common headline in all three views, with “Peak during
monitoring” as its label/tooltip. For a recovered disruption, retain that peak and
show current impact and recovery separately. Confidence explicitly refers to the
headline claim; if current-impact confidence is later shown, persist it separately
rather than reusing peak confidence. Revisions may correct a peak when an earlier
finding is invalidated; preserve previous revisions and explain the correction.

Impact assessment considers service loss/degradation, affected device/client
cohorts, extent, duration and evidenced service criticality. Use versioned domain
policies: loss of infrastructure service cannot be dismissed because client count
is zero, and one critical service loss cannot be diluted by healthy unrelated
devices. Only eligible findings contribute. Deduplicate affected entities before
computing magnitude and combine domain severities by maximum, not addition.
Potential configuration risk and unrelated degradation do not raise the impact
band. A suspected causal association remains explicitly provisional.

Confidence evaluates source quality/freshness, required-check coverage and scope
localization, baseline comparability/sample sufficiency, dependency/temporal support,
and counterevidence or competing changes. Persist observation strength separately
from attribution strength in the components. The headline confidence cannot exceed
the weaker of those two components for the claim driving the peak; high-quality
measurements cannot mask an unsupported causal link. Required evidence depends on
the claim: direct PoE service-loss evidence need not await optional SLEs, whereas
“no observed impact” needs adequate required-check coverage over the window.
Correlated observations from the same source do not count as independent support.

Use a reviewed rubric: low confidence reflects weak or conflicting support;
medium reflects corroboration with material remaining uncertainty; high requires
the claim's required evidence, evidenced scope and dependency, and no unresolved
material contradiction. Missing enough evidence to assess confidence produces an
insufficient state rather than a default low rating. Freeze domain-specific
requirements against adjudicated cases and improve them through ongoing review.

Do not discount impact by confidence: a severe observed outage with uncertain
causation remains critical with provisional attribution and low confidence.
Use “No observed impact” only for adequately supported results in the assessed
scope/window, never for an empty device list, failed collection or unmapped change.
An incomplete investigation may still show a confirmed disruption with partial
coverage. Missing ratings display “Pending”, “Insufficient evidence” or “Not
applicable”; sorting keeps them distinct from supported no-impact results.

Defer 0–100 scores. The initial 20–50 adjudicated cases cannot establish meaningful
101-value resolution. Revisit numeric ranking only if operators request finer
ordering and validation demonstrates useful discrimination. It is not a rollout
prerequisite. Policy changes create labelled new assessment revisions, never
silent changes to historical ratings. Explain components on demand while keeping
the two headline indicators compact.

## Impacted devices and topology

The agent must explicitly identify impacted devices through structured finding
contributions over resolver-issued handles. The backend validates those contributions
and materializes `impacted_devices`; the UI never extracts identities or impact
from prose. This required list appears as an “Impacted devices” table within
`findings` and supplies the topology overlay from the same report revision.

Keep one record per canonical device within an investigation revision, with multiple
impact contributions when necessary. Resolve organization/site/device identity in
the backend and supply the canonical ID used by topology nodes. Names and MAC
display strings are labels, not model-selected join keys.

| Device impact field | Required meaning |
| --- | --- |
| `entity_ref`, `device_id`, `site_id`, `device_type`, `display_name` | Authorized entity handle and backend-resolved topology identity/labels |
| `configured`, `monitored` | Independent scope membership flags; neither proves impact |
| `impacts[]` | Individual domain-specific impact contributions, with the fields below |
| `current_severity`, `peak_severity` | Backend projection of eligible contributions using the shared evaluation policy, never sums |
| `coverage`, `evidence_as_of` | Device evidence completeness and freshness |

Each `impacts[]` contribution carries a stable ID, affected service/component
(for example port power, AP availability or WLAN client connectivity), a concise
reason, `observation_status` (`observed` or `suspected`), attribution
(`supported`, `plausible` or `undetermined`), current/peak severity, lifecycle
(`active`, `recovered` or `unknown`), onset/last-observed/recovery times with timing
uncertainty, finding/evidence references and any evidenced dependency path.
Suspected impact remains provisional; merely being a candidate is not sufficient
for an impact contribution. Recovery requires positive evidence, not disappearing
samples. Preserve recovered impacts for the report's historical window.

Contributions follow the same rule exclusions and verdict eligibility checks as
the assessment. Only change-related findings enter this overlay; unrelated device
degradation remains network context. A suspected association must not be displayed
as confirmed attribution. Record client-service impact on its evidenced serving
device/cohort without implying the entire device is down. If a finding can only be
localized to a site or unresolved client cohort, retain that finding and the
localization gap; do not assign it to every AP. A downstream AP may be impacted
even when `configured` is false.

The topology offers an overlay for the selected change and report revision. Keep
ordinary device health separate from the change-impact badge. Show severity with
an attribution label, distinguish suspected and recovered impact, and provide a
legend. Selecting a node opens its impact reasons, affected services, timestamps
and links to the corresponding report findings/charts. Allow filtering to impacted
devices, while retaining evidenced connecting nodes as neutral context.

Configured-only and monitored-only nodes receive their own scope indicators, not
impact badges. Missing or unassessed devices remain unknown; absence from
`impacted_devices` is never sufficient to paint a device healthy. Keep impact
records for devices missing from the current topology in a visible unplaced-device
list with source identity/time; do not invent links to position them. Cross-site
impacts remain in the report with navigation to the corresponding site.

When showing multiple changes, retain per-investigation contributions and links.
Do not sum severity or impacted-device counts across overlapping audits, infer
exclusive causation, or overwrite a shared device's assessment. Any combined badge
must be a backend projection under the same max-not-sum policy, with uncertainty
and concurrent changes visible. Topology, report table and summary counts use the
same validated records and revision; pagination includes explicit completeness and
deduplicated totals. Device lists and drilldowns share the existing authorization
and output budgets.

## Typed evidence blocks

All blocks share `id`, `kind`, `title`, `caption`, `finding_refs`, `dataset_refs`
and a typed `spec`. Dataset references must resolve within the pinned report.
Blocks use stable IDs across revisions where their meaning is unchanged. A
caption explains what a visual supports and its limits; it cannot supply new
unreferenced measurements. Context blocks may reference contextual finding IDs
but cannot change the assessment's attribution or affected counts.

| Initial block kind | Useful evidence | Validated specification |
| --- | --- | --- |
| `metric_comparison` | Baseline/current value and comparable delta | Metric, unit, cohort, baseline/follow-up windows, sample counts and evidence states |
| `time_series` | SLE rates, power draw, failures or availability over time | Timestamp/value fields, series, units, actual bucket intervals and deployment markers |
| `table` | Device states, interrupted clients, checks and before/after settings | Typed columns, source-backed rows, sort and bounded pagination |
| `bar_chart` | Failures by classifier or affected counts by cohort | Category/value fields, aggregation, unit and denominator where applicable |
| `histogram` | Distribution of latency, outage duration or another sampled quantity | Numeric field, unit, explicit bin edges/counts, sample window and missing/out-of-range counts |
| `event_timeline` | Configuration and operational events around deployment | Occurrence/receipt times, event types, entity references and timing uncertainty |

Do not force a chart into every report. A single source-backed table may be the
clearest evidence. Later block kinds, such as a dependency diagram or heatmap, need
a registered schema, data validation and renderer before the agent can request
them. A diagram may show only evidenced resolver relationships, with uncertainty;
it cannot turn a display hierarchy into proof of forwarding dependencies.

Each dataset records source observation IDs, cohort/entity references, time range,
field types/units, evidence states, completeness, sampling and transformations.
The agent proposes dataset references and approved view parameters; the backend
resolves observations and computes comparisons, deduplication, rates and histogram
bins. It rejects arbitrary model-supplied numeric series, unsupported transforms,
invalid columns or entity references, and incomparable baseline/follow-up inputs.
Preserve raw counters and denominators where relevant. Materialization and any
additional collection use the investigation's existing execution/output budgets.

Missing and no-traffic buckets remain explicit gaps, never zeroes. Time-series
aggregation must respect source semantics and sample weighting. Histograms require
raw samples or compatible source-provided bins: averages cannot reconstruct a
distribution. Baseline/follow-up histograms use identical bins and disclose sample
counts and whether the axis shows counts or proportions. Label truncation,
downsampling and partial scope. Axes expose units and scales; categorical bars and
histogram counts start at zero, and percentage-rate axes default to 0–100%.

## UI behavior and validation

Open the report from the change/audit detail. Device pages can link to the shared
report and filter its evidence, without creating another assessment. The overview
shows the shared impact/confidence bands, conclusion, deployment status,
attribution and coverage before evidence
details. Scope distinguishes configured, monitored and potentially affected sets;
none is implicitly substituted for another.

The UI renders validated blocks through application components; the report cannot
introduce HTML, JavaScript, executable chart expressions, arbitrary network data
URLs or custom components. Render names/captions as escaped text. Evidence links
resolve through authorized backend records. The same organization access checks
apply to reports, datasets, drilldowns and exports.

Every chart offers an accessible data table, keyboard-accessible interactions,
readable labels and a text interpretation. Evidence state and attribution use text
as well as color. Source details show scope, time windows, provenance and coverage.
An unrelated AP-health drop remains visibly contextual even if its chart is large.

During the initial configured-event collection window, display “Collecting
deployment events” with the current device count and freshness. Later revisions
update the same report; keep previous revisions available and label stale data.
Filtering or zooming changes the view, not the persisted verdict. Serve paginated
tables and chart drilldowns from the same snapshot so interaction cannot mix revisions.

Validate model output against one backend-owned schema before publication, then
validate references, evidence eligibility and numerical semantics separately.
Generate API/frontend types from that contract during implementation. Persist
renderer compatibility information with the schema version. Unknown optional block
kinds fall back to a source table/text with an explicit unsupported-view label.
An invalid block produces a visible rendering/validation gap; an invalid envelope
cannot replace the last valid revision. Do not erase deterministic findings when
model formatting fails, and do not show the previous revision as fresh. Any repair
attempt consumes the existing agent budget.

## Investigation log view

Provide a “Logs” tab beside the structured report, reachable from the change and
impact views. Group entries by investigation checkpoint/agent turn, with expandable
logical checks and individual attempts. Use the executor journal defined in the
main design; report generation must not summarize away the underlying log entries.

The list shows timestamp, tool/check name, target scope, outcome, duration and retry
count. Filters cover turn, time range, tool, device/entity and status, including an
errors-only view. Open an entry to inspect sanitized request arguments, response
JSON or retained payload, error details, validation decisions, pagination/cache
information and budget usage. Clearly mark content that was redacted, truncated,
omitted, expired or never returned. Display an interrupted request as unknown
outcome rather than complete. Use server-side pagination and bounded payload loading.

Support navigation in both directions: finding/chart → source evidence → collector
or MCP call, and call → resulting evidence/findings. Calls yielding no findings
remain browsable. Shared collections retain provenance across linked investigations
without exposing another organization's records. Logs can explain a failed or
incomplete investigation even when no agent report exists.

Offer a bounded sanitized JSON export containing correlation IDs, attempts,
retained payloads and truncation/retention metadata for debugging. Apply the same
diagnostic authorization and redaction to UI, payload endpoints and exports.
Inspecting, expanding or exporting a log entry is read-only and must never rerun
the recorded MCP request. Keep the normal report's evidence explanations concise;
technical execution details live in this dedicated view.

## Delivery and acceptance

Build this contract and the shared audit report UI with the investigator shadow
runtime, before enabling its user-facing reports or notifications. Use sanitized
fixtures from the four v1 domains to exercise the same section structure. Start
with the six block types above; adding a domain should not require a new page.
The report work does not depend on the deferred OAS library or MCP adapter.
Deliver the same rating fields and labels in the changes view, impact view and
report header, including loading, unavailable, provisional and recovered states.
Persist execution logs with the first runtime prototype, before the log UI exists.
Add the Logs tab and sanitized export as the diagnostic UI phase; provide access
for shadow evaluation so failures can be reviewed before rollout.

Required checks cover all four domains, pending/partial/final revisions, missing
buckets, unequal sample sizes, histogram bin consistency, excluded contextual
evidence, late configured devices, overlapping audits, unknown block versions,
invalid references, misleading configuration names and bounded large tables.
Verify that every displayed value traces to the pinned evidence, all severity
badges agree with the persisted assessment, and 200 configured devices still
produce one report. Verify identical impacted-device records/counts in the report
and topology, including downstream unconfigured APs, suspected/recovered impacts,
client-only disruption on an otherwise healthy AP, missing topology nodes,
unlocalized cohort findings, partial lists and overlapping audits. An unused SSID
removal plus unrelated AP-health degradation must not produce a change-impact
badge on that AP. Exercise responsive layouts, accessible chart tables and
revision changes in UI tests. These are future acceptance requirements, not tests
claimed to pass for the current device views.
Rating acceptance also verifies agreement across all three surfaces, peak/current
recovery behavior, unavailable versus supported no impact, exclusion of unrelated SLE changes,
no confidence discounting of impact magnitude, low attribution confidence despite
strong outage measurements, policy-version replay and no count/severity inflation
from duplicated observations or overlapping cohorts.
Log-view checks cover failed investigations without reports, request/response/error
inspection, per-attempt retries, evidence navigation, pagination, expired payloads,
secret redaction and organization/diagnostic authorization for views and exports.
