# Configuration library and impact monitoring

The **Objects & versions** navigation entry opens a searchable catalogue, with type,
site and scope filters computed from the entire organization catalogue. Open an
object to see its versions. Choose Before and After to compare any two versions,
or Restore on a version to preselect it in the same page. Choose **Build restore
plan** to create and review a plan. Opening, refreshing or navigating between
version links never creates a plan automatically. Legacy `/restore`
and `/history/restore` links preserve their context and redirect into this flow.
Planning does not execute a restore; the existing write authorization, approval
and execution steps still apply.

Administrator settings changes use the existing authenticated administrator
session and CSRF protection. They no longer require re-entering an account password.
Stored credentials remain encrypted. Account authentication and restore execution
authorization retain their separate checks.

Comparison normalization omits `created_time`, `modified_time`, `image1_url`,
`image2_url`, `image3_url` and `thumbnail_url` recursively. Functional `url`
fields remain visible at every depth, including webhook destinations. This applies to
structured comparisons, comparison JSON and patches. Original stored snapshots
and restore payloads retain those fields.

The raw JSON comparison aligns matching lines and keeps each version's original
line numbers. Removed text appears in red with a minus marker; added text appears
in green with a plus marker. Replacements show both. The taller, resizable viewer
also opens in a full-screen dialog; Escape returns to the inline view and preserves
the scroll position. Protected values remain redacted, so identical placeholders
are not presented as confirmed raw-text changes.

## Timing

Impact assessments now persist the verdict, evidence coverage, relevance plan and
per-metric comparison together. API views read that result; older sessions use one
explicit compatibility projection. Scalar severity/summary fields remain mirrors
for existing indexes and clients. Current monitoring passes `legacy_all`, preserving
the existing evidence selection until audit-specific rules are implemented.

Metric rows include the union of planned and recorded metric identities, including
failed or unsampled metrics. Each side records its evidence state and nullable
value; missing values never render as zero or receive an invented delta. Known
scope identities must match. Collection-wide discovery failures remain separate
from metric failures. An explicitly empty relevance plan selects no evidence;
selected plans independently filter SLEs, incidents and operational finding kinds.

API compatibility: `ImpactMetric.baseline` and `latest` are now nullable, as is an
unavailable delta. External clients must accept null and use evidence state instead
of assuming every row contains floats. Regenerate clients from `docs/openapi.json`
before adopting this contract; null must not be converted to zero.

The site view uses `error` health for failed monitoring/deployment sessions unless
their assessment is already critical, which remains critical. This lifecycle
presentation keeps failures filterable without changing the stored impact verdict.

The legacy Changes-view baseline-confidence band counts only observations with
complete comparable evidence for the selected metrics. Failed, unsampled,
incomparable or unselected observations do not increase the count; an unusable
latest comparison keeps confidence low. This is a collection/comparison quality
heuristic, not causal confidence. Group metric tiles retain the actual worst
comparison and unique affected-scope counts, keeping site and device scopes
separate. They do not average healthy and degraded devices.

A supported Mist `device-events` configuration trigger immediately starts an
active monitoring session. Guardian requests device-scoped SLE summaries for the
24 hours preceding the source event timestamp, retains every bucket of that
window, and captures current operational state concurrently. The first
operational follow-up is due five minutes after the initial capture. SLE polls run every five minutes for at least one hour; receipt
of the configured event guarantees a further hour from that point. A missing
configured event no longer prevents collection.

Switch collection first calls `/sle/{scope}/{scope_id}/metrics` at the same
site/device scope. Only recognized switch metrics listed as both supported and
enabled are requested. This avoids assuming every deployment exposes
`switch-stc-new`. Advertised underscore/hyphen spellings are used verbatim in
request paths and normalized to the existing stored metric keys. Discovery
failures, empty eligible sets and errors for advertised metrics remain explicit
collection failures; they are never treated as quiet traffic or healthy evidence.
Existing persisted errors are retained as historical collection evidence.
See Juniper's [SLE metric discovery reference](https://www.juniper.net/documentation/us/en/software/mist/api/http/api/sites/sles/list-site-sles-metrics).

Source timestamps are accepted from 24 hours before receipt through one minute
after receipt (clock skew). Missing, malformed or out-of-range timestamps fall
back to receipt time. These bounds use the persisted receipt time so queue delays
and retries cannot change which timestamp is selected.

A switch or gateway configuration-reverted event ends that change's session as
failed with critical severity and cancels further polling. The reverted configuration
is no longer under test. The next configuration trigger starts a separate session
with a fresh baseline and its own hour of monitoring; it cannot extend the reverted
change's window. Retrying the revert receipt does not duplicate the incident.

SLE aggregation remains the mean of valid bucket success rates. The baseline
keeps every bucket of its 24 hours as a stored trend and the Impact chart draws
them, so the window before a change is visible rather than implied. The figure
the verdict compares against is the mean of the final hour of that window, not
of the whole day: a post-change poll measures minutes to an hour, and a 24-hour
mean smooths across a day/night cycle the change had nothing to do with. A final
hour with no sampled traffic widens back to the whole window, and the Impact page
labels which of the two the figure came from. A measured 0% is an outage and is
reported as one; only an unsampled tail widens. Post-change polls are not
anchored and keep averaging everything they measured since the change. Sessions
stored before this retain their whole-window baseline mean, carry no trend, and
are drawn and labelled as the single average they are.

Observations now record whether their scope is a site or a device. Legacy baselines without that field default to site scope and continue
polling site SLE; new device baselines continue polling device SLE. Different
scopes are never compared. HTTP failures, malformed responses and unexplained
missing metrics prevent a clean verdict and appear explicitly in the Impact page.
A legacy baseline with unknown scope identity cannot be compared to a newly
identified observation. Preserve the known identity and both measurements, omit
the delta, mark coverage insufficient and record a session warning.
Valid responses with no sampled traffic are recorded in `no_data`, separately
from `errors`. They contribute to collection coverage but receive no invented
success rate or numeric delta. A quiet roaming or join metric therefore does not
block a clean result for the other measured metrics. A clean verdict still requires
at least one metric measured on both sides. If a previously measured device becomes
silent, both windows are unsampled, or their measured metrics do not overlap, the
result is INFO: insufficient evidence, rather than an assertion of health.
Disruptive device evidence and incidents still take precedence over quiet SLEs.

Actual collection happens when the worker processes the webhook and when the
scheduler processes due work. Recorded capture times make delays visible. The
historical SLE baseline can be recovered from Mist after a delayed event, but
current-state APIs cannot reconstruct a radio, client or interface snapshot from
before the webhook was received. A configured event without its preceding trigger
therefore carries an explicit warning.

Repeated processing of the same receipt is idempotent. Further configuration
triggers for an already monitored device receive separate initial/follow-up
comparisons and extend monitoring by another hour. SLE and incidents describe
the combined window, so the UI warns about overlapping changes. Findings describe
observed changes, not proof that a particular configuration edit caused them.

## Collected evidence

All paths below are relative to `/api/v1/sites/{site_id}` and use the organization's
read-only Mist service token and configured regional host.

| Device | Sources |
| --- | --- |
| AP | `/stats/devices/{device_id}` including RF statistics; `/stats/devices/{device_id}/clients`; `/wlans/derived` |
| Switch | Device statistics; `/stats/ports/search`; `/stats/bgp_peers/search`; `/stats/ospf_peers/search`; `/wired_clients/search` |
| Gateway | Device statistics with `fields=tunnels,vpn_peers`; interface, BGP and OSPF searches |

Routing peers and wired-client searches use the preceding five minutes, filtered
by device MAC. Latest timestamped records determine peer state. Derived WLANs
are configured **site** SSIDs; radio statistics provide the device's advertised
WLAN count. They are not presented as an exact per-AP WLAN configuration list.

Deterministic findings include removed or disabled SSIDs and their initially
observed clients, occupied ports going down, lost BGP/OSPF neighbors or tunnels,
VPN loss increases, substantial interface error increases, radio loss or reduced
WLAN counts, high RF utilization, device disconnects/restarts, and sharply rising
CPU or memory usage. Ordinary client roaming alone does not imply an outage.

Each source explicitly reports successful coverage or an error. Permission,
licensing, connectivity, malformed responses and incomplete pagination remain
unknown and cannot be interpreted as removed resources. Collection is bounded to
five pages of 1,000 records per source. Pagination URLs must retain the exact
regional origin and endpoint. Only allowlisted operational fields are persisted;
raw configuration, credentials and provider error bodies are discarded.

The Impact page shows source counts while collapsed. Expanding a source mounts
two independent, paginated capture tables, with at most 50 records each. Only the
visible page is formatted; first/previous/next/last controls expose every collected
record. Closing the source removes its tables. Pending, unavailable and successfully
captured empty sources remain distinct.

Device comparisons and findings appear even when SLE is unavailable. Their
severity contributes to the deterministic result and derived evidence is included
in optional AI assessment. The five-minute findings remain historical evidence;
a subsequent recovery event does not erase what the captures recorded.

## API references

Endpoint contracts were checked against Juniper's [official Mist OpenAPI
specification](https://github.com/mistsys/mist_openapi) and [OSPF statistics
reference](https://www.juniper.net/documentation/us/en/software/mist/api/http/api/sites/stats/ospf/search-site-ospf-stats).
Availability depends on the device family, firmware, subscriptions and service-token
privileges. Automated tests use documented response shapes and mocked HTTP; live
Mist behavior still needs a read-only check against a live tenant; mocked HTTP
and documentation checks do not establish live endpoint compatibility.


The committed OpenAPI document is generated with `make openapi` and validated by
`make check`. Its version comes from the backend package, independent of the
working directory, local `.env` files and `APP_VERSION` overrides.


## Audit-owned WLAN shadow preview

`IMPACT_ENGINE_MODE=shadow` enables the first deterministic audit investigation.
Set the same value on the API and worker processes and restart them; the default
is `legacy`. This does not enable an AI investigator or change the published
impact/notification verdict. It suppresses the old per-device AI narrator while
legacy deterministic monitoring continues for comparison.

New audit receipts create one investigation per organization/audit. Initial
collection waits 60 seconds. The existing worker tick services subsequent
checkpoints around +10 through +60 minutes from the audit timestamp. A retry or
late configured event does not create another investigation or reset its budget.

The first rule recognizes site WLAN deletion or disablement from immutable
configuration versions and scopes historical client-session queries by site and
WLAN UUID. Unsupported attributes, organization WLAN consumer assignment,
missing history, changed incarnations and exhausted limits remain visible gaps.
Historical disconnects are possible disruption, not proof of AP failure or
causation. AP health and aggregate site SLEs cannot enter this rule's verdict.

In **Changes**, open a change and choose **Review shadow evidence**. The on-demand
preview shows impact/confidence bands, scoped findings, serving AP identities,
coverage gaps and normalized collection outcomes. It does not expose raw client
identifiers. It is available only in the current view, and is a diagnostic preview
rather than the final common report/chart contract or a topology impact overlay.

In shadow mode, Changes rows, change details and the Overview feed also show a
shared compact audit assessment: result, confidence, session-evidence coverage
and report revision. Expanded summaries include the evidence timestamp, policy,
gaps and unmapped-attribute counts. A stopped investigation cannot present an
earlier clean checkpoint as a completed clean investigation.

Overview's **Shadow review** counts describe only the returned feed (up to 50
changes), including rows hidden by its local actor/impact filter. They partition
that feed into possible disruption, no observed disconnect, insufficient evidence,
awaiting evidence, unavailable assessment and no investigation recorded. They are
not organization-wide outage counts. Production badges, filters, aggregate totals
and notifications continue to use the legacy projection until acceptance.

API additions: change summaries/details expose `impact_source` and nullable
`shadow_impact`; Overview exposes nullable `shadow_feed_counts`, and its existing
`counts` identifies `impact_source`. Historical impact sources are null. In legacy
mode or historical views, the shadow fields are null and no shadow batch reads run.
In shadow mode, a missing investigation is an explicit `not_recorded` result, not
null or a clean verdict. An unreadable publication is `unavailable`. The detailed
investigation response also includes the same compact `shadow_impact` contract.
These are additive fields; existing severity fields retain their meaning.

Queries are read-only, limited to four WLAN targets, 56 requests per audit and one
bounded page per check. Current organization status, credential identity, budget
and worker lease are verified before each request. Each published revision pins
its normalized evidence; repeated checkpoints retain separate immutable artifacts.
The preview follows only the published root pointer, never a losing worker's
unpublished artifact. Full MCP journaling, retention cleanup, historical report
navigation, the AI tool loop and production migration remain future work.

Implementation decisions and rollout gates are recorded in
[impact-implementation-decisions.md](design/impact-implementation-decisions.md).
