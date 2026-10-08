# Configuration events and impact evidence

The navigation unit is an administrator's configuration change, identified by
`organization_id + audit_id`. Devices receiving a template deployment appear
beneath that event. The existing audit change group supplies its title and audit
time; device windows supply configuration events and operational evidence.
Devices sharing only a timestamp, name, or site are not enough to establish
causation. Uncorrelated device changes stay explicitly uncorrelated.

## Workspace

Overview shows period-wide change/disruption/recovery counts and a recent feed.
Feed filters are explicitly limited to that feed; the Changes workspace provides
server-side search, severity filters and pagination across the full period.
Selecting a change opens a focused outcome page with the change identity and
return action pinned above its scrollable work area. Four local sections keep
Outcome, Configuration, Timeline and Technical evidence in the same context.
The selected section is retained in the URL; a full version comparison or legacy
device link carries a direct return to the originating change.

The Outcome section answers the operational questions first: what needs
attention, why it was flagged, whether deployment recovered, what service impact
was actually measured, and what evidence is missing. Deployment events do not
increment the measured-degradation count. A comparable, selected metric must
cross the existing ten-percentage-point warning threshold for that count.
Unmeasured application traffic remains explicitly unknown. Historical peak,
latest recorded outcome and live connectivity are distinct facts.

Incident status, event/recovery times, overlapping changes and AI interpretation
appear before topology and raw captures. Stored AI commentary stays labelled as
an interpretation; severity or metric-direction conflicts are flagged for review.
The current Guardian summary can load automatically, while its full investigation
and attempts expand locally. These are existing read APIs, bounded to twenty
monitoring windows with explicit omissions and retry feedback. Critical and
warning device windows are prioritized within that limit.

Device lists are the default for both the selected change and Sites & devices.
Topology is an optional local view using the existing observed-link canvas.
Its colors describe recorded findings for the selected change; outside devices
remain unknown. It does not establish live health or causation. Device evidence
can be expanded inline, and full captures/timelines are available in local change
sections. Restore activity also has a direct navigation entry; contextual rollback
still uses the existing plan, backup, authorization and execution workflow.

The time bar remains on period-based lists and inventory. A selected recorded
change uses its own timestamps; historical mode retains its explicit banner.
The browser and application frame do not scroll. Feeds, work areas, device details,
version/comparison panes, forms and restore plan/authorization each own their
scrollport. On compact overview layouts the summary also has a bounded scrollport
so the feed and attention rail remain reachable. Chromium rails are 4px; Firefox
uses its native thin rail.

### Information hierarchy and journey

| Information | Priority and purpose | Default placement |
| --- | --- | --- |
| Latest recorded outcome, unresolved finding, recovery and evidence age | Immediate triage: decide what needs attention | Change header and outcome summary |
| Deployment status, measured service impact, application evidence gaps | Avoid conflating a failed deployment with a service decline | Three separate outcome facts |
| Incident/recovery event, attribution limits, next action and AI interpretation | Explain the verdict and support an administrator's decision | First outcome section, before raw telemetry |
| Affected sites/devices and changed configuration | Identify scope and inspect the proposed cause | Inline device selection and local Configuration section |
| Event chronology, metrics and operational captures | Validate a finding without losing the selected change | Local Timeline and Technical evidence sections |
| Raw IDs, collection metadata and full AI attempts | Diagnose collection or interpretation issues | Explicit disclosures within those sections |
| Backup state, restore plans/approvals/progress | Assess recovery readiness and safely act | Overview attention rail, direct Restore activity and contextual rollback |
| Organization, time context, account and settings | Maintain scope and configure the application | Fixed transparent chrome and dedicated form panes |

From the Changes list, the outcome and its reason take one selection. Configuration,
timeline or technical evidence each take one local section switch. Selecting a
device exposes its measurements inline. A full comparison provides a direct
return to the same change. Rollback planning remains in that change's context
through authorization and progress. No diagnostic step requires traversing a
sequence of unrelated pages.

The shared navigation and top bars sit directly on one neutral background,
without enclosing borders or colored bands. Main content cards and tables use
soft shadows; detail panes and floating menus sit a level higher. This shared
styling also applies to Configuration, Site topology and Settings. Historical
mode remains explicit through its warning text, marker and return-to-live action.
Use direct, descriptive headings and reserve color for states and controls.
Avoid decorative status rails, duplicate severity dots, slogan overlines,
numbered section labels and illustrative network diagrams. The interactive
topology remains an evidence view; its dashboard shortcut is a plain navigation
card. Recent changes communicate severity through their labeled badges.

Desktop previews use synthetic browser-test fixtures:
[overview](change-overview-preview.png),
[recorded outcome](change-outcome-preview.png), and
[rollback review](change-rollback-preview.png). The shared flat styling can also
be seen in [Site topology](flat-shell-topology-preview.png) and
[Configuration](flat-shell-configuration-preview.png).

## Change detail API and rollback

`GET /organizations/{organization_id}/change-groups/{id}` adds `site_impacts`
and `missing_monitoring_sessions`. Each site has its ID, display name, lean
device-window summaries and separately listed `unmonitored_devices`. These
fields reuse the existing organization-scoped session read and the same evidence
projection as the site workspace; no raw configuration or telemetry is exposed.
Reach is the union of linked sites, changed objects and linked devices, not a
prediction that every site receiving an organization template was affected.
Historical reads withhold these mutable impact fields. Older servers without the
fields degrade to linked identities with unknown impact in the browser.

“Review rollback” explicitly creates a non-destructive plan using captured
before-version IDs and dependencies. Objects without previous versions are
counted as exclusions before planning and during review. Planning writes no
configuration. The existing restore review, fresh-backup preparation, final
confirmation, approvals, MFA, worker execution and verification run in the same
change pane. Operation IDs remain in the URL for reload/recovery. Advanced
target selection remains available on request. Closing the pane does not cancel
an already queued operation.

Monitoring windows currently have one active slot per device. Overlapping audits
can therefore share a window; its evidence appears under each linked event and
the detail warns that attribution is not exclusive. Group counts describe the
loaded device windows, and further windows can be loaded. They are not advertised
as an exhaustive count of configuration events across the entire database.

A future event-native read model should paginate audit groups first, return lean
device summaries, and fetch evidence on selection. A separate device-window
association would allow a window to reference several causal candidates without
duplicating telemetry. Do not split windows into falsely independent assessments
when changes overlap: keep the ambiguity visible.

## Current state and history

The first operational comparison remains immutable historical evidence. Starting
five minutes after the trigger, each SLE poll also refreshes operational state.
The latest findings drive the current assessment; the first findings, highest
observed severity, and recovery timestamp remain visible separately. Interval
facts (a reboot or rising error counter) use successive observations rather than
continuing to report the same old increment forever.

Loss of PoE on a previously powered, linked port is critical even if the
connected device's identity and client count are unknown. Confirming its recovery
requires a fresh linked-and-powered reading. Failed source collection or missing
port fields cannot clear that alarm. SLE evidence remains independent: clearing
an operational outage does not turn absent numeric SLE evidence into health.

Completed sessions describe their monitoring window, not perpetual live device
health. Recovery after a window has closed requires a subsequent observation;
old historical sessions are not rewritten to claim a recovery they never saw.
The Site topology workspace refreshes its selected device every 30 seconds.
The change workspace displays evidence from its latest read, refreshed through
“Refresh evidence”. Backend collection continues on the existing five-minute
cadence for at least one hour.

## Timeline

Persist raw configuration lifecycle event types with both source event time and
webhook receipt time, plus audit and assessment transitions. Display actual
capture, confirmation, recovery and completion times in order. Older sessions
use their stored trigger/confirmation timestamps where individual events were
not retained. Never infer “received by device” or “deployment confirmed” solely
from a collector receipt. Missing stages remain missing.

## SLE collection

Use the exact scope's supported and enabled metric list for APs, switches and
gateways. Preserve advertised URL spelling while keeping canonical stored metric
keys. Do not fall back from device to site measurements within a session.

Reference: [Mist listSiteSlesMetrics](https://www.juniper.net/documentation/us/en/software/mist/api/http/api/sites/sles/list-site-sles-metrics).

A 404 remains a collection error, with the requested endpoint included for
diagnosis; provider response bodies and tokens are not exposed. Quiet metrics
remain separate from request failures. Existing baseline errors are historical
and are not erased when collection code changes. Tests cover the published API
contract; the remaining 0.6.4 production 404s still require an exact current error
line or a read-only live capture to establish their cause.


## Confirmed changes and network-impact eligibility

Overview, Changes, search and site change history filter out audit groups with
no captured object differences before counting or pagination. Raw receipts and
configuration versions remain available for diagnosis. A direct link to an
unlinked audit can still explain the missing capture; it offers no empty
rollback workflow.

The [network-impact policy](network-impact-policy.md) classifies all currently
backed-up object types. Administrative/location changes remain in configuration
history, with `impact_validation: excluded`, a reason and a `NOT APPLICABLE`
badge. Their unrelated device windows and old Guardian results are not presented
as impact evidence. New excluded audits do not start Guardian investigations;
excluded audit-linked events do not open or merge a monitoring window.

SLE observations now retain `sample_counts` for the same anchored window as their
numeric values. A zero total is no data; a legacy zero percentage without a
positive sample total is unavailable. It supplies no numeric delta, degraded
metric, chart point or network-health claim. A measured zero with positive
traffic samples remains eligible for a degradation alarm. Independent incidents
and device findings remain valid evidence. Existing unsupported zero verdicts
are corrected by read projections without changing their source observations.

The existing scheduled projection backfill upgrades groups to
`impact_policy_version: 1` in batches of 200 every 15 minutes, repairing old severity/count
projections. Raw receipts, immutable versions and monitoring records are not
removed. Tests use mocked Mist responses; live source validation was not run.

The assessment describes the metric, before/after percentages, percentage-point
change and exact scope identity. Device colors report observed degradation in
the window, with an explicit statement that this does not establish causation.
See the [excluded asset-filter preview](excluded-network-validation-preview.png).

## Deployment incident recovery

Within one device monitoring window, an observed later AP/SW/GW CONFIGURED event
closes the matching CONFIG_FAILED incident. Provider event time takes precedence
over receipt time, including late delivery. A prior success, a different device
kind or a revert does not close a failure; a subsequent failure stays open.
Ambiguous or incomplete historical ledgers do not infer recovery. Historical
peak and operational findings are retained; recovery never manufactures missing
SLE measurements or rewrites stored AI text.

Current reads reconcile affected legacy records on a copy. Projection policy
version 2 also uses the existing idempotent background backfill, bounded to 200
groups per run, so cached list filters and counts converge. Raw receipts,
configuration versions and monitoring observations are retained. Resolution in a
different closed monitoring window is not inferred by this reconciliation.
