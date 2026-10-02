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
Selecting a change turns the list into a narrow navigation rail. Its main pane
combines redacted before/after configuration values, known cross-site reach,
site selection, topology, and per-device evidence. On small screens the list
gives way to the detail, with a focused return action and section shortcuts.

The embedded topology uses the same routing algorithm as Site topology, with
empty tier rows removed and tighter spacing. It still shows only observed
connections. Its colors describe evidence for the selected change; devices
outside that change have unknown impact, even when currently connected.
The device list is an alternative to selecting a node. Shared monitoring
windows, missing measurements and completed historical windows stay explicit.
Refresh evidence reloads the selected change; full device timelines remain a
deliberate drill-down.

The time bar keeps Live, exact-date and period controls visible. Expand
“Explore time” for the activity slider and event navigation.

The shared navigation and top bars sit directly on one neutral background,
without enclosing borders or colored bands. Main content cards and tables use
soft shadows; detail panes and floating menus sit a level higher. This shared
styling also applies to Configuration, Site topology and Settings. Historical
mode remains explicit through its warning text, marker and return-to-live action.

Desktop previews use synthetic browser-test fixtures:
[overview](change-overview-preview.png),
[change workspace](change-workspace-preview.png), and
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
