# Configuration events and impact evidence

The navigation unit is an administrator's configuration change, identified by
`organization_id + audit_id`. Devices receiving a template deployment appear
beneath that event. The existing audit change group supplies its title and audit
time; device windows supply configuration events and operational evidence.
Devices sharing only a timestamp, name, or site are not enough to establish
causation. Uncorrelated device changes stay explicitly uncorrelated.

## Workspace

Objects default to latest capture first, with server-side sorting before
pagination. Objects and Changes have independently scrolling tables bounded by
the available viewport. Selecting a change opens a second scrolling pane within
the same viewport. Impact has collapsible audit groups, device selection, the
latest verdict, and a timeline of observed lifecycle events.

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
The selected device refreshes in the UI every 30 seconds. Backend collection
continues on the existing five-minute cadence for at least one hour.

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
