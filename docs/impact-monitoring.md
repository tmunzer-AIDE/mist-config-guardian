# Configuration library and impact monitoring

The **Objects & versions** navigation entry opens a searchable catalogue, with type,
site and scope filters computed from the entire organization catalogue. Open an
object to see its versions. Choose Before and After to compare any two versions,
or Restore on a version to review its plan in the same page. Legacy `/restore`
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

## Timing

A supported Mist `device-events` configuration trigger immediately starts an
active monitoring session. Guardian requests device-scoped SLE summaries for the
24 hours preceding the source event timestamp and captures current operational
state concurrently. The first operational follow-up is due five minutes after the
initial capture. SLE polls run every five minutes for at least one hour; receipt
of the configured event guarantees a further hour from that point. A missing
configured event no longer prevents collection.

SLE aggregation remains the mean of valid bucket success rates, matching existing
stored baselines. Observations now record whether their scope is a site or a
device. Legacy baselines without that field default to site scope and continue
polling site SLE; new device baselines continue polling device SLE. Different
scopes are never compared. HTTP failures, malformed responses and unexplained
missing metrics prevent a clean verdict and appear explicitly in the Impact page.
Valid responses with no sampled traffic are recorded in `no_data`, separately
from `errors`. They contribute to collection coverage but receive no invented
success rate or numeric delta. A quiet roaming or join metric therefore does not
block a clean result for the other measured metrics; an entirely unsampled window
is explicitly labelled as having no sampled traffic. Disruptive device evidence
and incidents still take precedence over quiet SLEs.

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
