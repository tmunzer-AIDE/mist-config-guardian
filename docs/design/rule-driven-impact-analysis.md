# Hybrid configuration impact analysis

Status: revised design, 2026-09-12. Delivery steps 1–2 are implemented in the
working tree: explicit relevance-plan seam, per-metric evidence states and one
persisted assessment with legacy compatibility projection. New monitoring still
uses `legacy_all`; no attribute rules, agent or MCP integration are enabled.
Recommended direction: a small deterministic evidence layer, four initial rules,
and a bounded agent that investigates changes through read-only tools. An exhaustive
attribute catalogue and a complete dependency graph are not delivery prerequisites.
The future matrix below describes candidate effects, not implemented coverage.

## Objective

Assess a configuration change using evidence relevant to its actual effects.
Every assessment must explain the chain:

**Changed setting → effective configuration change → affected dependencies →
selected evidence → observed impact and attribution confidence.**

Keep potential risk, observed service impact, deployment outcome, and confidence
separate. A potentially disruptive edit is not evidence of an outage. Conversely,
an infrastructure outage can matter even when there are no connected clients.

## Original findings before steps 1–2

- `services/impact_analysis.py:assess_impact` receives SLE observations, incidents,
  and device findings, but no configuration diff or relevance plan. Any compared
  SLE dropping 25 percentage points can make the result critical; 10 points can
  make it a warning. Any critical operational finding or unresolved critical
  incident can also make the result critical without a setting-specific check.
- `integrations/mist_sle.py` discovers supported/enabled metrics at the requested
  scope, intersects them with a device-family allowlist, then collects that set.
  Discovery checks availability, not relevance to the change.
- `services/device_impact.py` compares all successfully collected operational
  sources. Its observations can be valuable, but require the same relevance
  filtering as SLEs before contributing to change attribution.
- `services/site_impact.py:impact_from_session` builds metric rows from the
  intersection of baseline and latest numeric values. An unmeasured metric can
  disappear from that list even when collection errors are reported elsewhere.
- `integrations/mist_topology.py` supplies observed device/port adjacencies. Its
  display hierarchy is explicitly a layout convention, not proof of forwarding
  or service dependency.
- Monitoring already retains baseline trends, operational evidence, lifecycle
  events, current/peak severity, and warnings for overlapping changes. Preserve
  these capabilities while changing how evidence is selected and evaluated.

These findings explain a route to the reported false attribution; they do not
establish the cause of a particular production event or missing API response.

## Sparse rules and explicit coverage

Start with rules matching object types and attribute paths, backed by real payload
fixtures. Every unmatched path produces `unmapped` in the current assessment,
including when mapped parts of the same change can be assessed. This is a result
state, not merely a backlog item. Agent investigation may produce useful findings
for an unmapped path without changing its deterministic coverage status.

The official OpenAPI and snapshot registry help validate individual mappings as
they are added. Pin the source revision, but do not extract every possible field
before shipping. Spec coverage cannot establish coverage of the live product.

Each catalogue entry records:

| Field | Purpose |
| --- | --- |
| Object scope/type, schema revision, attribute path | Identify the setting unambiguously; normalize variable keys and array identities |
| Applicable device family, firmware/capabilities | Avoid applying unsupported semantics |
| Default, inheritance, override and deletion behavior | Determine whether the effective configuration changes |
| Semantic change types | Add, remove, enable, disable, modify, reorder, assignment, reference change |
| Rule IDs and effect domains | Connect the attribute to reviewed impact rules |
| Coverage status and rationale | Mapped, explicitly non-service-affecting, unsupported, or unmapped |
| Evidence requirements and availability | State what can actually be measured and at what scope |
| Source references, examples, owner and tests | Make future changes reviewable |

Future coverage may include registered organization/site objects such as:

- Site templates, WLAN/configuration templates, RF/AP/network/gateway templates;
  AP/switch/gateway device profiles; site/organization settings; site assignments;
  and per-device configuration.
- WLANs, networks, PSKs, NAC rules/tags/portals, WxLAN rules/tags, services and
  service/security policies, VPNs, Mist tunnels and Mist Edge objects.
- Referenced antivirus, IDP and security-intelligence profiles.
- Administrative, integration and location objects: SSO/roles, webhooks, alarm
  templates, maps/zones, assets and beacons. These need explicit classification;
  they must not inherit network SLE monitoring merely because they changed.

Do not declare an entire object harmless: a display name may be cosmetic while a
referenced name, site country, assignment, schedule or timezone can affect behavior.
Include raw CLI/custom configuration as an explicit partial/unknown coverage case.
Never infer the safety of opaque commands from a few keyword matches.

Measure coverage against observed changed paths and observed changes, with the
denominator and period shown. Report partial coverage, unmapped and unsupported
counts separately. A spec-relative count is optional inventory information, not
an acceptance criterion or evidence of completeness. Unmapped paths cannot inherit
a healthy result from mapped paths, even when no outage has been observed.

## Effective changes and dependency resolution

Evaluate the before and after effective configuration, including inherited values,
site variables, profile assignments, local overrides and referenced objects.
Deleting an override can restore an inherited value rather than disable a feature.
A template change can be suppressed only when known object-specific merge/replace
semantics prove that the before and after effective values are identical. A local
override alone is not sufficient proof. **Unknown inheritance, merge, assignment or
applies-to semantics mean assume effective**, retain candidate consumers and show
the uncertainty. This preserves monitoring eligibility, not a presumption of harm.
Follow reference changes even when the consuming object's own JSON is unchanged.

Use complete semantic differences, not truncated UI diff entries or redacted JSON
patches that can hide secret changes. Reuse the existing secret-change fingerprints
without persisting plaintext. Preserve unknown comparisons as unknown. Collection
order is irrelevant for sets; policy/ACL order can change first-match behavior.

V1 has exactly two resolver families: configuration inheritance/consumer assignment
for explicitly understood cases, and physical port → powered-device association
using observed identities. Neither promises complete discovery. Missing assignments
retain known candidate consumers and an unresolved-scope state. WLAN/client source
filtering uses observed identities; it is not a VLAN or service-path resolver.

Do not build a general graph service in v1. The agent can retain evidence-backed
relationships per investigation. The longer-term dependency model may include:

- Configuration: template/profile → site/device, object reference → consumer.
- Physical: switch port → powered AP/device, links, LAG members and redundant paths.
- Logical: port/WLAN → VLAN → subnet/VRF → gateway/route; distinguish management
  traffic from client traffic and IPv4 from IPv6.
- Service: cohort/flow → authentication, DHCP, DNS, security policy, NAT, VPN,
  application and WAN path. Include cross-site dependencies where established.

Use the union of relevant before/after dependencies. Otherwise, a deleted VLAN,
removed WLAN, disconnected AP or withdrawn route could remove its own affected
entities from monitoring. Keep the pre-change client cohort while also measuring
new connection attempts; account for clients successfully roaming or reconnecting.

Expand only along edges justified by the rule's effect domain. LLDP adjacency
alone does not establish that a flow traverses a gateway, or that a routing change
affects every AP. Respect alternate paths, route policy, VRFs, VLAN membership,
firewall rule order and service matching. Missing path information produces a
bounded candidate scope with reduced confidence and explicit gaps.

## Rule kinds and v1 scope

Ship four hardcoded terminal rules first: WLAN removal/disable; WLAN authentication
changes; switch PoE delivery changes; and port administrative disable/link loss.
Restrict each to validated paths and available evidence. Shared-power-budget
propagation, SSID rename/scheduling and speed/MTU analysis are later extensions,
not implied coverage of these four rules. Missing WLAN/client scope yields partial
evidence rather than automatic use of an AP-wide SLE.

Expanders produce terminal checks or comparison constraints; they do not issue a
service-impact verdict themselves. Give expansion a depth bound and detect cycles.

| Expander | Output | V1 status |
| --- | --- | --- |
| Template/profile/site-group assignment | Effective path changes for candidate consumers, then terminal rules | Only validated inheritance/assignment cases; otherwise assume effective and unresolved |
| Firmware/reboot-affecting deployment | Device lifecycle/availability and relevant interface/radio/service checks | Basic lifecycle evidence retained; broad expansion deferred |
| SLE thresholds/classifier exclusions | Versioned comparison constraints, split/rebased windows and raw-counter checks where valid | Prevent incomparable evidence from generating a delta; no automatic service degradation |

## Candidate terminal rules

These are engineering hypotheses to encode and validate, not vendor guarantees.
Names below describe signals; collectors must map them to supported API metrics,
classifiers, counters or event sources. A row never promises that a particular
tenant exposes a metric at WLAN, port, client or application scope.

Only the four narrow rules above are proposed v1 implementations. All remaining
rows are deferred. In particular, cross-platform VLAN, BGP/OSPF, firewall, WAN and
VPN attribution is **not buildable with the v1 resolvers**. Direct local peer/link
events can still be recorded. An agent may investigate these domains opportunistically,
but must expose unresolved paths rather than claim full deterministic coverage.

| Changed setting family | Affected entities / dependency condition | Primary evidence to monitor | Conditional corroboration / exclusions |
| --- | --- | --- | --- |
| WLAN deletion, disable, schedule or SSID identity | Actual serving APs and clients using/attempting that WLAN; retain old identity | Effective WLAN availability, affected cohort disconnect/reconnect and join attempts | Connection SLEs only when attributable to that cohort; AP-health aggregate does not establish WLAN-removal impact |
| WLAN authentication, PSK, RADIUS, EAP, certificate, captive portal or NAC | Matching WLAN/port/users and authentication service | Authentication failures/timeouts, join success and time, authorization/VLAN result | Wired/wireless connection SLEs as available; no RF/PoE monitoring by default |
| WLAN VLAN, dynamic VLAN, bridge/tunnel mode | WLAN cohorts and old/new VLAN or tunnel paths | DHCP completion, address/gateway/DNS reachability, tunnel state, session/flow failures | Relevant connection and throughput SLEs; management health only if its path also changes |
| Radio enable, band, channel, width, transmit power or RF template | Changed radios and evidenced RF neighbors | Radio operation, channel/power, client signal/retries, disconnects, roaming, throughput | Coverage/capacity/roaming SLEs for affected radios/cohorts; extend to RF neighbors using RF evidence, not LLDP |
| Minimum rates, band steering, roaming/association controls | Eligible radio/client capabilities | Association failures, roam failures/duration, retries, connectivity | Relevant connection/roaming/throughput SLEs; separate unsupported clients from unaffected clients |
| WLAN QoS, rate limits, multicast/broadcast settings | Matching WLAN/classes/flows | Throughput, latency, drops, affected service behavior | Capacity and service evidence only where applicable; lower throughput can be an intended limit |
| Switch PoE enable, mode, priority or budget | Changed ports and powered devices; shared-budget siblings if applicable | PoE delivery/denial, power allocation, port state, downstream AP/device availability | AP-health power/disconnection evidence and downstream client interruption; no client minimum for confirmed loss of a previously powered device |
| Port admin state, speed, duplex, MTU | Changed port, attached devices and traffic that uses it | Link state/flaps, negotiated speed, errors/discards, MTU-related failures | Downstream AP Ethernet evidence and throughput; MTU impact can vary by packet/flow |
| Access/native/tagged VLAN, port profile or VLAN membership | Ports plus clients/APs using old/new VLANs | VLAN assignment, DHCP/authentication failures, gateway reachability, flow loss | AP reachability only for affected management VLAN; an allowed-client-VLAN edit does not imply AP power loss |
| STP, LAG, uplink, loop protection or storm control | Affected L2 domain and active/redundant paths | Forwarding/LAG state, topology changes, loops, drops, path reachability | Downstream availability/throughput; member loss with successful failover is resilience loss, not a demonstrated outage |
| DHCP server/relay, address pools, subnet/IRB or gateway IP | Clients in affected subnet/VLAN, including downstream wireless clients | Lease failures/exhaustion, relay reachability, address/gateway failures | DHCP-related connection SLEs; existing leases can conceal impact until renewal/new joins |
| DNS configuration | Consumers and flows using changed resolver/path | DNS timeout/failure/latency and dependent application access | Join/application evidence where available; do not infer device power or RF failure |
| BGP, OSPF, static routing, redistribution, route policy or VRF | Peers and prefixes whose usable paths change, plus dependent subnets/services | Adjacency, route presence/next hop, reachability, convergence and failover | Relevant downstream connection/application SLEs; peer loss alone does not prove user outage |
| Firewall/ACL/security/service policy, address/service object, NAT | Flows matching changed effective policy and old/new references/order | Matching denies/session failures, translation state, application/DNS/DHCP/auth reachability | Management connectivity only for matching management flows; intended deny is separate from unintended disruption |
| Security inspection profiles | Flows using the profile on capable enforcement devices | Inspection drops, application failures, latency and enforcement resource pressure | Resource/health SLEs only with a plausible resource mechanism; include references to consumers |
| WAN interface, link selection, shaping or QoS | Traffic/classes routed over changed links | Link state, loss/latency/jitter, utilization, queue drops and failover | WAN link/application/bandwidth SLEs as available; do not classify all LAN services as affected |
| VPN, IPsec, Mist tunnel or Edge configuration | Tunnel endpoints and WLAN/subnet/application consumers, including remote sites | Tunnel/peer state, loss, encapsulation failures, dependent flow reachability | AP-health tunnel evidence only for APs consuming that tunnel |
| Management IP/VLAN, cloud proxy/reachability or device DNS | Devices whose management path changes | Device/cloud connectivity, management address/route, relevant DNS events | Distinguish loss of management visibility from independently observed forwarding/client outage |
| Display-only metadata | Objects with verified absence of behavioral/reference changes | Configuration/deployment bookkeeping | No service SLE queries required |
| Webhooks, alarm/integration settings | Delivery/observability consumers | Delivery evidence, event freshness and collection capability | Observability impact is separate from network service impact |
| Location/BLE/maps/zones | Referencing location services/assets | Relevant location/service telemetry if available | No default network-health escalation; unsupported measurement remains explicit |
| Unknown attributes or opaque CLI | Known consumers, with unresolved effect domain | Coverage gap plus minimal deployment status | Potential risk unknown; incidental SLE movement cannot establish change attribution |

Multiple matching rules compose by union of their positive evidence requirements.
An exclusion from a WLAN rule cannot cancel AP-health evidence requested by a
simultaneous PoE rule.

### Verdict composition

Normalize findings by organization, entity identity, service and time interval.
Deduplicate affected clients/devices **before** computing magnitude. For overlapping
intervals, union the intervals rather than adding durations or client-minutes.
Without stable identities, keep per-source counts or explicit bounds; do not sum
anonymous counts into an exact affected-client total.

Evaluate each terminal rule over its deduplicated relevant cohort. Combine change
severity as the maximum supported terminal severity, without adding severity
scores or averaging away an outage. Multiple warnings do not automatically become
critical. Fleet-wide magnitude escalation requires a separate, versioned aggregation
policy over the union of affected entities; it is deferred in v1.

A healthy result from one rule cannot clear another rule's unresolved finding.
Conflicting evidence for the same entity/service/time remains disputed until
freshness and source precedence resolve it; record both observations. Coverage
and attribution remain separate fields: a change can be `critical + partially
unmapped`, or `no observed disruption + insufficient evidence`. Only a completely
assessed scope with adequate evidence can receive an unqualified no-impact result.
Maintain current, historical peak and recovery separately. Related changes can
share evidence but must retain ambiguous attribution when their windows overlap.

## Modular implementation

Initially use typed Python functions and small models in the existing backend.
The following are logical boundaries, not seven new subsystems/services. Extract
a YAML/JSON rule-pack format only after the first four rules reveal the repeated
structure. Keep complex resolvers in code and avoid executable expressions in
rule files. Preserve these boundaries as the implementation grows:

1. **Attribute catalogue / semantic diff:** produces typed changes, including
   inherited/reference effects and uncertainty.
2. **Rule registry:** matches semantic change types and conditions; declares
   effect domains, evidence, evaluation policy, recovery criteria and explanations.
3. **Scope resolver:** resolves configuration, topology and service dependencies.
4. **Plan compiler:** persists selected targets, metric/classifier filters,
   required/optional checks, windows, reasons, capabilities and exclusions.
5. **Collectors:** retrieve only planned evidence, preserve raw numeric sample
   counts/timestamps/units, and report collection status independently.
6. **Evaluators:** assess comparable evidence using the rule's conditions and
   confidence requirements; produce direct, downstream and contextual findings.
7. **Investigator and presenter:** the agent proposes hypotheses, selects additional
   evidence and explains findings; the presenter displays stored assessment facts,
   hypothesis status and coverage. Agents cannot rewrite source observations or
   clear deterministic findings without the required recovery evidence.

Illustrative future rule shape, to revise after implementing the four rules
(semantic IDs and signal IDs are proposed internal interfaces):

```yaml
id: switching.poe.delivery_changed
version: 1
match:
  semantic_changes: [port.poe.disabled, port.poe.budget_changed]
resolve:
  strategy: powered_port_dependents
  use_before_and_after: true
  include_shared_budget_dependents: when_budget_is_shared
evidence:
  required: [port.poe_delivery, port.link_state]
  conditional:
    - signal: device.availability
      when: downstream_device_identified
    - signal: wireless.ap_health.power_or_disconnect
      when: downstream_is_ap_and_signal_supported
evaluation:
  policy: powered_service_loss
  require_previously_powered: true
  client_count_required: false
  recovery: fresh_power_and_link_plus_required_dependent_checks
```

Persist rule versions/content hashes, catalogue version, effective diff identity,
dependency evidence/time, scope completeness, monitoring-plan revisions and
evaluation policy with each assessment. Replaying an old assessment uses the old
versions; re-evaluation creates a labelled new result without rewriting history.

### Investigation ownership

The future `ChangeInvestigation` is uniquely keyed by Guardian organization ID
and audit ID (one-to-one with its `AuditChangeGroup`). A template deployment to
200 APs owns **one investigation**, not 200 agent conversations. Keep existing
`MonitoringSession` records as device telemetry windows; their `audit_ids` already
represent a many-to-many relationship. An explicit investigation/session association
records applicable deployment intervals and evidence references. A session can feed
several investigations without assigning exclusive causation to any of them.

Uncorrelated receipts own provisional deterministic evidence buffers, keyed by
organization and receipt ID. They cannot start agent conversations, including on
webhook wakes. Correlation attaches their evidence idempotently to the canonical
audit investigation; there are no provisional agent conclusions to merge.
Reuse the existing ten-minute `AWAITING_CONFIG` timeout duration and polling loop
to end the correlation wait. Track that wait separately: a telemetry session can
already be `MONITORING`, so its deployment status is not a correlation predicate.
On expiry, promote the buffer to a standalone deterministic report with unresolved
change identity. Timeout alone does not prove that receipts represent separate
changes and must not enqueue one agent per receipt. Automatic agent execution
requires an established audit identity and available diff. Late correlation imports
facts from the standalone report into that audit, never a second conversation.
Device-level persisted assessments in steps 1–2 describe telemetry windows only;
the four future rules must run with audit-specific plan context, not mutate a
shared session's plan to serve whichever audit ran last. Shared session assessments
remain explicitly legacy-all until that separation exists.

Device telemetry jobs may be shared across changes using identical query identity
and windows. Link downstream devices to the change even when those devices receive
no configuration webhook themselves.
The agent receives the change, a deduplicated list of devices observed as configured
during an initial collection window, and resolver-produced candidate entities. It
then selects the devices/cohorts and checks relevant to its hypotheses. Configured
devices are deployment evidence, not the complete affected set: dependent APs or
clients can be disrupted without receiving a configuration event themselves.
Candidate discovery is
bounded inventory/configuration/topology work, not full telemetry collection for
every device. Matching deterministic rules supply mandatory scoped checks; the
agent cannot omit those, but can add permitted checks or request resolver expansion.
Record selection reasons and unresolved scope; a truncated candidate set cannot
support a complete no-impact result. Prefer batch/cohort queries where supported.
Necessary individual device calls run in shared collectors under the same plan,
without creating device agents or device-specific conversations. Enforce one active
reasoning lease per organization/audit across checkpoints and webhook wakes.
If a webhook precedes its diff, mark planning pending and retain lightweight
deployment evidence; compile/revise the plan when the diff becomes available.
Do not start with an unqualified all-SLE verdict during that gap.

## Agent investigation through Mist MCP

For the proposed investigation skills and separate OAS documentation service, see
[Investigation skills and attribute documentation](impact-investigation-knowledge.md).
These supply guidance and definitions; neither expands the live executor's permissions.

The agent replaces the requirement to pre-enumerate every cause/effect mapping.
It does not replace evidence collection, timing, persistence or the need to
establish an actual dependency. It can inspect configurations and telemetry to
discover a path for one change without first building an organization-wide graph.

Juniper documents an official Mist MCP server, labelled beta, at
`https://mcp.ai.juniper.net/mcp/mist`, including regional API and organization
headers. This establishes a possible integration, not verified support for every
needed historical SLE, classifier, configuration or route/flow query. Before an
implementation depends on it, enumerate its tools and test read-only capability
for the target tenant. Use existing Mist API collectors behind the same typed tool
boundary for missing capabilities where supported; otherwise report unavailable.

The existing `integrations/impact_ai.py` only sends derived assessment summaries
to an LLM and receives JSON. It has no diff input or tool execution loop. The
investigator is a bounded worker workflow, not a prompt adjustment to that adapter.
It will **replace** the narrator: retire `AiImpactProvider` and its completion-time
invocation when the investigator is enabled. Introduce a separate investigator
interface with tools and persisted state rather than stretching the narrator
Protocol. Use one mutually exclusive runtime mode (`legacy_narrator`, `investigator`,
or `disabled`) during migration, preserve old AI results for history, and never
execute both paths for the same new change. Steps 1–2 do not change the current AI
runtime; retirement belongs to the investigator rollout.

### One persisted investigation per change

1. At the trigger, persist the audit/change identity, full secret-safe semantic
   diff, before/after versions, deployment times/uncertainty, known consumers,
   baseline evidence and concurrent changes. Start deterministic webhook handling
   immediately. Retrieve historical baselines where available; a current-state
   API queried after the change cannot reconstruct pre-change clients or ports.
2. Accumulate correlated `device configured` events for a configurable initial
   window, default 60 seconds from the first persisted audit receipt. Persist
   `initial_review_not_before`; duplicates, additional devices and worker restarts
   do not move it. Once that deadline has passed and the audit identity and diff
   are available, run the agent once with the diff and observed configured-device
   list to form a small set of hypotheses and select relevant device cohorts. Each records
   the changed paths, proposed failure mechanism, candidate scope, supporting and
   falsifying checks, evidence needed and unresolved dependencies. Persist the
   resulting monitoring plan even if no measurements have arrived yet.
3. Reuse `MonitoringPollService.poll_active()`: the existing worker dispatches it
   every 60 seconds, while device telemetry normally becomes due every five minutes
   over a one-hour monitoring duration. Check the initial review deadline on worker
   ticks, independently of whether any device telemetry poll is due. Thus a
   60-second collection window normally starts reasoning after about 60–120 seconds,
   plus queue latency. Subsequent investigator checkpoints use a subset of telemetry
   polls, roughly every ten minutes, plus the final opportunity.
   Do not add a second scheduler or reduce the current telemetry frequency. After
   polling device sessions, coalesce due audit IDs and claim one investigation job
   per audit/checkpoint; device count does not multiply model invocations. Continue
   the saved investigation with new observations.
4. Strong webhooks update deterministic findings immediately and can wake an
   eligible audit investigator early after its initial collection window.
   Provisional receipts remain deterministic.
   Coalesce bursts and deduplicate receipts; avoid concurrent
   writes/runs for the same investigation. A positive webhook observation remains
   visible if the model, MCP or scheduled checkpoint fails.
5. At the existing window's final poll, close with current/peak impact, recovery, tested hypotheses, unresolved
   questions and coverage. Mark data whose availability lags the window as pending;
   allow a bounded delayed final collection rather than inventing completeness.
   A one-hour result does not assess future scheduled behavior or lease renewal.

The initial input includes each configured device's resolver-issued handle, type,
site, event source/receipt times and correlation provenance, alongside the semantic
diff, expected consumers where known and concurrent changes. Deduplicate device
entries while preserving their underlying receipts. Only attach events supported
by the correlation mechanism; proximity within 60 seconds alone does not establish
audit membership. Ambiguous events remain explicitly unassigned deployment context.
Events that arrived before the audit can be included once correlated.

The collection window is a fixed minimum wait, not a sliding debounce or proof
that deployment is complete. With no configured events, start the eligible audit
investigation with deployment unconfirmed and use resolved expected consumers;
an empty list does not mean no affected devices. Late configured events update the
same investigation and plan at the next bounded checkpoint, without new agents or
restarting its initial window. Capture baselines and handle deterministic outage
events immediately throughout the wait; only the first agent run is delayed.

The device lifecycle remains the timing authority, including receipt/source-time
distinctions, configured-event window extension, retries and `AWAITING_CONFIG`
timeout. The investigation stores each association's start/end and an aggregate
deadline derived from linked windows; it does not reset device timers. Partial
rollouts retain per-device deployment times. New linked windows may extend that
deadline explicitly, within an investigation lifetime budget, rather than granting
another seven calls per device. Reasoning eligibility uses elapsed time since the
last claimed investigation checkpoint, not odd/even successful poll counts.
Propagate terminal timeouts/failures through the same loop so no investigator
continues after all its windows terminate. Retries reuse checkpoint IDs. Shared
queries may serve overlapping changes; their findings retain causal ambiguity.

For unchanged evidence, the worker can record the checkpoint without another LLM
call; rerun reasoning on changed evidence, outstanding hypotheses or the final
assessment. Scheduled checks and source freshness remain visible. Bound model
turns, tools, elapsed time, token usage and API requests per run, investigation and
organization. Operational checks, resolver expansions and any future documentation
search/describe/list/reference calls consume the same persisted investigation tool
budget. Charge retries and each pagination request; cached responses still consume
a logical tool call and output budget. Reserve capacity atomically before execution,
and retain counters across checkpoints/restarts. Per-response limits and a separate
documentation quota cannot substitute for this shared total cap.
Budget exhaustion, rate limiting and model/tool failures produce partial or pending
results, never no-impact conclusions. Budget seven scheduled reasoning opportunities
per audit investigation for the ordinary one-hour case, reserving one for the final
assessment; event-driven and extended-window runs share a separate explicit total
cap. This bounds invocations, not tokens or tool queries. Cost scales with the
number of audit investigations and evidence volume, not seven times device count.

### Context and history between turns

Use hybrid persistence: retain source evidence and structured investigation state,
then assemble a compact working context for each reasoning turn. Do not rely on
either an ever-growing model conversation or a narrative summary as the only
record. One logical conversation belongs to the audit investigation even if each
checkpoint uses a fresh model request or runs on another worker.

| Persisted layer | Contents and role |
| --- | --- |
| Evidence history | Timestamped observations, baseline snapshots, correlated receipts, normalized tool responses, source identities and collection errors; immutable evidence for verification and report charts |
| Investigation state | Change/diff references, configured/selected/downstream entities, plan revisions and exclusions, hypothesis/finding records, supporting and contradicting evidence IDs, unresolved checks, current/peak impact, recovery and assessment references |
| Working summary | Bounded, structured account of what was tested, conclusions and uncertainty, what changed since the previous turn, and next checks; a rebuildable aid to reasoning |
| Execution journal | Checkpoint IDs, validated requests/results, visible model outputs, state revisions, evidence cursor, budgets and errors; supports restart, debugging and replay |

Store hypothesis status explicitly (`open`, `supported`, `refuted`, `inconclusive`)
with its evidence references, scope and timestamps. Keep findings distinct from
the hypothesis that proposed them. Backend-owned fields such as ratings, budgets,
identity and mandatory checks cannot be rewritten by the summary. Store concise
decision explanations and evidence links; no private model reasoning trace is
needed. Evidence retention is independent of prompt compaction: summarizing a turn
must never delete samples needed for a historical chart, a removed WLAN's former
client cohort, or a transient outage's peak/recovery record.

Each resumed turn receives:

1. The fixed investigation instructions, applicable skill/rule versions, permitted
   check catalogue and remaining execution budget.
2. The relevant original diff, deployment timeline, scoped entity handles and
   current validated plan/state, including exclusions and coverage gaps.
3. The previous working summary and latest assessment/report references, with
   open hypotheses and prior supporting/counterevidence explicitly retained.
4. New evidence since the last committed ingestion cursor, plus the relevant
   baseline and older evidence slices required for the current checks.

Use an ingestion sequence/cursor rather than event time alone so late-arriving
configured events and delayed telemetry are not skipped. Deduplicate receipts and
observations while preserving source provenance. Historical data is still historical:
freshness rules apply on every resume, and yesterday's successful check cannot be
silently treated as a current result. Reuse previously collected evidence when it
matches the required scope/window and freshness; collect new follow-ups where due.

Older observations remain available through bounded catalogue retrieval checks
over authorized stored-evidence references. These are read-only accesses within
the same investigation/organization boundary, counted under the shared tool and
output budgets. They do not grant arbitrary database queries or entity identities.
If data has expired or was never retained, expose that gap instead of treating the
summary as a substitute measurement. Apply the application's explicit retention
policy to evidence, sanitized source payloads and journal entries; do not retain
unbounded raw API responses or secret-bearing transcripts by default.

Regenerate summaries from validated state and referenced evidence, not exclusively
from previous summaries, to limit cumulative drift. Use a fixed schema/token cap
and preserve contradictions, unknowns, exclusions, unresolved checks and transient
impact. A summary cannot promote an inference to an observation or an untrusted
device name to an instruction. Treat summaries and stored tool prose as data on
every turn; execution-time validation still applies. Any model call used for
summarization consumes the same investigation model/token budget, not a hidden
extra call at every checkpoint. Prefer deterministic projection for structured
fields; retain only a bounded recent exchange when it helps explain a pending check.

Commit checkpoint results against the expected state revision under the existing
single-investigation lease. Publish the new state, summary references, report
revision and consumed evidence cursor as one logical commit; a failed or stale
worker cannot advance the cursor or overwrite newer conclusions. Persist accepted
tool results and budget reservations separately as execution proceeds so retries
can reuse completed work without resetting costs. New evidence arriving during a
turn remains queued for the next revision. Missing/invalid summaries are rebuilt
from state; worker restart or provider conversation loss never restarts an audit's
investigation, deadlines or budgets.

### Reviewable execution logs

Capture a structured execution journal from the first investigator prototype;
historical requests cannot be reconstructed later from report prose. Expose it
through the [report's investigation log view](impact-investigation-report.md)
when that UI is delivered. Log collection is part of the executor, independent
of whether the agent succeeds in producing a report.

Every logical check and each dispatch attempt has a stable ID linked to organization,
audit/investigation, checkpoint/turn, plan revision, hypothesis and resulting evidence
where applicable. Record:

- Requested catalogue check, MCP server/tool and version, authorized entity handles,
  sanitized arguments and executor validation decision/rejection reason.
- Dispatch/completion timestamps, duration, attempt number, pagination relationships,
  cache hit/miss, available upstream request IDs and execution budget usage.
- Sanitized response payload or stored-payload reference, normalized evidence IDs,
  payload size, explicit truncation/redaction and source coverage metadata.
- Success, tool-declared error, transport/authentication failure, timeout, cancellation,
  rate limit, invalid response or budget rejection; include available status/error
  codes, safe diagnostic details and retry decisions without inventing upstream fields.

Include Mist operations, resolver checks, stored-evidence retrieval and future OAS
lookups under the same journal contract. Link model invocation metadata, supplied
state/evidence references, visible structured output, report validation failures
and checkpoint commits to these calls. Do not require private model reasoning
traces. Record executor-rejected requests as rejected, never as dispatched calls.

Persist the dispatch intent before an external call and its outcome afterwards.
If the worker crashes between them, show an interrupted/unknown outcome until
reconciled, not an inferred success. Retried attempts remain individually visible
under the logical check ID. A journal failure must be surfaced; pause new agent
tool dispatch if its intent cannot be durably recorded, while preserving existing
deterministic monitoring. Journal writes do not themselves invoke another agent.

Redact credentials, tokens, cookies, authentication headers and configuration secrets
before persistence or export, including when echoed in errors or response prose.
Use schema-aware filtering and conservative handling of unstructured payloads;
an unredactable payload retains safe metadata with a reason for omission. Avoid
unfiltered HTTP wire dumps. Apply explicit payload size limits and retention,
showing expired/omitted/truncated content distinctly from an empty successful
response. Keep normalized evidence under its own retention contract so logs may
expire without silently breaking retained reports. Restrict log payload access and
exports to authorized organization users through a dedicated diagnostic permission;
links to logs never bypass those checks.

### Evidence-backed agent output

Use one versioned report schema and a shared audit-level UI across all domains,
as specified in [Structured investigation reports and evidence views](impact-investigation-report.md).
Fixed sections present the conclusion, change, scope, findings, evidence, timeline,
context and gaps. Within those sections the agent selects typed chart/table/histogram
blocks over validated evidence datasets; application renderers own presentation.
Every report revision pins the assessment and evidence used. Visuals cannot bypass
rule exclusions, invent measurements or become a second source of severity.
Expose backend-calculated impact severity and confidence bands from that same
assessment in the changes view, impact view and report header. Headline impact is
the peak observed impact; current impact/recovery is separate. Confidence is low,
medium or high with component explanations, not a probability. Preserve pending
and insufficient states, and do not discount impact magnitude by confidence.
Defer numeric scores until operators need finer ranking and evidence validates it;
the report contract defines band provenance, states and evaluation requirements.
Require a structured impacted-device list with resolver-backed identity, affected
service, severity, attribution, lifecycle and evidence references. The backend
validates and deduplicates finding contributions into this list. The report table
and topology overlay consume the same revision, distinguish configured/monitored
devices from impacted ones, and retain uncertain or recovered impact explicitly.
Unlocalized findings remain scope gaps rather than assigning impact to every device.

Persist structured findings with hypothesis ID, affected entities/time window,
observation IDs, measured facts, inferred dependency chain, proposed severity,
attribution status, contradicting evidence and missing checks. Use the same evidence
states and aggregation policy as deterministic rules. An agent can report a novel
suspected outage without a matching hardcoded rule; `unmapped` coverage remains.

Code validates observation references, scope, freshness, comparability and numeric
calculations. These checks cannot prove the agent's causal inference. Agent-only
attribution stays visibly provisional until corroborated/adjudicated; report a
supported severe outage separately from an uncertain link to the configuration
change. Promote common, adjudicated mechanisms into tested rules over time.

Explicit rule exclusions outrank skill/agent-proposed corroboration **for that
rule's verdict**. Compile exclusions into the rule-specific evidence eligibility
policy and enforce it before evaluation and aggregation, not in skill prose alone.
Persist the rule ID and evidence/check identity with each proposed contribution;
reject excluded contributions to its severity, affected counts and attribution.
Excluded observations may appear as separate contextual findings, with no effect
on the change's attributed verdict through that rule. Another rule's positive
requirement remains valid in its own context. Relabelling the same excluded evidence
as an agent-only hypothesis cannot bypass the exclusion; a distinct causal mechanism
requires independent supporting evidence and the same executor validation.

Require consideration of pre-existing degradation, simultaneous changes and
available counterevidence. For example, after an SSID deletion, check the former
client cohort and join activity before drawing conclusions from AP health. Do not
allow "an outage happened later" to serve as the sole attribution argument.

Enforce the tool boundary in code: enumerate capabilities for the authenticated
organization and expose a typed catalogue of check IDs and bounded parameters.
The agent may select only catalogue checks over opaque entity handles emitted by
the authorized resolvers. It cannot supply raw URLs, arbitrary API arguments,
organization IDs, MACs or other identities introduced in its prose. Validate the
check/entity pairing, allowed scope, time window, pagination and query budget at
execution, not merely in the prompt. Capability discovery is necessary but is
intersected with an application-owned read-only allowlist, not automatically trusted.

For additional entities the agent can request an allowlisted resolver expansion
from an existing handle. Only the resolver can issue new handles, with provenance
and organization validation. V1 therefore cannot invent VLAN/route/flow entities
to bypass deferred resolver work. Persist the capability catalogue, resolved handles,
rejected requests and normalized tool responses for deterministic shadow replay.
This constrains the action space; it does not guarantee the model's prose is immune
to manipulation, so evidence validation and provisional attribution still apply.

Keep scoped read-only credentials in the executor. Redact secrets before model
ingestion and treat configuration names, descriptions and tool-returned prose as
untrusted data. No rollback or configuration mutation belongs in this workflow.
Record model/prompt/tool versions, calls and
normalized evidence for audit and replay. Preserve the existing provider's limited
data exposure through deliberate redaction of the richer diff/tool context.

## Evidence and verdict contract

Every planned check remains visible, whether or not it has a numeric delta:

- Measured and comparable; measured but not comparable.
- Pending or delayed; no sampled traffic; unsupported or disabled.
- Permission/API error; incomplete collection; missing baseline or stale evidence.
- Not applicable, with the specific condition that makes it inapplicable.

Keep metric identity, scope ID, filters/cohort, classifier, unit, definition and
time windows explicit. Never compare different scopes just because both say
`device`. If only a broad aggregate is available, label it contextual unless
additional affected-entity evidence supports attribution. Capability discovery
should distinguish a relevant unavailable signal from an intentionally unselected
one. Unavailable optional SLEs need not block an operationally decisive result;
missing required checks prevent a complete no-impact conclusion.

Preserve sample denominators. A 100% to 0% movement with one attempt and with
thousands of attempts must not receive identical confidence. Choose aggregation
per metric semantics; use summed event counters for event success rates where
valid, and retain time/user-minute weighting for metrics defined that way. Metric
direction is explicit: more failure is worse; more success is better.

Select baseline windows and response horizons per effect domain. Align observations
to actual deployment timing where known, record timing uncertainty otherwise, and
distinguish rolling current state from cumulative incident history. DHCP renewal,
authentication rechecks and scheduled behavior may need longer observation than
immediate power/link failures. Do not hide a real interruption in a settling window;
record its duration and recovery separately from the steady-state result.

Severity uses relevant impact magnitude, duration, service criticality, affected
entities and corroboration. Numeric thresholds, sample minima and persistence are
versioned evaluation policies to calibrate against historical cases, not universal
25-point rules. Direct service-loss evidence can raise a critical result without
waiting for SLE samples. Loss of redundancy is a distinct finding from service loss.

Report attribution as supported, plausible or undetermined, with evidence rather
than an invented probability. The accompanying confidence band uses a
versioned evidence rubric and retains those attribution labels; it is not a
probability of causation. A matching rule establishes plausibility, not proof.
Check for pre-existing degradation, concurrent changes, collection gaps and
available unaffected comparison cohorts. Show unrelated incidents as network
context without promoting the change's attributed severity. Missing information
does not prove irrelevance either; retain unexplained deployment anomalies for
investigation. Configuration rollback is a deployment failure with separately
assessed service impact, not automatic proof of a critical client outage.

For a removed SSID with zero clients observed before removal:

- Record the intended service removal and the exact occupancy coverage/window.
- Report no observed active-client disruption only if the relevant client evidence
  supports that statement. Zero connected clients does not exclude failed join
  attempts, occasional clients or unknown occupancy.
- Retain evidence for former clients even if WLAN-scoped queries stop working
  after deletion. Absence of post-deletion SLE samples is not a measured outage.
- Do not let unrelated AP-health degradation determine WLAN-removal severity.
  A separately evidenced deployment restart or broader service loss remains
  reportable with its own attribution confidence.

## Delivery and acceptance

Steps 1–2 below describe the implemented foundation. Steps 3 onward remain proposed.

1. Ship the evidence-state contract and evaluator seam. Add an explicit relevance
   plan to `assess_impact`; initially callers can pass a named legacy/all plan to
   preserve behavior. The plan must cover incidents and operational findings as
   well as SLEs. An explicit empty plan means no selected checks, never all checks.
   Build UI rows from planned metrics union observed/no-data/error metric identities,
   with nullable values and per-side states. Discovery-level errors stay collection
   errors. Legacy unrecorded metric selections cannot be reconstructed by guessing.
2. Collapse assessment into one persisted result containing severity and coverage.
   Remove the view's independent `ok → unknown` severity recomputation for new
   results. Handle legacy results in one explicit compatibility projection; rendering
   must not silently create a second current evaluator. These changes require API,
   frontend and regression checks, not just changing set intersection to union.
3. Implement the four narrow hardcoded rules and two resolver families described
   above, using audit-owned plans and deterministic-only provisional buffers.
   Validate mappings with four hand-validated, sanitized domain fixtures and the
   regression cases below. Expose partial/unmapped
   state and assumed-effective decisions. No catalogue or YAML loader prerequisite.
4. Human-adjudicate 20–50 historical changes covering benign changes, real outages,
   unrelated degradation, low/no traffic, missing evidence and overlapping changes.
   Record observed service impact separately from attribution, affected scope,
   onset/recovery and evidence sufficiency. Use incident records/operator knowledge
   where available. Allow indeterminate labels; old telemetry alone is not ground
   truth. Resolve reviewer disagreement explicitly and reserve a held-out subset.
5. Prototype the bounded MCP investigator in shadow mode on that acceptance set
   and new read-only captures. Verify tenant capabilities first. Compare deterministic,
   agent and hybrid outputs against adjudicated labels, never against each other
   as ground truth. Replay fixed tool responses for reproducible evaluation; live
   future queries cannot reconstruct missing historical states.
   Implement the shared structured report contract and audit report UI alongside
   this runtime, including validated evidence blocks, provenance drilldowns and
   partial/revision states. Validate them before user-facing agent reports launch.
   Load the four versioned domain skills through this runtime. Only after it exists
   and real unmapped cases require attribute retrieval, build the OAS lookup library;
   defer an MCP adapter until an external consumer needs it. Neither gates v1 rules.
6. Before enabling agent-derived notifications, freeze a held-out gate with both
   labelled critical outages and labelled benign/unrelated changes (at least three
   of each; otherwise gather more cases). Report TP/FN/FP/TN counts, outage recall
   `TP/(TP+FN)`, critical-attribution precision `TP/(TP+FP)`, and benign specificity
   `TN/(TN+FP)`. For this small initial gate require no missed labelled critical
   outage and no false critical attribution on labelled benign/unrelated changes.
   Abstention on a labelled outage is not a true positive; benign abstention is not
   a true negative. Report abstentions separately and require explicit abstention
   for cases labelled insufficient evidence. Missing denominators, unresolved
   adjudication that could change a pass, and ties fail closed: keep shadow mode,
   do not enable agent-derived alerts. Also require valid evidence references and
   bounded query cost/latency. The categorical unrelated-SLE check remains a
   regression invariant in addition to these counts. A held-out slice may be only
   about ten cases: passing this gate is not statistical proof of production accuracy.
   At three benign cases, counts and categorical regressions carry the gate; rates
   add no statistical power. Ongoing adjudication in step 7 builds confidence.
7. Enable behind a feature flag, retain deterministic event handling and a rollback
   path, and adjudicate subsequent disagreements. Extract a rule-pack schema from
   repeated implemented patterns only when useful. Add VLAN/route/flow resolvers
   when real cases and available APIs justify them, not as a precondition for the
   hybrid experiment.

Required regression scenarios are labelled by implementation phase. Deferred cases
are acceptance backlog entries, not failing tests required to ship steps 1–2.

- **V1 rules:** Unused SSID removed plus unrelated AP-health drop: no attributed critical result.
- **V1 rules:** Used SSID removed: quantify interrupted clients and successful reconnections;
  intended deletion remains visible and does not erase real disruption.
- **V1 rules:** Unknown occupancy versus confirmed zero; failed new joins with zero connected
  clients; missing versus truly empty source collection.
- **V1 rules:** PoE lost on an AP port: monitor the attached AP even without its own change
  webhook; unknown client count cannot suppress confirmed device-service loss.
- **Deferred resolvers:** Client VLAN removed while AP management VLAN remains intact: client-path impact,
  without inventing an AP power or management failure.
- **Deferred resolvers:** BGP peer lost with successful alternate routing: resilience finding; route loss
  with dependent flow failures: service impact on the evidenced consumers.
- **Deferred resolvers:** Firewall rule ordering/reference changes: scope matching flows, including
  management traffic only when matched; distinguish intended denial.
- **V1 rules:** Profile change masked by a proven replace override; unknown merge semantics assume effective;
  override removal exposes inherited value;
  a removed dependency remains in the pre-change affected set.
- **Steps 1–2 active:** Relevant SLE unavailable: visible coverage state, operational findings retained;
  unsupported scope never silently substitutes a site-wide measurement.
- **Deferred investigator/evaluation:** Low sample counts, changed SLE definitions, stale topology, overlapping changes,
  delayed deployment, and recovery after a transient disruption.
- **V1 rules:** Unknown new attribute: explicit coverage gap. Multiple rules: additive evidence,
  deterministic versioned evaluation, shared-query and client deduplication.
- **V1 ownership:** Many device receipts correlate to one audit; provisional and
  timed-out standalone buffers run no agents. Late correlation imports evidence
  once, and overlapping audits never overwrite a shared session's rule plan.
- **Deferred investigator:** One template change with 200 AP candidates creates
  one conversation and one active reasoning lease. Its plan selects relevant
  cohorts; individual collector requests and webhook bursts cannot spawn agents.
- **Deferred investigator:** The initial 60-second window batches configured
  devices once; duplicates/restarts cannot postpone it. Empty, late, out-of-order
  and ambiguously correlated events retain deployment uncertainty, while downstream
  devices without configured events remain eligible. Initial review is dispatched
  on a worker tick even when no device telemetry poll is due.
- **Deferred investigator memory:** Resume after worker/provider context loss with
  the same audit, plan, evidence and budgets. Repeated summary compaction preserves
  exclusions, counterevidence, unresolved checks and a recovered outage's peak.
  Late evidence crosses ingestion cursors correctly; stale commits cannot overwrite
  new state, expired evidence remains missing, and summary text cannot invent facts
  or bypass entity/check validation.
- **Deferred investigator logs:** Success, tool error, timeout, rejected check,
  retry, cache hit and interrupted dispatch remain distinguishable and traceable
  to a turn/evidence record. Secrets echoed in requests, responses and errors are
  redacted before storage/export; payload expiry/truncation and diagnostic access
  denial remain explicit. Log viewing never executes the recorded request again.
- **Deferred investigator:** A skill proposes excluded AP-health corroboration for
  WLAN removal: contextual display only, no contribution to that rule's verdict;
  independently required PoE evidence remains eligible for the PoE rule.
- **Deferred documentation integration:** Search/describe/list/reference loops,
  pagination and retries exhaust the shared investigation budget across checkpoints
  and restarts; exhaustion preserves incomplete coverage rather than no impact.

## Primary references

- [Official Mist MCP integration (beta)](https://www.juniper.net/documentation/us/en/software/mist/automation-integration/shared-content/topics/concept/juniper-mist-mcp-claude.html):
  remote endpoint, regional/organization headers and read-only token guidance;
  bounded tenant checks are recorded in [Mist MCP capability checks](mist-mcp-capabilities.md).
- [Mist OpenAPI](https://github.com/mistsys/mist_openapi): attribute inventory input;
  the project describes the specification as manually maintained documentation.
- [SLE metric discovery](https://www.juniper.net/documentation/us/en/software/mist/api/http/api/sites/sles/list-site-sles-metrics):
  validate requested-scope capabilities rather than assuming metric availability.
- [Wireless SLEs](https://www.juniper.net/documentation/us/en/software/mist/mist-aiops/shared-content/topics/topic-map/wireless-sle.html):
  wireless signal definitions and classifier context.
- [Wired SLEs](https://www.juniper.net/documentation/us/en/software/mist/mist-aiops/shared-content/topics/topic-map/wired-sle.html):
  connectivity, throughput and switch-health semantics.
- [WAN SLEs](https://www.juniper.net/documentation/us/en/software/mist/mist-wan/shared-content/topics/concept/sle-wan-edge-health.html):
  WAN/link/application signal semantics; availability depends on subscriptions.
- [AP-health network classifiers](https://www.juniper.net/documentation/us/en/software/mist/product-updates/2024/may-16th-2024-updates.html):
  documented latency, jitter and tunnel-down mechanisms support conditional
  upstream-path rules rather than treating AP health as RF health alone.

Per-attribute API mappings, classifier endpoints/filters, route/flow visibility and
live tenant compatibility still require implementation-time validation beyond the
bounded checks recorded above. No exhaustive attribute extraction was performed.
