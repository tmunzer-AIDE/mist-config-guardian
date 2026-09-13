# Audit impact engine: review handoff

Status: bounded v1 implemented and locally verified on 2026-09-13. Production remains
`legacy`; no setting, deployment or external notification was changed. This is ready
for source review and a controlled shadow evaluation, not a claim of calibrated accuracy.

## Implemented scope

| Area | Behavior and limits |
| --- | --- |
| Investigation ownership | One organization/audit root. Configured events are collected as deployment context after a 60-second settling interval. Uncorrelated audits remain visibly pending; they cannot start agent queries. No device-agent fan-out. |
| Scheduling | Existing worker tick, approximately ten-minute checkpoints within the audit's one-hour window, subject to expiry, budget and ten published checkpoints. Lease claims are fencing generations, not completed checkpoints. |
| WLAN lifecycle | Removal/disable examines the affected WLAN's client sessions. Deduplicated client cohorts and exact audit windows establish observed disconnects. AP-health movement cannot enter this evaluator. |
| Authentication | Supported WLAN authentication changes inspect a fixed set of success/failure client events. Prior success followed by failure is a provisional finding; absent attempts, unsupported event types and incomplete history do not prove health. |
| Port availability | Concrete immutable switch/port changes use scoped recorded up/down history. A prior up state is required before attributing a later down transition. Alternate paths and competing causes remain unresolved. |
| PoE | A disabled event alone is insufficient. A recent pre-change observation with power delivery is required; current snapshots often cannot supply it, so the result remains unknown. Enabling PoE does not prove recovery. |
| Physical dependencies | Encrypted server-only source bindings permit exact managed-AP inventory/statistics checks. Recent reciprocal LLDP and interface state may corroborate adjacency. Neither current membership nor adjacency proves historical attachment, sole power supply, AP failure or causation. |
| Agent and skills | Four versioned application-owned domain skills guide the model. The capability menu equals the deterministic required set; a shared cache prevents extra Mist reads. The model proposes cited hypotheses/open questions and cannot assign verdicts or introduce entities. |
| Attribute knowledge | Four content-hashed, reviewed OAS fixtures: switch BGP/OSPF and WLAN SSID/schedule. At most two local lookups per checkpoint, under the same check budget. Definitions explain unmapped attributes; they do not make these changes operationally supported. |
| Reports and UI | One typed revision schema, eight stable sections, tables/bars/histograms/timelines with source values, current/peak impact and confidence bands, coverage and gaps. History follows published parents, not arbitrary latest artifacts. |
| Device associations | Source-validated device/service records feed an optional shadow topology overlay. Serving affected clients is distinct from device failure. Lists describe observed evidence only; missing devices and unavailable denominators remain explicit. |
| Diagnostics and memory | Bounded normalized tool outcomes and model input/action artifacts; exact identity/hash verification on access. Recent summarized observations and proposals supplement immutable historical evidence. Logs are not raw Mist payload archives. |
| Retention | Organization-policy retention on roots, revisions, model artifacts and adjudications; bounded legacy backfill and organization-orphan cleanup. Missing expired evidence invalidates acceptance instead of retaining a stale pass. |

The maximum plan contains **22 checks: 20 operational and two local definitions**.
The audit budget is **56 check reservations**, shared by both modes, so this maximum
fits two complete checkpoints and twelve further checks. Ordinary WLAN removal uses
two checks per checkpoint. Budget exhaustion publishes explicit incomplete/denied
coverage and stops subsequent polling. This deliberately bounds cost; it does not
promise every maximum-sized audit a full hour of successful collection.

The model has its own 21-call audit budget, up to three calls per checkpoint and a
24 KB input bound. Opaque references compact repeated windows, targets and collection
times; full normalized provenance remains in artifacts. A model/provider failure cannot
prevent the mandatory deterministic sweep while collection remains authorized.

## Production consumer readiness

| Consumer | Current behavior | Acceptance-dependent migration |
| --- | --- | --- |
| Changes list/detail and filters | Shared revision-pinned audit preview; legacy severity/filter source explicitly retained. | Persist audit provenance, peak/current bands and recovery together, and change database filters to that same projection. |
| Overview | Same audit summaries on returned feed; shadow counts describe only that feed. Production counts remain legacy. | Count the published group assessment used by Changes; never substitute feed counts for organization totals. |
| Impact and topology | Audit report/associations available in live shadow view, distinct from device health. Historical views do not read today's audit verdict. | Keep live health independent; any historical audit overlay must resolve a revision at the selected time. |
| Notifications | Existing group projection remains authoritative. Tests prove shadow disagreement cannot alter alert decisions. | Use the same published audit projection, durable delivery/outbox and deduplication policy described in the decision log. |
| Search/recovery/monitoring | Existing group/device meanings remain intact. | Migrate group labels and recovery with Changes; retain or explicitly version device monitoring semantics. |
| Runtime modes | `legacy`, `shadow`, `agent_shadow`; the old narrator is suppressed in both shadow modes. | A production-audit mode and broad-collection retirement are not yet implemented. Add them only after the reviewed acceptance set establishes readiness. |

This table completes the migration **readiness audit**, not production migration.
Removing broad device collection now would remove the comparison path before operators
have established whether the new scoped coverage misses real outages.

## Acceptance and remaining prerequisites

An administrator reviews 20–50 actual historical audits with a rationale and explicit
human attestation against an exact published report. A publicly computable audit hash selects
a deterministic 25% subsample of administrator-selected audits; it must contain at least three critical outages and three benign
changes. The UI reports TP/FN/FP/TN, critical misses, abstentions, precision, recall and
specificity. Misses, false alarms, unresolved evidence and scored-subsample abstentions fail;
ties do not pass. At this sample size these are conservative case counts, not statistical
calibration or probability estimates; denominators may be single digits.

This is **not an independent held-out set**: administrators choose the audits and can
compute membership before submitting. Sample composition can therefore be selected
against the scored subset. There is no deployment/incident grouping; a change and its
rollback can fall on opposite sides. The API retains the compatibility names `held_out`
and `adjudicated_held_out_cases`, but `eligible` means only that diagnostic count criteria
passed, not that independent validation or production approval has been established.

Before production validation, implement deployment/incident grouping (including
rollbacks), freeze the eligible cohort and group membership before scoring, and separate
selection/development from independent evaluation. Record the evaluation protocol and
prevent iterative sample substitution against results. These controls are not implemented
by the current hash split. Continued adjudication is also required after release.

Deterministic replay re-evaluates retained typed evidence and the published history
chain without Mist or model calls. Labels bind to evidence-chain and policy hashes;
altered, foreign, missing or expired artifacts cannot approve a release. This replay
does not make model decisions deterministic. Passing the acceptance endpoint never
activates production automatically.

**No real acceptance labels were submitted during implementation.** Remaining work:

1. Implement and review the independent evaluation controls above, then run the
   shadow build on the frozen representative cohort and independently adjudicate
   it, including benign changes and actual outages.
2. Resolve any failures or unsupported cases revealed by that evaluation. Complete
   the production group-consumer migration and notification publication boundary,
   then retire broad attribution collection in a separately reviewed release.
3. Extend coverage only through explicit resolvers/capabilities. Effective template
   inheritance, VLAN/route/VRF/flow paths, BGP/OSPF/firewall/WAN/VPN attribution and
   historical powered-device dependencies remain unsupported. SSID/schedule knowledge
   is documentation only. An external OAS MCP adapter remains deferred until an
   external consumer needs it; the runtime already consumes the library directly.

## Verification

- Backend: **1,274 passed, 20 skipped**; Ruff and source type checks pass.
- Frontend: **406 passed**; production build passes.
- Browser: the structured report/history/human-gate flow and the WLAN shadow evidence,
  deployment, port, neighbor, dispatch and agent flow pass; generated screenshots were
  inspected. These use mocked API fixtures, not production acceptance labels.
- Maximum mixed plan: both shadow modes publish all 22 evidence items, journal 20 Mist
  reads plus two local lookups, and round-trip the revision. The agent produces its
  final proposal within the input bound. An over-cap revision is rejected.
- OpenAPI export is current, including nullable metric values and documentation-only
  dispatch scope. Consumers must preserve null as unknown rather than convert it to zero.

Implementation decisions: [decision log](impact-implementation-decisions.md).
Completion scope: [implementation checklist](impact-completion-plan.md).
