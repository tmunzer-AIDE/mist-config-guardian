# Impact implementation decisions

Owner: Guardian impact workstream. Updated: 2026-09-12.
The user delegated implementation decisions and requested this durable record.
This file records decisions and verified delivery state; proposed features are not
described as implemented. The detailed contracts remain in the linked design docs.

## Decisions

1. **Deliver one complete WLAN-removal slice first.** Connect audit configuration
   versions, owned evidence windows, selective collection, rule verdict and existing
   projections before adding WLAN authentication, PoE and port availability rules.
   Do not let broad session telemetry become audit-attributed evidence by default.
2. **One audit owns one investigation.** Organization/audit uniqueness is enforced
   in storage. Device sessions are shared sources. Provisional receipts collect
   deterministic evidence only; timeout alone never creates per-device agents.
3. **Keep identity and time explicit.** Each check records its entity/cohort and
   baseline/follow-up windows. Missing identity or history is incomplete coverage,
   not zero traffic. Configured events are deployment evidence, not the affected set.
4. **Use the existing worker.** Persist a 60-second initial collection deadline and
   an investigation expiry independent of device sessions. Reuse the worker's
   minute tick; subsequent model opportunities remain bounded near ten-minute
   checkpoints. Late events update the same investigation without resetting budgets.
5. **Publish one assessment.** Changes, Overview, Impact/topology, search and
   notifications consume the audit assessment or an explicitly labelled legacy
   projection. Per-scope movements and affected counts replace group SLE means.
6. **Select checks before collection.** Typed requests constrain metric/source,
   scope and time. Match rule exclusions in code. Deduplicate matching reads;
   legacy broad capture remains isolated until migration is verified.
7. **Use compact durable state.** Evidence and report artifacts are immutable and
   bounded; publish a revision through a conditional root update. Resumed workers
   validate lease generation at dispatch and commit. Summaries can be rebuilt.
8. **Constrain live AI access.** Only approved checks over resolver-issued handles;
   current organization authorization at dispatch, isolated caches, redacted logs,
   and shared budgets. Never use restore-administrator credentials for monitoring.
9. **Keep the agent rollout gated.** No new AI notifications until capability tests
   and human-adjudicated acceptance cases pass. Automated tests are not operator
   labels. Missing labels leave shadow mode enabled, not an inferred pass.
10. **Implement presentation incrementally.** Preserve the common report schema.
    Start with impact/confidence bands, impacted devices, evidence tables/trends,
    gaps and logs. Richer chart types and OAS retrieval follow real consumer needs.
11. **Work in local, reviewable commits.** Preserve the recovery stash. Do not push,
    deploy or change Mist configuration as part of implementation. Record test
    results and remaining limitations at each milestone.

## Delivery ledger

- `17a29e5`: evidence-state contract, relevance evaluator seam, persisted device
  assessment and site/device UI projections; design and MCP capability notes.
- Confidence follow-up: count only complete, selected, comparable observations;
  latest failed comparison keeps confidence low. Eight regression cases; 914
  backend tests passed, 20 skipped; lint/format/type/OpenAPI checks passed.
- Next: WLAN-removal slice and projection consistency. Agent runtime, live report
  rendering and the remaining three rules are not yet implemented.

## Gates that require external evidence

- Human labels: 20–50 historical changes with a held-out set grouped by deployment
  or outage, including benign and critical cases. No fabricated labels.
- Runtime connection: verify Guardian worker access independently of the desktop
  Mist MCP connection, including allowed historical WLAN/client queries.
- Numeric confidence/impact scores remain deferred; bands and evidence explanations
  are the agreed interface.
