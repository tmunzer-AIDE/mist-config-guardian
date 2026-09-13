# Remaining impact engine implementation

Owner: autonomous implementation following the 2026-09-13 instruction to finish the queue before review.

Completion means the bounded v1 runtime, report/UI, diagnostics, retention and acceptance tooling are implemented and verified. Production activation requires genuine operator adjudication; synthetic labels must never satisfy that gate. No release, deployment or live configuration mutation is part of this work.

- [x] Scoped operational history: exact switch port/link/PoE events and WLAN authentication events, normalized with explicit completeness and timing.
- [x] Four terminal domains and shared assessment composition: WLAN lifecycle, authentication, port availability and PoE. Unknown historical power or dependency remains unknown.
- [x] Current managed AP physical-dependency verification, with explicit historical limitations and no arbitrary entity expansion.
- [x] Versioned application-owned domain skills, selected from the plan and unable to expand authority.
- [x] Common revision-pinned report with typed evidence tables/charts/timelines and shared impact/confidence bands.
- [x] Validated impacted-device records and topology overlay; serving APs are never classified as failed merely because their clients disconnected.
- [x] Investigation/log/history navigation and retention cleanup, including orphan artifacts and organization deletion.
- [ ] Bounded pinned OAS lookup library after operational gaps are demonstrated; an external MCP adapter remains conditional on an external consumer.
- [x] Operator adjudication/replay workflow, precision/recall counts and a fail-closed promotion gate. Real labels remain an operator task.
- [ ] Consumer migration readiness for Changes/Overview/Impact/notifications, mutually exclusive engine routing and retirement of broad collection only after acceptance.
- [ ] Final backend/frontend checks, scoped commits, documentation and review handoff.

Implementation decisions, evidence limitations and validations are appended to `impact-implementation-decisions.md`. Each capability uses the same deterministic and agent-required menu, existing audit budget and fenced journal. This queue does not authorize speculative VLAN/route/firewall resolvers or automatic production promotion.
