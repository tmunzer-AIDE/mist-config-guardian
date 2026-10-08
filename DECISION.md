# UI redesign decisions

Source: `docs/Config Guardian.zip`, especially `Impact View Spec.dc.html` and the interactive `Config Guardian App.dc.html` reference. The archive is design input, not executable application code to import.

## Direction

- Replace the primary Impact session list with a site-centred change rail, a deterministic topology canvas, and one contextual detail panel. Keep the existing session evidence as a deliberate drill-down, so operational captures and collection errors remain accessible without occupying the default screen.
- Preserve the four selection combinations from the spec. Change selection scopes the diagram; device selection scopes the detail. Switching sites clears both. Pan and zoom are independent of selection.
- Use the reference's restrained typography, neutral surfaces, fine rules and compact status tokens. Prefer useful labels and measured whitespace over decorative gradients, large summary cards or repeated explanations.
- Remove decorative left accent stripes; use a selected background, clear focus ring and status badges. This also honours the earlier preference against left borders.

## Evidence and status

- Add an explicit **Unknown** health state. Connected does not prove healthy SLE, and missing telemetry never means OK. Connectivity, configuration delivery, monitoring progress and measured impact remain separate.
- PoE-related operational disruption can remain Critical under the existing deterministic rules. The new design's narrower Critical definition does not silently change backend incident policy.
- Monitoring percentage describes elapsed monitoring time, not the percentage of samples successfully collected. Sample counts and insufficient evidence are separately visible. Pending and aborted windows must not look completed successfully.
- Draw links only from observed topology identities. Do not infer a physical link from similar names, IP subnets, nearby timestamps or arbitrary placement. Missing links remain unknown. Layout roles and geometry are presentation hints, not discoveries.
- Historical mode must not label current topology or current verdicts as historical facts. Use only evidence available at the selected instant, or explicitly withhold a field when it cannot be reconstructed. Navigation and inspection remain possible; write paths stay disabled.

## API and scale

- Add organization-scoped read endpoints for site discovery, topology and paginated site changes. Return small, typed summaries; fetch detailed session evidence only on request.
- Use documented read-only Mist statistics for live topology, with bounded pagination and an explicit incomplete/error state. Never return raw provider configuration or credentials.
- Keep timestamps as ISO 8601 values. Format UTC in the UI rather than returning preformatted strings; this supports ordering, accessibility, exact timestamps and future locale preferences.
- Use actual audit identity for configuration events. Shared windows must disclose overlapping changes. Uncorrelated events stay visible and explicitly uncorrelated.

## Beyond Impact

- Replace the ambiguous top time scrubber with a labelled activity track, clear Live/historical state, exact time selection and an obvious return-to-live action. Keep range selection distinct from the as-of instant.
- Apply consistent page spacing, table headers, selection and focus treatment to Overview, Changes, Objects and Settings. Preserve established restore and credential workflows.
- Adapt the reference's panel overlay at a measured 1040px container width; add a usable small-screen mode below the widths the desktop reference covers. Do not shrink the entire diagram into unreadable text as the only mobile solution.

The implementation, departures and validation evidence follow.

## Implementation departures and tradeoffs

- The topology uses exact LLDP identities from site device statistics and organization switch/gateway port search. Missing or ambiguous identities remain unlinked; visually completing the tree would be misleading.
- Site colors describe connectivity until a change is selected; then affected devices describe that change's measured impact while other devices retain connectivity state. The header and footer identify the active meaning. Current healthy SLE is not fabricated from a device's connected status.
- Fit uses the actual occupied canvas width with a 400px minimum, and considers height too. Small sites keep readable labels; larger sites can pan and zoom. This departs from a mandatory 880px canvas. Manual zoom remains between 30% and 260%.
- Historical mode shows stored inventory and observed lifecycle evidence, withholding mutable verdicts and physical links. Site selector names are current labels. Evidence/action deep links are disabled in historical mode; return to Live for the full current session.
- A change with no device reports stays pending with unknown impact. Failed/reverted monitoring is aborted, not successfully completed. The monitoring-status enum itself is unchanged.
- Discovery is limited to 5000 records per source; site statistics to 5000 devices; event pages to 100 events; device expansion to 5000 windows with explicit truncation warnings. Filters are labeled as filtering loaded events. These limits avoid returning a whole organization's telemetry through the UI index.
- Kept detailed evidence, AI Assist configuration, restore authorization and credential policy intact. Shared flat surfaces, quieter shadows, selected backgrounds, typography and focus states improve the existing pages without introducing new configuration workflows.
- The global timeline now exposes UTC timestamps and separate range/instant controls. Deployment milestones show seconds; time selection supports exact input, event clicks, keyboard navigation and an explicit Live action.

## SLE correction and verification boundary

The corrected `docs/mist_sles.md` examples supersede the earlier generic device paths and agree with Juniper's published scope enum. AP collection uses `/sle/ap/…`, switches use `/sle/switch/…`, and gateways use `/sle/gateway/…`, for both discovery and summaries. Site collection uses `/sle/site/…`. Added the supplied current metric names to discovery's allowlist while preserving advertised legacy names as distinct stored keys. Baseline arithmetic, quiet-data semantics and the requirement for numeric evidence are unchanged. Regressions verify generated requests, not an actual Mist organization. This is not a claim that every deployment's 404 is resolved; discovery and live access still need real read-only validation.

The API contract, historical restrictions, collection limits, sources and browser test instructions are documented in `docs/design/site-impact-workspace.md`.


## Additional fixes found during validation

- The organization card that opens automatically in Settings now starts its snapshot-history request immediately. A failed history request stays unavailable with a Retry action, rather than looking empty. Reads are deduplicated while pending.
- Settings tabs remain available while scrolling, and Overview uses quieter per-event action buttons.
- Manual topology zoom survives site switches; pan resets. Out-of-scope labels remain readable. Critical and Error use distinct node treatments. The deployment timeline includes seconds.
- The global Live activity track refreshes once a minute while the page is visible. Historical tracks remain pinned to the selected instant.

## Validation evidence

### Visual refinement after design review

- Replaced the dark navigation slab with a quiet light sidebar, an inset blue selection, and clearer hover states. The workspace keeps its existing information hierarchy and selection behavior.
- Use the native system sans-serif for interface text and retain the self-hosted mono font for identifiers, timestamps, and raw data. Increased key headings and replaced small, widely tracked mono section labels with readable sans-serif labels.
- Impact's three regions have consistent 14px corners, subtle borders, and a 12px gutter. Mobile panels reclaim those gutters. Shared buttons, fields, segmented controls, tables, and menus use opaque surfaces and restrained shadows; color and spacing carry the hierarchy.
- Topology connections now use a darker 2px dotted stroke with shorter gaps. Links outside the selected change retain 72% opacity instead of 22%, so physical connectivity remains visible. Selected paths are 2.5px and blue; node health colors and labels retain their meaning.
- Used token-derived `color-mix()` selections, existing container queries, tabular numerals, and thin contained scroll areas. Reduced-motion preferences disable decorative transitions. No new fonts, runtime dependencies, API changes, or animations were introduced.
- CSS reference: [MDN color-mix](https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/Values/color_value/color-mix) and [SVG vector-effect](https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/Properties/vector-effect). The latter keeps SVG strokes from scaling within SVG transforms; the existing outer HTML canvas still controls overall zoom.
- Visual refinement validation: all five Chrome scenarios pass, including mobile/overlay behavior, topology interaction, and bounded tables. Inspected screenshots for Impact, Objects & versions, Changes, Overview, and Settings. Updated the synthetic-data preview. The production build passes; removed redundant CSS rather than increasing the component stylesheet budget.

### Original redesign validation

- Unit and API regressions cover event grouping, organization/site boundaries, bounded collection, immutable inventory, late arrivals, missing versus malformed SLE evidence, new Mist paths, UI selection, retries, pagination, exact UTC input and safe historical navigation.
- Real MongoDB 8 tests exercise event-first pagination, `$unionWith`, device expansion, historical filtering and immutable inventory. The existing database-backed restore search tests also pass against the disposable test server.
- Five reproducible Chrome scenarios cover the four selection states, drag/zoom and site switches, desktop overlays, mobile navigation, UTC/keyboard timeline controls, bounded tables, immediate change details, failed discovery/retry, and legacy session links. Screenshots were inspected for Impact, Objects, Changes, Overview and Settings. Fixtures are synthetic; no production writes or live Mist validation were performed.
- `docs/design/site-impact-preview.png` shows the final device/change panel with synthetic data. Browser artifacts remain in the ignored `frontend/test-results/` directory.


Final validation: `make check` passed with `MONGO_TEST_URL` set: **706 backend tests, 305 frontend tests, no skipped database tests**, OpenAPI validation and production build. The **five Chrome scenarios** also passed. The disposable MongoDB and design-reference server were shut down afterward. Existing application services were left running.


## Switch and gateway neighbor enhancement

- Use the documented organization port-search endpoint with the provider organization ID and MAC filters from the selected site's inventory. Validate returned organization/site membership and resolve only exact, unambiguous device, module, or port MACs.
- Return explicit device-pair links in the existing topology response. Preserve redundant and same-tier neighbors rather than forcing a single-parent hierarchy; aggregate the observed ports without claiming one-to-one circuit pairing. Existing parent/uplink fields remain a compatibility convenience only when the upstream layout neighbor is unique.
- Expose neighbor/port evidence in a collapsed device section with navigation to the peer. Keep link health unknown: Mist's endpoint contains current/last reports, not a proof of availability.
- Bound port collection independently to five requests / 5000 records and 15 seconds. Copy only validated pagination cursors into requests with fixed filters; no provider-directed credential forwarding. Port failures preserve device inventory and available AP evidence with an incomplete-collection warning. Historical mode remains inventory-only.
- Regenerate OpenAPI for the additive link schema; test membership, provider org IDs, virtual-chassis/port aliases, pagination, partial failures, bounds, redundant edges, and peer navigation. See `docs/design/site-impact-workspace.md` for the published Mist sources and API contract.
- Validation: 709 backend tests passed (20 MongoDB integration tests skipped because the disposable database was not started); 306 frontend tests and all six Chrome scenarios passed. Production build, formatting, lint, type checks, and OpenAPI consistency passed. The final adjacency lookup cleanup also passed all 44 focused neighbor/site regressions. `docs/design/neighbor-topology-preview.png` captures the inspected view with synthetic data. No live Mist validation was performed.

## Change-centered redesign · 2 October 2026

The latest request supersedes the earlier visual refinements: prioritize a fast
change dashboard, explicit configuration differences, global and local impact,
and fewer rollback screens. After the user's visual follow-up, the direction uses
a continuous neutral background, borderless shared navigation and top bars,
teal accents, stronger headings, and a compact time bar. Soft shadows lift main
cards and tables; selected detail panes and floating menus have more elevation.
The active navigation item uses stronger text and icon weight. The
existing Angular components and semantic status colors remain the foundation.

Overview supplies period-wide counters plus a recent change feed. Changes is the
main investigation workspace: selection narrows the list to a rail and displays
before/after values alongside cross-site impact. The existing topology is reused
with compact geometry; site cards and a device list provide accessible paths to
local measurements. Unknown impact is distinct from disruption and from a
measured absence of impact. Shared windows do not imply exclusive causation.

Rollback starts with an explicit plan action and preselected previous versions,
then stays inside the change through backup, final review and progress. The
server's existing authorization, approvals and execution gates are unchanged.
Missing previous versions are visible exclusions, not a promised complete undo.
See `docs/design/change-event-impact.md` for API and interaction conventions.

Validation on the isolated PR checkout: 2,596 backend tests passed, with 109 environment-dependent tests
skipped; 436 frontend tests and all 16 Chrome scenarios passed. Backend format,
lint, source type checks, the exported OpenAPI contract, and the frontend
production build passed. After the final advanced-target navigation adjustment,
all 53 restore component tests and the two change/rollback browser scenarios
passed again. Browser checks cover desktop/mobile layout, keyboard focus,
redacted comparisons, unknown evidence, retry, and the complete contextual
rollback journey including refresh/resume. They use mocked APIs and do not
validate a live Mist rollback. Saved previews are linked from the design note.

The follow-up flat styling pass passed the production build without budget
warnings and all 16 browser scenarios. Desktop/mobile screenshots were inspected
across Overview, Changes, Site topology, Configuration and Settings. The keyboard
test waits for the change list to become visible before focusing it, avoiding a
race with the shell's loading overlay. No API or application behavior changes
were needed for this visual pass.

The user also requested removal of the generic decorative UI treatment. Recent
change cards no longer carry colored left borders or duplicate severity dots.
Slogan overlines, numbered section labels, ornamental icons and the illustrative
topology thumbnail were removed. Dashboard cards now use neutral surfaces with
the requested shadows; headings name the information directly. Status badges,
functional selection states and the actual interactive topology remain.

This cleanup passed the production build, all 19 affected component tests and
all 16 browser scenarios. The saved dashboard, change and rollback previews
were refreshed from that run.


Backup receipts without captured object differences are now hidden before
change-feed pagination and counts. Network validation uses conservative,
explicit exclusions for BLE asset tracking/filters, reporting zones,
notifications, webhooks and administrator SSO; mixed and unrecognized changes
stay eligible. The policy and complete registry review are documented in
`docs/design/network-impact-policy.md`.

SLE collection retains sampled event totals for its anchored numeric window.
Unverified legacy zero percentages are unavailable, while measured zeroes and
independent incidents/device findings can still establish degradation. Cached
false zero alarms are corrected on reads; the existing bounded backfill updates
older group projections after deployment. No source observations are erased.

Validation: 2,640 backend tests passed; 110 environment-dependent checks were
skipped, including MongoDB integration coverage because MONGO_TEST_URL is unset.
All 436 frontend tests and 18 Chrome scenarios passed, along with production
build, Ruff format/lint, source type checks and OpenAPI export verification.
The browser scenarios include an excluded asset filter with its diff/rollback
and a direct link to an unlinked audit without an empty rollback card. CodeRabbit
is unavailable; changes received a local review. Mist validation used fixtures.

Guardian's previously stashed digital-twin guidance is now integrated against
upstream commit 6840ace (2026-10-02). Its 34-check catalog includes RADIUS backend,
static-route, control-plane and storm-control candidates. The refresh also fixes
missing WLAN VLAN, profile, network and topology-dependency mappings. Candidates
remain investigator hints; existing service-health citations, exclusions,
coverage gaps and execution limits still determine published impact.

The new behavioral engine is not imported: upstream has no production Mist
compiler, and its Python 3.14/Mist SDK 0.62.x requirements differ from Guardian's
runtime. Source provenance, compatibility and refresh instructions are recorded
in `docs/design/digital-twin-guidance.md`. No API or database change is required.

Validation: 2,672 backend tests passed (110 environment-dependent skips), plus
Ruff format/lint, source types and unchanged OpenAPI verification. Upstream's
2,173 offline tests, lint, types, wheel build and installed-wheel imports passed.
No live Mist/model calls were made. CodeRabbit remains unavailable; the diff
received a local review.

## Outcome-first UX · 8 October 2026

The approved mockups move the selected change into a focused workspace. The
shared top bar and left navigation remain transparent and borderless. The
application frame stays within the viewport, with independent content scroll
areas and 4px Chromium scrollbars (native thin on Firefox).

The first section separates deployment outcome, measured service impact and
application experience. It shows the reason for a finding, recovery time,
attribution limits, recommended next step and labelled AI interpretation before
raw captures or topology. Configuration, Timeline and Technical evidence are
local sections that retain the selected change and section in the URL. Full
version comparisons and legacy device evidence have a direct return to the
originating change. Device lists are the default; observed topology remains an
optional local view. Restore activity has a direct operator-only navigation
entry, while contextual rollback retains the existing backup, credential,
approval, confirmation and progress workflow.

A configuration failure is not proof of measured network degradation. Later
matching successful configuration in the same monitoring window closes the
failure using observed event time, including out-of-order receipt delivery.
Read-time reconciliation retains the historical peak, other operational findings
and uncertainty. Projection policy version 2 uses the existing bounded backfill
to repair list filters and counts without altering raw observations or receipts.
Stored AI text is preserved and flagged when severity or metric direction
conflicts with the deterministic evidence.

The information inventory, hierarchy, click paths and recovery limits are in
[configuration events and impact evidence](docs/design/change-event-impact.md).
The [desktop](docs/design/change-outcome-preview.png) and
[mobile](docs/design/change-outcome-mobile-preview.png) previews use synthetic
browser fixtures for the reported gateway scenario.

Validation: production build, 479 frontend unit tests and all 20 Chrome browser
scenarios passed. The compact-window refinement also passed focused outcome,
keyboard/context and independent-scroll checks at 1600, 1024, 768, 390 and 320px.
The backend suite passed 2,765 tests with 175 environment-dependent integration
cases skipped; formatting, lint, type checks and OpenAPI consistency passed.
An additional 77 focused group/recovery regressions passed after the wording
cleanup. Local code review was completed. CodeRabbit could not run because its
CLI reports that reauthentication is required. No live Mist restore, deployment
or other network mutation was performed.
