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
