# Digital-twin guidance in Guardian

Guardian reuses the check catalog from
[digital-twin commit 6840ace](https://github.com/tmunzer-AIDE/digital-twin/tree/6840acea3c4ac2cf27411e443c04756074362e0f),
merged in upstream PR #50 on 2026-10-02. Upstream still identifies its package
as `0.1.0` and has no tagged release, so the source commit identifies this update.
The catalog contains 32 wired/wireless checks and two organization NAC checks.

`guardian/impact_rules.py` maps captured object differences to candidate checks.
The mapping is deliberately broader than the twin's IR predicates: Guardian
has raw configuration paths, not compiled before/after network models.
Its candidates are bounded investigator hints, never evidence, executed
simulations, deterministic coverage, a SAFE verdict or an impact severity.
Unsupported fields remain covered by Guardian's existing gap handling;
having no candidate does not establish that a change is safe.

## Adaptations for the latest upstream

| Change | Candidate guidance |
| --- | --- |
| `radius_config` or `mist_nac` | `wired.auth.radius_missing`: compare backends, including credential-only changes; verify client admission. |
| IPv4 `extra_routes` or IPv6 `extra_routes6` | `wired.l3.static_route_reachability` and `wired.l3.control_plane_reachability`: verify actual forwarding and management/authentication reachability. |
| L3 interface addressing | Include route-dependency and physical-topology checks. |
| Port configuration, usages or switch matching | Include `wired.port.storm_control_policy`, including uplink shutdown/threshold changes. |
| Switch/gateway profiles or site template assignments | Admit inherited wired candidates, and investigate whether device overrides mask the edit. |
| WLAN VLAN or other configuration edits | Admit wireless candidates; do not silently omit VLAN edits because they were absent from an attribute whitelist. |
| Organization network objects | Admit VLAN, subnet and L3 dependency candidates. |
| Generic configuration templates | Conservatively admit wired/wireless candidates because paths do not establish the template subtype. |

The topology-coverage mapping includes device, link and L3-interface changes,
matching the current upstream guard. The system prompt asks the investigator
to distinguish introduced failures, pre-existing conditions and overridden
inherited edits. Configured RADIUS servers do not prove successful admission;
configured routes do not prove installed or working forwarding.

The hints retain only check names, never configuration values or credentials.
They use 440-character chunks and a 1,500-byte hint envelope, with
candidate chunks first and deterministic plugin hints limited to applicable
plans. The prompt version is incremented. The fixed 48 KB and total 96 KB
limits, ten model turns, seven MCP calls, read authorization, and citation
validation stay enforced by the existing runner.

BLE assets/filters, location reporting, notifications, webhook delivery and
administrator SSO produce no network candidates. The
[network-impact exclusion policy](network-impact-policy.md) continues to govern
whether an audit starts an investigation. The candidate mapping cannot bypass
those exclusions or turn unavailable/zero-sample SLE data into degradation.

## Why the behavioral engine is not a runtime dependency

Upstream's new behavioral package is an offline foundation. Its own
[implementation documentation](https://github.com/tmunzer-AIDE/digital-twin/blob/6840acea3c4ac2cf27411e443c04756074362e0f/docs/behavioral-engine.md)
states that production Mist-to-behavior compilation is not implemented and
captures remain an incomplete behavioral inventory. A synthetic example cannot
validate Guardian's real captures or provide rollback safety guarantees.

There is also a runtime mismatch: the twin requires Python 3.14 and Mist SDK
`>=0.62,<0.63`, while Guardian supports Python 3.13 and currently locks Mist SDK
0.63.x. This integration therefore imports neither the twin nor its SDK
transport; Guardian keeps its existing collector and authenticated read runner.
No deployment configuration, public API, database migration or restore gate is
required. Guardian remains controlled by its existing `GUARDIAN_ENABLED` gate.

## Refreshing and verifying

1. Select an upstream commit, inspect the wired registry and separate NAC
   pipeline, and update `SOURCE_COMMIT` and the candidate relationships.
2. Review effective configuration roots and Guardian registry keys. A new
   candidate is guidance only; do not copy upstream review warnings into
   measured degradation or treat missing observations as a clean result.
3. Run the applicability, agent, runtime and replay tests. Verify that a mixed
   change retains all candidates in the prompt and that worst-case prompts
   still respect their limits.
4. Record upstream limitations and dependency compatibility here.

This refresh compared all 34 local check IDs with upstream source. Verification
uses offline fixtures and fake providers, with no live Mist or model calls.

Validation on 2026-10-02: 2,672 Guardian backend tests passed; 110
environment-dependent tests were skipped. Ruff format/lint, source type checks
and OpenAPI verification passed. Upstream's 2,173 offline tests passed, with
two live tests deselected; its lint, types, wheel build, CLI help, behavioral
demo and installed-wheel imports also passed. CodeRabbit was unavailable;
the change received a local diff review.
