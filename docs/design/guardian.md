# Guardian

Guardian is the audit-level impact investigation described in
[the simplification design](../superpowers/specs/2026-09-16-guardian-simplification-design.md).
This document records the external facts that design depends on, and how the implemented engine is run.

## Running Guardian

Guardian is off by default: `GUARDIAN_ENABLED` (Helm `config.guardianEnabled`, `false`) on the API and the
worker. That one boolean is every gate there is. While it is off, no webhook starts a root, the worker tick
polls nothing, the changes, overview and site pages project nothing for it, and its two endpoints answer not
found because no root exists to read. Turning it on changes nothing about the per-device monitoring
subsystem -- its verdicts, badges and notifications stay the production ones -- except that it supersedes the
old per-device AI narrator, which is then not run.

When it is on, an investigation needs AI provider configuration and reads the Mist MCP endpoint in
`MIST_MCP_URL`. External spend per audit is bounded by 2 runs x 2 attempts x (10 model turns + 7 MCP calls +
8 rule reads), plus one MCP catalogue discovery per attempt.

Guardian writes `guardian_investigations` and `guardian_runs` and nothing else. Both carry `retained_until`,
derived from the organization's `monitoring_retention_days`, and expire through a partial TTL index. The hourly
`guardian.maintain_retention` job exists only for what a TTL cannot see: documents whose organization has been
deleted.

### Removing the collections of the engine it replaced

The engine Guardian replaced owned five collections: `impact_investigations`, `investigation_revisions`,
`impact_model_request_artifacts`, `impact_adjudications` and `neighbor_bindings`. No code reads or writes them
any more and no document model is registered for them. `scripts/drop-legacy-impact-collections.py` removes
them, and nothing else. It never runs at startup or on a tick: an operator invokes it, and it only reports
each collection and its document count until `--apply` is given. Running it again is safe -- a collection
already gone is reported as absent.

## Verified external contracts

The design left five facts to verification. Each one is recorded in
[`guardian-verification.yaml`](guardian-verification.yaml) with its question, sources, observation time, result and
the SHA-256 of every fixture it was decided from. The fixtures live in `backend/tests/fixtures/guardian/`.
`backend/tests/test_guardian_verified_contracts.py` fails when a decision is missing, a result is outside its allowed
set, or a fixture changes without its recorded hash. Later tasks read the record through
`backend/tests/guardian_verification.py`.

Verification made no Mist configuration write and used no AI provider or Mist credentials. The read-only Mist MCP
tools were disabled in the verification environment. The sources are therefore the Mist OpenAPI specification
(2609.1.0, `mistsys/mist_openapi@609ea46`), the recorded MCP catalogue, repository code, and the DNT-NTR audit
reconstructed from production API projections.

| Decision | Result | Consumed by |
|---|---|---|
| `device_event_ordering` | `same_second_ambiguous` | Task 4 deployment pairing |
| `sw_configured_emission` | `unknown` | Task 4 deployment pairing, Task 12 replay |
| `dns_attribute_semantics` | `recorded` (3 management, 10 client, 18 both, 34 unverified) | Task 6 `dns` plug-in |
| `mcp_evidence_kind_allowlist` | `frozen` (85 combinations over 5 tools) | Task 5 Reader |
| `structured_output_capability` | `inconclusive` | Task 5 capability probe |

### Device-event ordering

- The provider contract defines a device event's `timestamp` as epoch seconds and lists no sequence, counter or
  ordering property. `additionalProperties` is false, and `count` is an event count.
- All 11 recorded DNT-NTR device-event occurrence times are whole seconds. The audit time carries milliseconds
  (04:41:35.242). Comparing the two directly placed every trigger before the change: the 242 ms regression.
- Receipt creation time and ObjectId reflect delivery order, not occurrence order.

Device-event times are compared at one-second precision, with the change anchor truncated to the second. Triggers
from different audits for one device in the same second, and conflicting outcomes in the same second, stay
ambiguous. Receipt time remains a fallback that never satisfies a precondition.

### `SW_CONFIGURED` emission

No controlled test was run. In DNT-NTR all three switches received `SW_CONFIG_CHANGED_BY_USER` and none reported
`SW_CONFIGURED`, `SW_CONFIG_FAILED` or `SW_CONFIG_REVERTED` within the monitoring hour. The APs and the gateway
did report `*_CONFIGURED`. The switches' rendered configuration may or may not have changed, because DNS set in a
switch's `ip_config` or `oob_ip_config` overrides the template's `dns_servers`. The observation can't tell
"not emitted for an unchanged configuration" from "not emitted or not delivered at all".

The result is `unknown`. A targeted switch without a confirming outcome keeps an unsatisfied deployment
precondition, so switch-bearing audits stay at `info` until a controlled test or a config-confirmation plug-in
settles it.

### DNS attribute semantics

`dns_attribute_semantics.json` covers every registry object type. For each one it lists every property whose name
contains `dns`, or whose description names DNS, found through `$ref`, composition, maps and lists. Paths use `*`
for one object key and `[]` for one list index. Every entry cites the schema pointer and text it was decided from.

| Semantics | Object types and paths | Schema basis |
|---|---|---|
| `management_resolution` | `org:deviceprofiles` and `site:devices` (AP) `ip_config.dns`, `ip_config.dns_suffix` | "DNS server IP addresses for AP management traffic" |
| `management_resolution` | `org:mxedges` `oob_ip_config.dns` | "Name server addresses for out-of-band management" |
| `client_resolution` | `dhcpd_config.*.dns_servers` and `dns_suffix` of switch profiles, gateway profiles, gateway templates, site gateway settings and switch/gateway devices | "DNS servers advertised to DHCP clients" |
| `client_resolution` | `org:wlans`, `site:wlans` `no_static_dns`, `dns_server_rewrite` | Restricts or rewrites the DNS that wireless clients use |
| `management_and_client_resolution` | Switch and gateway resolver settings: global `dns_servers`/`dns_suffix` of network templates, switch and gateway profiles, gateway templates, site `switch`/`gateway` settings and devices, plus `dnsOverride` and Junos `ip_config` DNS | "dns settings in `ip_config` and `oob_ip_config` will overwrite this setting" and "if not defined, system one will be used" |

**Dual-use rule.** A setting gets `management_and_client_resolution` when the schema documents both uses: it is the
device's own management resolver, and the device's DHCP server hands the same resolver to clients of any scope that
defines no DNS. The `dns` plug-in emits the union of infrastructure-connectivity obligations
(`empty_policy=incomplete`) and client obligations (`empty_policy=not_exercised`) for it, so a management-only
check can never hide a client effect. Network templates target switches, as the recorded catalogue describes them.

Everything else is `unverified` and stays uncovered:

- Site-level `dns_servers`/`dns_suffix`, because the device types that consume them are not established.
- Gateway data-interface resolvers (`port_config.*.ip_config.dns`), whose traffic is not established.
- Settings that are not resolver configuration: mDNS forwarding, DNS-failure alert thresholds, Sky ATP DNS
  inspection, SecIntel categories, host-out path policy, and `use_mgmt_vrf` or management `network` selection.
- Legacy `secpolicies` WLAN copies and Mist tunnel IPsec client DNS, whose consuming devices are not established.

An attribute absent from the table is rejected as unknown, and so is any class outside the four above. The
DNT-NTR change (`org:networktemplates` `dns_servers`) is dual use for switches.

### MCP evidence-kind allowlist

`mcp_allowlist.json` is frozen from `backend/tests/fixtures/mist_mcp_catalog.json` (recorded `tools/list`, no live
discovery). Each allowlisted tool's input schema is hashed as sorted-key, compact UTF-8 JSON.

| Tool | Discriminator | Kind | Excluded values | org / site / time |
|---|---|---|---|---|
| `search_mist_data` | `search_type` | `service_health` (events, alarms, client/device/session searches) | `sites`, `inventory`, `mxedges`, `usermacs`, `guest_authorizations`, `rogue_events` | yes / yes / yes |
| `get_mist_stats` | `stats_type` | `service_health` (all 15) | none | yes / yes / yes |
| `get_mist_insights` | `insight_type` | `service_health` (all 4) | none | yes / yes / yes |
| `get_mist_config` | `resource_type` | `configuration` (27) | `psks`, `webhooks` | yes / yes / no |
| `get_mist_constants` | `constant_type` | `reference` (all 27) | none | no / no / no |

The last column freezes `requires_org`, `site_scopable` and `time_ranged` from the recorded input schema
(controller ruling R28). The Reader injects `org_id`, applies the site rule and requires one fixed window from
these frozen facts, never from what a server advertises, and it rejects a discovered tool whose schema
contradicts them.

`get_mist_self` and `find_mist_entity` are not allowlisted. The secret-bearing configuration objects `psks` and
`webhooks` are excluded for minimal exposure, since they carry no investigation value. A tool, or a discriminator
value, that is missing from the fixture is unavailable.

### Structured-output capability

The result is `inconclusive`. No provider was probed, because verification does not use provider credentials, and
the Guardian action schema does not exist until Task 7. The setup-time probe added in Task 5 produces the
authoritative capability record. Without that record the agent is skipped.

## DNT-NTR replay expectations

The replay fixtures are `dnt_ntr_change.json`, `dnt_ntr_monitoring.json` and `dnt_ntr_device_events.json`. They are
reconstructed from API projections, and organization, site, audit, object, session, receipt and device identifiers
are pseudonymized. Timestamps, event types, device types and metric values and states are kept as recorded. No
raw webhook bodies or individual monitoring observations exist for this audit.

The expected outcome is **conditional**, for two reasons. `SW_CONFIGURED` emission is unknown, and the choice of
infrastructure and client metrics for the dual-use mapping belongs to Task 6. Only mapping-independent invariants
are asserted now:

- At one-second precision every audit-linked trigger is at or after the anchor, with one trigger per device, and
  every `*_CONFIGURED` outcome follows its trigger within 30 minutes. No device becomes deployment `unknown` because
  of the 242 ms boundary.
- The three switches have no confirming outcome, and the dual-use mapping targets them, so each one has an
  unsatisfied deployment precondition.

The dual-use mapping handles the DNS atom on the three switches. The three APs and the gateway are not targeted by a
switch mapping, so the atom stays uncovered on them. Under the recorded decisions, the spec's rules imply `info` peak
and current, `partial` coverage, `low` confidence and no recovery, both as recorded and with `SW_CONFIGURED` added.
No input reaches `warning`. Task 12 asserts the final result once the engine exists.

## Refreshing a verification

1. Re-derive the fact from its cited source, and keep fixtures redacted and pseudonymized.
2. Update the fixture, its `sha256` in `guardian-verification.yaml`, the decision's `result`, `observed_at` and
   `notes`, and this document.
3. Revisit `dnt_ntr_expected_outcomes`. The test requires it to stay `conditional` while the DNT-NTR attribute is
   unverified or `SW_CONFIGURED` emission is unknown.

Never update a hash without re-verifying the fact behind it.
