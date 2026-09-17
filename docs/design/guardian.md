# Guardian

Guardian is the audit-level impact investigation described in
[the simplification design](../superpowers/specs/2026-09-16-guardian-simplification-design.md).
This document starts with the external facts that design depends on. Later tasks add the implemented design.

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
| `dns_attribute_semantics` | `recorded` (3 management, 10 client, 52 unverified) | Task 6 `dns` plug-in |
| `mcp_evidence_kind_allowlist` | `frozen` (87 combinations over 5 tools) | Task 5 Reader |
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

Everything else is `unverified` and stays uncovered:

- **Switch and gateway resolver settings.** This covers global `dns_servers`/`dns_suffix` (network templates, switch
  and gateway profiles, gateway templates, site settings, devices), `dnsOverride` and Junos `ip_config` DNS. The
  schema ties them to the device's own management resolver ("dns settings in `ip_config` and `oob_ip_config` will
  overwrite this setting"). The DHCP server on the same device falls back to that resolver ("if not defined, system
  one will be used"). Management resolution is established; a client effect is possible. A management-only
  mapping could therefore hide a client impact.
- Gateway data-interface resolvers (`port_config.*.ip_config.dns`), whose traffic is not established.
- Settings that are not resolver configuration: mDNS forwarding, DNS-failure alert thresholds, Sky ATP DNS
  inspection, SecIntel categories, host-out path policy, and `use_mgmt_vrf` or management `network` selection.
- Legacy `secpolicies` WLAN copies and Mist tunnel IPsec client DNS, whose consuming devices are not established.

An attribute absent from the table is rejected as unknown. The DNT-NTR change (`org:networktemplates`
`dns_servers`) is unverified, so the `dns` plug-in does not claim it.

### MCP evidence-kind allowlist

`mcp_allowlist.json` is frozen from `backend/tests/fixtures/mist_mcp_catalog.json` (recorded `tools/list`, no live
discovery). Each allowlisted tool's input schema is hashed as sorted-key, compact UTF-8 JSON.

| Tool | Discriminator | Kind | Excluded values |
|---|---|---|---|
| `search_mist_data` | `search_type` | `service_health` (events, alarms, client/device/session searches) | `sites`, `inventory`, `mxedges`, `usermacs`, `guest_authorizations`, `rogue_events` |
| `get_mist_stats` | `stats_type` | `service_health` (all 15) | none |
| `get_mist_insights` | `insight_type` | `service_health` (all 4) | none |
| `get_mist_config` | `resource_type` | `configuration` (all 29) | none |
| `get_mist_constants` | `constant_type` | `reference` (all 27) | none |

`get_mist_self` and `find_mist_entity` are not allowlisted. A tool, or a discriminator value, that is missing from
the fixture is unavailable. The secret-bearing configuration types `psks` and `webhooks` are allowlisted as
configuration, so the Reader's redaction must hold for them.

### Structured-output capability

The result is `inconclusive`. No provider was probed, because verification does not use provider credentials, and
the Guardian action schema does not exist until Task 7. The setup-time probe added in Task 5 produces the
authoritative capability record. Without that record the agent is skipped.

## DNT-NTR replay expectations

The replay fixtures are `dnt_ntr_change.json`, `dnt_ntr_monitoring.json` and `dnt_ntr_device_events.json`. They are
reconstructed from API projections, and organization, site, audit, object, session, receipt and device identifiers
are pseudonymized. Timestamps, event types, device types and metric values and states are kept as recorded. No
raw webhook bodies or individual monitoring observations exist for this audit.

The expected outcome is **conditional**, because the DNS mapping for the change is unverified and `SW_CONFIGURED`
emission is unknown. Only mapping-independent invariants are asserted now:

- At one-second precision every audit-linked trigger is at or after the anchor, with one trigger per device, and
  every `*_CONFIGURED` outcome follows its trigger within 30 minutes. No device becomes deployment `unknown` because
  of the 242 ms boundary.
- The three switches have no confirming outcome, so any of them that is targeted has an unsatisfied deployment
  precondition.

Under the recorded decisions, the spec's rules imply `info` peak and current, `partial` coverage, `low` confidence
and no recovery, both as recorded and with `SW_CONFIGURED` added. The atom `dns_servers` stays uncovered on all
seven expected devices, and no input reaches `warning`. Task 12 asserts the final result once the engine exists.

## Refreshing a verification

1. Re-derive the fact from its cited source, and keep fixtures redacted and pseudonymized.
2. Update the fixture, its `sha256` in `guardian-verification.yaml`, the decision's `result`, `observed_at` and
   `notes`, and this document.
3. Revisit `dnt_ntr_expected_outcomes`. The test requires it to stay `conditional` while the DNT-NTR attribute is
   unverified or `SW_CONFIGURED` emission is unknown.

Never update a hash without re-verifying the fact behind it.
