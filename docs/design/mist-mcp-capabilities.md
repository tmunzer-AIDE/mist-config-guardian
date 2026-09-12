# Mist MCP capability checks

Read-only probe on 2026-09-12 against TM-LAB, sampling DNT-NTR. No configuration
was changed. This is capability evidence, not an impact assessment or an exhaustive
organization inventory. Raw client/configuration records and credentials are not
included in this report.

## Observed working

| Capability | Observation | Implementation consequence |
| --- | --- | --- |
| Site configuration/inventory | Paginated site list with template and site-group references | Resolve actual site IDs and configuration references; do not rely on names |
| Device inventory | Site statistics returned a switch, gateway and AP with stable IDs | Use statistics for inventory; configuration listing is not exhaustive inventory |
| Detailed AP statistics | Single-device lookup returned radio, CPU, memory, power and LLDP fields | List responses are abbreviated; retrieve detail for required evidence |
| Physical AP dependency | AP LLDP identified an inventoried switch and its exact port; the targeted port identified the AP neighbor | Provides a concrete v1 port-to-powered-device relationship |
| Port power/link evidence | Targeted switch-port result included `poe_on`, `power_draw`, `up`, speed and neighbor data | PoE and link checks can use operational evidence through this MCP |
| Historical wireless sessions | One-hour client-session search returned connection/disconnection times, AP, WLAN ID, SSID and client identity | Supports former-client cohort discovery; one sampled page does not establish complete occupancy |
| Device-event search | Bounded one-hour AP event query succeeded with zero results | Endpoint access verified; absence of events in this sample is not outage evidence |
| SLE discovery | Site and AP-scope requests returned supported/enabled lists | Discover capabilities; lists alone do not prove every metric works at every scope |
| Historical AP SLE trend | Explicit start/end timestamps were reflected exactly in AP-health response | Verified one-hour historical window support despite narrower wording in tool parameter documentation |
| SLE raw evidence | AP-health response contained totals/degraded counters, 600-second interval and classifier series | Preserve sample counts, intervals and null buckets; agent need not infer causes from aggregate score alone |

Observed classifiers included low power, AP/switch/site disconnection, reboot,
Ethernet errors/speed mismatch, latency, jitter and tunnel loss. Their presence
does not imply an incident. The sampled trend included null buckets; those must
remain missing/unsampled evidence, not zero-success measurements.

Pagination remains explicit. A targeted port response returned one item, total=1,
and a continuation cursor with `has_more=true`. Do not assume total==count means
collection is complete. Follow bounded cursors, deduplicate identities and detect
repeated cursors. This probe did not exhaust that cursor or the session-history pages.

## Advertised but not yet verified here

- Wired/NAC/WAN clients and events, BGP/OSPF peers, tunnels and VPN peer paths.
- Impacted-client/device/interface/application SLE queries and classifier-specific queries.
- Configuration reads for profiles and WLAN/network/gateway templates.
- Marvis troubleshooting/actions (tool descriptions identify subscription/preview conditions).

These are candidate capabilities, not validated contracts. No secret-bearing
WLAN/profile configuration was fetched merely to inventory the tools.

## Remaining boundaries

- `get_mist_config` does not advertise site/organization settings or derived WLAN
  configuration as selectable resource types. Its description explicitly mentions
  derived WLANs as an endpoint outside its resource-type interface. Effective
  configuration resolution may still need Guardian snapshots or a controlled API adapter.
- Peer statistics do not establish route selection or which application flows
  traverse a path. VLAN/route/firewall dependency attribution remains unverified.
- No tool currently advertises per-attribute OAS documentation retrieval. The
  proposed documentation MCP therefore has a distinct role.
- This desktop MCP connection does not automatically connect Guardian's background
  worker. That runtime needs an explicit MCP client, organization-scoped execution,
  capability/handle validation and shared polling integration as already designed.

Conclusion: the probe supports using Mist MCP as an operational evidence source
for the initial WLAN/client and physical PoE investigations. It does not establish
that every field, historical interval or future cross-platform rule is covered.
