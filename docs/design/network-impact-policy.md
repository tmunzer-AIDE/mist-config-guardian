# Network-service impact eligibility

The policy concerns packet forwarding, radio service and client network access.
It preserves all captured configuration differences in history. Only changes
with a documented, known non-network role are excluded from network validation.
Unknown object types, unknown fields, empty field lists and mixed changes remain
eligible. The policy is implemented in `services/network_impact_policy.py`;
a registry-coverage test requires a deliberate review when backup support grows.

| Object types | Network validation | Reason |
| --- | --- | --- |
| `assetfilters`, `assets` | Excluded | Categorization and tracking of existing BLE assets. |
| `zones`, `rssizones` | Excluded | Location reporting areas. |
| `alarmtemplates`, `webhooks` | Excluded | Notifications and event delivery. Collection availability is a separate operational concern. |
| `ssos`, `ssoroles` | Excluded | Administrator portal identity and permissions. |
| `data`, `settings`, `sites`, `info`, `sitegroups` | Eligible | Organization/site configuration can contain effective defaults, schedules, regulatory settings and template assignment. |
| `sitetemplates`, `templates`, `wlans`, `networks`, `networktemplates` | Eligible | Effective network configuration and template references. |
| `rftemplates`, `aptemplates`, `deviceprofiles`, `switchprofiles`, `hubprofiles`, `gatewaytemplates`, `devices` | Eligible | RF, interface, firmware and device service configuration. |
| `vpns`, `mxtunnels`, `mxclusters`, `mxedges` | Eligible | Forwarding, tunneling and connectivity. |
| `psks`, `pskportals`, `nacrules`, `nactags`, `nacportals` | Eligible | Client access and authentication. |
| `services`, `servicepolicies`, `secpolicies`, `wxrules`, `wxtags`, `avprofiles`, `idpprofiles`, `secintelprofiles` | Eligible | Traffic selection, security rules and referenced policies. |
| `maps`, `beacons`, `vbeacons` | Eligible | Keep conservative coverage for placement/RF and radio or beacon configuration. Do not exclude a whole location-related object if it can configure a radio. |

Only **updated** device `name`/`notes`, site `name`/`notes`/`address`/`latlng`, or
organization `data.name` changes are excluded at field level. Every changed
field must belong to that type's allowlist. Creation, deletion, restoration,
site time zones/countries, and names on referenced policy objects remain
eligible. A group combining an asset filter with a port/VLAN change is eligible.

The asset-filter classification follows [Juniper's asset-filter documentation](https://www.juniper.net/documentation/us/en/software/mist/location-services/topics/concept/ble-assets.html):
the filter identifies and categorizes existing beacon tags. Radio settings for
Asset Visibility or Bluetooth engagement belong to AP/site configuration and
remain eligible. The distinction prevents unrelated Wi-Fi SLE changes from
being attributed to an asset-filter rename.

Numeric SLE evidence follows the sampled totals from Mist's summary-trend
response, documented through [Mist SLE API workflows](https://www.juniper.net/documentation/us/en/software/mist/automation-integration/topics/concept/api-mist-metrics.html).
Zero sampled events are unavailable. Zero quality with positive sampled events
is measured. Old zero percentages without sample totals remain unknown until
new measurements provide evidence; they are not assumed to be healthy.
