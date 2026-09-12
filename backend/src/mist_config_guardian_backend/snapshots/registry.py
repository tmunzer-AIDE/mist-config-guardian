"""Restorable Mist configuration object registry."""

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class ObjectDefinition:
    """Read and identity metadata for one restorable Mist object type."""

    key: str
    label: str
    scope: Literal["org", "site"]
    endpoint: str
    is_list: bool = True
    name_fields: tuple[str, ...] = ("name",)
    request_params: tuple[tuple[str, str], ...] = ()
    response_items_key: str | None = None
    create_supported: bool = True
    update_supported: bool = True
    delete_supported: bool = True
    ignored_fields: frozenset[str] = frozenset(
        {
            "created_time",
            "modified_time",
            "last_seen",
        }
    )
    sensitive_fields: frozenset[str] = frozenset(
        {
            "api_secret",
            "client_secret",
            "passphrase",
            "password",
            "root_password",
            "private_key",
            "psk",
            "secret",
        }
    )
    restore_excluded_fields: frozenset[str] = frozenset(
        {
            "created_time",
            "id",
            "modified_time",
            "org_id",
            "site_id",
        }
    )

    def path(self, *, org_id: str, site_id: str | None = None) -> str:
        """Render the Mist API path for this definition."""
        if self.scope == "site" and site_id is None:
            msg = f"site_id is required for {self.key}"
            raise ValueError(msg)
        return self.endpoint.format(org_id=org_id, site_id=site_id)

    def item_path(
        self,
        object_id: str,
        *,
        org_id: str,
        site_id: str | None = None,
    ) -> str:
        """Render the update/delete path for one object."""
        collection_path = self.path(org_id=org_id, site_id=site_id)
        return f"{collection_path}/{object_id}" if self.is_list else collection_path

    def supports_restore_action(self, action: str) -> bool:
        """Return whether this object has an explicit inverse API operation."""
        return {
            "create": self.create_supported,
            "update": self.update_supported,
            "delete": self.delete_supported,
        }.get(action, False)


ORG_OBJECTS: tuple[ObjectDefinition, ...] = (
    ObjectDefinition(
        key="data",
        label="Organization",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}",
        is_list=False,
        create_supported=False,
        delete_supported=False,
    ),
    ObjectDefinition(
        key="settings",
        label="Organization Settings",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/setting",
        is_list=False,
        create_supported=False,
        delete_supported=False,
    ),
    ObjectDefinition(
        key="sites",
        label="Sites",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/sites",
    ),
    ObjectDefinition(
        key="sitegroups",
        label="Site Groups",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/sitegroups",
    ),
    ObjectDefinition(
        key="sitetemplates",
        label="Site Templates",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/sitetemplates",
    ),
    ObjectDefinition(
        key="templates",
        label="Configuration Templates",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/templates",
    ),
    ObjectDefinition(
        key="wlans",
        label="Organization WLANs",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/wlans",
        name_fields=("ssid", "name"),
    ),
    ObjectDefinition(
        key="networks",
        label="Networks",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/networks",
    ),
    ObjectDefinition(
        key="networktemplates",
        label="Network Templates",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/networktemplates",
    ),
    ObjectDefinition(
        key="rftemplates",
        label="RF Templates",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/rftemplates",
    ),
    ObjectDefinition(
        key="aptemplates",
        label="AP Templates",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/aptemplates",
    ),
    ObjectDefinition(
        key="deviceprofiles",
        label="AP Device Profiles",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/deviceprofiles",
        request_params=(("type", "ap"),),
    ),
    ObjectDefinition(
        key="switchprofiles",
        label="Switch Device Profiles",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/deviceprofiles",
        request_params=(("type", "switch"),),
    ),
    ObjectDefinition(
        key="hubprofiles",
        label="Gateway Device Profiles",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/deviceprofiles",
        request_params=(("type", "gateway"),),
    ),
    ObjectDefinition(
        key="gatewaytemplates",
        label="Gateway Templates",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/gatewaytemplates",
    ),
    ObjectDefinition(
        key="vpns",
        label="VPNs",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/vpns",
    ),
    ObjectDefinition(
        key="psks",
        label="PSKs",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/psks",
    ),
    ObjectDefinition(
        key="pskportals",
        label="PSK Portals",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/pskportals",
    ),
    ObjectDefinition(
        key="nacrules",
        label="NAC Rules",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/nacrules",
    ),
    ObjectDefinition(
        key="nactags",
        label="NAC Tags",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/nactags",
    ),
    ObjectDefinition(
        key="nacportals",
        label="NAC Portals",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/nacportals",
    ),
    ObjectDefinition(
        key="services",
        label="Services",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/services",
    ),
    ObjectDefinition(
        key="servicepolicies",
        label="Service Policies",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/servicepolicies",
    ),
    ObjectDefinition(
        key="secpolicies",
        label="Security Policies",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/secpolicies",
    ),
    ObjectDefinition(
        key="wxrules",
        label="Organization WxLAN Rules",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/wxrules",
    ),
    ObjectDefinition(
        key="alarmtemplates",
        label="Alarm Templates",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/alarmtemplates",
    ),
    ObjectDefinition(
        key="webhooks",
        label="Organization Webhooks",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/webhooks",
        name_fields=("name", "url"),
    ),
    ObjectDefinition(
        key="mxtunnels",
        label="Mist Tunnels",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/mxtunnels",
    ),
    ObjectDefinition(
        key="mxclusters",
        label="Mist Edge Clusters",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/mxclusters",
    ),
    ObjectDefinition(
        key="mxedges",
        label="Mist Edge Appliances",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/mxedges",
    ),
    ObjectDefinition(
        key="avprofiles",
        label="Antivirus Profiles",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/avprofiles",
    ),
    ObjectDefinition(
        key="idpprofiles",
        label="IDP Profiles",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/idpprofiles",
    ),
    ObjectDefinition(
        key="secintelprofiles",
        label="Security Intelligence Profiles",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/secintelprofiles",
    ),
    ObjectDefinition(
        key="ssos",
        label="SSO Configurations",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/ssos",
    ),
    ObjectDefinition(
        key="ssoroles",
        label="SSO Roles",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/ssoroles",
    ),
    ObjectDefinition(
        key="assets",
        label="Assets",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/assets",
    ),
    ObjectDefinition(
        key="assetfilters",
        label="Asset Filters",
        scope="org",
        endpoint="/api/v1/orgs/{org_id}/assetfilters",
    ),
)

SITE_OBJECTS: tuple[ObjectDefinition, ...] = (
    ObjectDefinition(
        key="info",
        label="Site Information",
        scope="site",
        endpoint="/api/v1/sites/{site_id}",
        is_list=False,
        create_supported=False,
        delete_supported=False,
    ),
    ObjectDefinition(
        key="settings",
        label="Site Settings",
        scope="site",
        endpoint="/api/v1/sites/{site_id}/setting",
        is_list=False,
        create_supported=False,
        delete_supported=False,
    ),
    ObjectDefinition(
        key="wlans",
        label="Site WLANs",
        scope="site",
        endpoint="/api/v1/sites/{site_id}/wlans",
        name_fields=("ssid", "name"),
    ),
    ObjectDefinition(
        key="devices",
        label="Devices",
        scope="site",
        endpoint="/api/v1/sites/{site_id}/devices",
        name_fields=("name", "mac"),
        request_params=(("type", "all"),),
        create_supported=False,
        delete_supported=False,
    ),
    ObjectDefinition(
        key="maps",
        label="Maps",
        scope="site",
        endpoint="/api/v1/sites/{site_id}/maps",
    ),
    ObjectDefinition(
        key="zones",
        label="Zones",
        scope="site",
        endpoint="/api/v1/sites/{site_id}/zones",
    ),
    ObjectDefinition(
        key="rssizones",
        label="RSSI Zones",
        scope="site",
        endpoint="/api/v1/sites/{site_id}/rssizones",
    ),
    ObjectDefinition(
        key="psks",
        label="Site PSKs",
        scope="site",
        endpoint="/api/v1/sites/{site_id}/psks",
    ),
    ObjectDefinition(
        key="assets",
        label="Site Assets",
        scope="site",
        endpoint="/api/v1/sites/{site_id}/assets",
    ),
    ObjectDefinition(
        key="beacons",
        label="Beacons",
        scope="site",
        endpoint="/api/v1/sites/{site_id}/beacons",
    ),
    ObjectDefinition(
        key="vbeacons",
        label="Virtual Beacons",
        scope="site",
        endpoint="/api/v1/sites/{site_id}/vbeacons",
    ),
    ObjectDefinition(
        key="wxrules",
        label="Site WxLAN Rules",
        scope="site",
        endpoint="/api/v1/sites/{site_id}/wxrules",
    ),
    ObjectDefinition(
        key="wxtags",
        label="WxLAN Tags",
        scope="site",
        endpoint="/api/v1/sites/{site_id}/wxtags",
    ),
    ObjectDefinition(
        key="webhooks",
        label="Site Webhooks",
        scope="site",
        endpoint="/api/v1/sites/{site_id}/webhooks",
        name_fields=("name", "url"),
    ),
)


def object_name(configuration: dict[str, object], definition: ObjectDefinition) -> str:
    """Extract a stable display name from an object."""
    for field_name in definition.name_fields:
        value = configuration.get(field_name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    object_id = configuration.get("id")
    return str(object_id)[:12] if object_id else definition.label


def get_definition(scope: str, object_type: str) -> ObjectDefinition | None:
    """Look up a registry definition by persisted scope and type."""
    definitions = SITE_OBJECTS if scope == "site" else ORG_OBJECTS
    return next((item for item in definitions if item.key == object_type), None)
