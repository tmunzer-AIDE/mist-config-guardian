"""Administrative changes stay in history without unrelated network alarms."""

import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.models.webhook import ChangedObjectRef
from mist_config_guardian_backend.services.network_impact_policy import EXCLUDED_OBJECTS, exclusion_reason
from mist_config_guardian_backend.snapshots.registry import ORG_OBJECTS, SITE_OBJECTS


def ref(kind, fields=(), event="updated"):
    return ChangedObjectRef(
        logical_object_id=PydanticObjectId(),
        object_type=kind,
        object_name="Example",
        scope="org",
        event=event,
        changed_fields=list(fields),
    )


@pytest.mark.parametrize("kind", sorted(EXCLUDED_OBJECTS))
@pytest.mark.parametrize("event", ["created", "updated", "deleted", "restored"])
def test_administration_and_location_reporting_do_not_validate_network_quality(kind, event):
    assert exclusion_reason([ref(kind, ("enabled",), event)])


def test_every_backed_up_object_type_is_reviewed_and_unknown_types_remain_eligible():
    eligible = {
        "data",
        "settings",
        "sites",
        "info",
        "sitegroups",
        "sitetemplates",
        "templates",
        "wlans",
        "networks",
        "networktemplates",
        "rftemplates",
        "aptemplates",
        "deviceprofiles",
        "switchprofiles",
        "hubprofiles",
        "gatewaytemplates",
        "vpns",
        "psks",
        "pskportals",
        "nacrules",
        "nactags",
        "nacportals",
        "services",
        "servicepolicies",
        "secpolicies",
        "wxrules",
        "mxtunnels",
        "mxclusters",
        "mxedges",
        "avprofiles",
        "idpprofiles",
        "secintelprofiles",
        "devices",
        "maps",
        "beacons",
        "vbeacons",
        "wxtags",
    }
    assert {item.key for item in (*ORG_OBJECTS, *SITE_OBJECTS)} == eligible | EXCLUDED_OBJECTS.keys()
    for kind in eligible | {"future-network-object"}:
        assert exclusion_reason([ref(kind, ("future_setting",))]) is None


def test_only_metadata_can_be_excluded_and_mixed_changes_remain_eligible():
    assert exclusion_reason([ref("devices", ("name", "notes"))])
    assert exclusion_reason([ref("devices", ("notes", "port_config"))]) is None
    assert exclusion_reason([ref("devices", ("name",), "deleted")]) is None
    assert exclusion_reason([ref("sites", ("timezone",))]) is None
    assert exclusion_reason([ref("wlans", ("name",))]) is None
    assert exclusion_reason([ref("assetfilters"), ref("networktemplates")]) is None
    assert exclusion_reason([ref("devices")]) is None


def test_asset_filter_audit_without_linked_versions_is_still_excluded():
    assert exclusion_reason([], 'Update Asset Filter "Aeroscout" (from "A1")')
    assert exclusion_reason([], 'Update WLAN "Asset Filter"') is None
    assert exclusion_reason([], "Update unrecognized object") is None
