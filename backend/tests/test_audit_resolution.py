"""Mist audit target resolution tests."""

import pytest

from mist_config_guardian_backend.webhooks.audits import (
    is_configuration_change,
    resolve_audit_target,
)


def test_resolve_site_wlan_from_identifier() -> None:
    target = resolve_audit_target(
        {
            "topic": "audits",
            "site_id": "site-1",
            "wlan_id": "wlan-1",
            "message": 'Update WLAN "Corporate"',
        }
    )

    assert target is not None
    assert target.definition.key == "wlans"
    assert target.definition.scope == "site"
    assert target.object_id == "wlan-1"
    assert target.site_id == "site-1"
    assert not target.deleted


def test_resolve_deleted_site_from_message() -> None:
    target = resolve_audit_target(
        {
            "topic": "audits",
            "site_id": "site-1",
            "message": 'Delete Site "Branch"',
        }
    )

    assert target is not None
    assert target.definition.key == "sites"
    assert target.object_id == "site-1"
    assert target.site_id is None
    assert target.deleted
    assert target.object_name == "Branch"


def test_ignore_non_actionable_audit() -> None:
    assert resolve_audit_target({"topic": "audits", "message": "Logged in"}) is None


@pytest.mark.parametrize("message", ["Update Site Settings", "Modify Site Settings"])
def test_resolve_site_settings_audit(message: str) -> None:
    target = resolve_audit_target(
        {
            "topic": "audits",
            "id": "audit-1",
            "site_id": "site-1",
            "message": message,
            "before": '{"auto_upgrade": {"enabled": false}}',
            "after": '{"auto_upgrade": {"enabled": true}}',
        }
    )

    assert target is not None
    assert target.definition.key == "settings"
    assert target.definition.scope == "site"
    assert target.definition.endpoint == "/api/v1/sites/{site_id}/setting"
    assert target.object_id is None
    assert target.site_id == "site-1"
    assert not target.deleted


def test_site_settings_without_site_cannot_resolve_to_organization_settings() -> None:
    assert resolve_audit_target({"topic": "audits", "id": "audit-1", "message": "Update Site Settings"}) is None


def test_registry_backed_audit_is_a_configuration_change() -> None:
    assert is_configuration_change(
        {
            "topic": "audits",
            "mxcluster_id": "72df7314-b11b-49d8-8570-c7b39ab7c0c0",
            "message": 'Update MxCluster "campus_cluster"',
            "before": {"tunterm_hosts_selection": "shuffle"},
            "after": {"tunterm_hosts_selection": "shuffle-by-site"},
            "site_id": None,
        }
    )


def test_deletion_of_registry_object_is_a_configuration_change() -> None:
    assert is_configuration_change(
        {
            "topic": "audits",
            "message": 'Delete MxEdge "teleworker-x1"',
            "mxedge_id": "None",
            "site_id": None,
        }
    )


def test_trailing_verb_is_a_configuration_change() -> None:
    # Mist puts the verb after the noun for some org-level objects. The event
    # resolves to no registry object, so only the verb can classify it.
    assert is_configuration_change(
        {
            "topic": "audits",
            "message": "Org API Token 1f258aca-3477-4c5a-a180-77d80929482b created",
            "site_id": None,
        }
    )


@pytest.mark.parametrize(
    "message",
    [
        'Accessed Org "TM-LAB"',
        "Packet Capture started",
        "Packet Capture stopped",
        "Logged in",
        "Invoked Webshell",
    ],
)
def test_operational_audit_is_not_a_configuration_change(message: str) -> None:
    assert not is_configuration_change({"topic": "audits", "message": message, "site_id": None})


def test_verb_inside_an_object_name_is_not_a_configuration_change() -> None:
    # The org is named "Update Test". Matching the quoted name would let every
    # access of it through as a configuration change.
    assert not is_configuration_change({"topic": "audits", "message": 'Accessed Org "Update Test"', "site_id": None})


def test_audit_without_a_message_is_not_a_configuration_change() -> None:
    assert not is_configuration_change({"topic": "audits", "site_id": None})
