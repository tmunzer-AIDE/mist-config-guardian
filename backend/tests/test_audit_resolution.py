"""Mist audit target resolution tests."""

from mist_config_guardian_backend.webhooks.audits import resolve_audit_target


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
