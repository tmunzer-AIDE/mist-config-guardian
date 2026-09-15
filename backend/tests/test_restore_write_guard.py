"""The live check taken immediately before each Mist write."""

from unittest.mock import AsyncMock

import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.organization import MistCloudRegion, Organization, OrganizationStatus
from mist_config_guardian_backend.models.restore import RestoreAction, RestoreActionType
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.restore_compensation import RestoreDriftError
from mist_config_guardian_backend.services.restore_planner import SafetySnapshotEntry
from mist_config_guardian_backend.services.restore_write_guard import check_before_write
from mist_config_guardian_backend.snapshots.canonical import configuration_hash
from mist_config_guardian_backend.snapshots.registry import get_definition

WLANS = get_definition("site", "wlans")
SETTINGS = get_definition("site", "settings")
assert WLANS is not None
assert SETTINGS is not None


class _Client:
    def __init__(self, live: dict[str, dict[str, object]]) -> None:
        self.live = live
        self.reads: list[tuple[str, str | None]] = []

    async def get_current(self, definition, object_id, *, org_id, site_id):  # noqa: ARG002
        self.reads.append((object_id, site_id))
        value = self.live.get(object_id)
        return None if value is None else dict(value)


def _vault() -> CredentialVault:
    return CredentialVault(Settings(environment="test", credential_encryption_key="test-key"))


def _organization() -> Organization:
    return Organization.model_construct(
        id=PydanticObjectId(),
        mist_org_id="org-1",
        name="Lab",
        cloud_region=MistCloudRegion.GLOBAL_01,
        status=OrganizationStatus.VERIFIED,
        encrypted_service_token="v1:encrypted-value",
        service_token_last_four="alue",
    )


def _action(
    action_type: RestoreActionType,
    *,
    object_type: str = "wlans",
    current_mist_id: str = "mist-0",
    site_mist_id: str = "site-a",
) -> RestoreAction:
    return RestoreAction(
        logical_object_id=PydanticObjectId(),
        source_version_id=PydanticObjectId(),
        order=0,
        action=action_type,
        scope="site",
        object_type=object_type,
        object_name="Corp",
        current_mist_id=current_mist_id,
        site_mist_id=site_mist_id,
        protected_configuration={"name": "Corp"},
    )


def _entry(action: RestoreAction, live: dict[str, object]) -> SafetySnapshotEntry:
    return SafetySnapshotEntry(
        logical_object_id=action.logical_object_id,
        order=action.order,
        action=action.action,
        scope=action.scope,
        object_type=action.object_type,
        object_name=action.object_name,
        mist_object_id=action.current_mist_id,
        site_mist_id=action.site_mist_id,
        existed=True,
        configuration=dict(live),
        configuration_hash=configuration_hash(live, ignored_fields=WLANS.ignored_fields),
    )


async def _check(client: _Client, action: RestoreAction, **overrides):
    arguments = {
        "object_id": action.current_mist_id,
        "site_id": action.site_mist_id,
        "entry": None,
        "deferred": False,
        "compensating": False,
    } | overrides
    definition = SETTINGS if action.object_type == "settings" else WLANS
    return await check_before_write(client, _organization(), _vault(), action, definition, **arguments)


async def test_an_update_proceeds_while_live_state_still_matches_the_snapshot() -> None:
    snapshot = {"name": "Corp", "enabled": True, "modified_time": 1}
    action = _action(RestoreActionType.UPDATE)
    client = _Client({"mist-0": {**snapshot, "modified_time": 2}})

    check = await _check(client, action, entry=_entry(action, snapshot))

    assert check.recorded is False


async def test_an_update_is_refused_when_the_object_changed_after_the_snapshot() -> None:
    snapshot = {"name": "Corp", "enabled": True}
    action = _action(RestoreActionType.UPDATE)
    client = _Client({"mist-0": {"name": "Corp", "enabled": False}})

    with pytest.raises(RestoreDriftError, match="changed in Mist after the pre-restore safety snapshot"):
        await _check(client, action, entry=_entry(action, snapshot))


async def test_a_delete_of_an_object_that_is_already_gone_is_refused() -> None:
    action = _action(RestoreActionType.DELETE)

    with pytest.raises(RestoreDriftError, match="no longer exists"):
        await _check(_Client({}), action, entry=_entry(action, {"name": "Corp"}))


async def test_an_action_without_a_snapshot_entry_is_refused() -> None:
    with pytest.raises(RestoreDriftError, match="no pre-restore safety snapshot"):
        await _check(_Client({"mist-0": {"name": "Corp"}}), _action(RestoreActionType.UPDATE))


async def test_a_drift_error_names_the_object_but_never_its_configuration() -> None:
    snapshot = {"name": "Corp", "psk": "stored-secret"}
    action = _action(RestoreActionType.UPDATE)
    client = _Client({"mist-0": {"name": "Corp", "psk": "rotated-secret"}})

    with pytest.raises(RestoreDriftError) as raised:
        await _check(client, action, entry=_entry(action, snapshot))

    assert "Corp" in str(raised.value)
    assert "secret" not in str(raised.value)


async def test_settings_under_a_recreated_site_are_read_at_the_new_site_and_recorded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version",
        AsyncMock(return_value=None),
    )
    action = _action(
        RestoreActionType.UPDATE,
        object_type="settings",
        current_mist_id="site-old:settings",
        site_mist_id="site-old",
    )
    client = _Client({"site-old:settings": {"vlan": 1}})

    check = await _check(client, action, site_id="site-new", deferred=True)

    assert client.reads == [("site-old:settings", "site-new")]
    assert check.recorded is True
    assert check.entry.existed is True
    assert check.entry.site_mist_id == "site-new"


async def test_a_create_under_a_recreated_site_records_absence_without_reading(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version",
        AsyncMock(return_value=None),
    )
    client = _Client({})

    check = await _check(
        client, _action(RestoreActionType.CREATE, site_mist_id="site-old"), site_id="site-new", deferred=True
    )

    assert client.reads == []
    assert check.recorded is True
    assert check.entry.existed is False


async def test_an_unconfirmed_create_under_a_deferred_site_still_looks_for_the_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The inverse of a delete that may never have happened must find the object if it is still there."""
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version",
        AsyncMock(return_value=None),
    )
    action = _action(RestoreActionType.CREATE, site_mist_id="site-old")
    action.outcome_unknown = True
    client = _Client({"mist-0": {"name": "Corp"}})

    check = await _check(client, action, site_id="site-old", deferred=True, compensating=True)

    assert client.reads == [("mist-0", "site-old")]
    assert check.recorded is True
    assert check.entry.existed is True
    assert check.skip is True


def _reversal(action_type: RestoreActionType, *, expected: str | None, payload: dict[str, object]) -> RestoreAction:
    action = _action(action_type)
    action.compensates_action_order = 3
    action.expected_current_hash = expected
    action.protected_configuration = dict(payload)
    return action


async def test_a_reversal_refuses_to_overwrite_a_fix_made_after_the_restore() -> None:
    written = {"name": "Corp", "enabled": True}
    action = _reversal(
        RestoreActionType.UPDATE,
        expected=configuration_hash(written, ignored_fields=WLANS.ignored_fields),
        payload={"name": "Corp", "enabled": False},
    )
    client = _Client({"mist-0": {**written, "vlan": 9}})

    with pytest.raises(RestoreDriftError, match="changed after this plan was reviewed"):
        await _check(client, action, entry=_entry(action, written), compensating=True)


async def test_a_reversal_skips_an_object_already_back_in_its_earlier_state() -> None:
    earlier = {"name": "Corp", "enabled": False}
    action = _reversal(RestoreActionType.UPDATE, expected="applied-hash", payload=earlier)

    check = await _check(_Client({"mist-0": dict(earlier)}), action, entry=_entry(action, earlier), compensating=True)

    assert check.skip is True


async def test_a_reversal_skips_deleting_an_object_that_is_already_gone() -> None:
    action = _reversal(RestoreActionType.DELETE, expected="applied-hash", payload={})

    check = await _check(_Client({}), action, entry=_entry(action, {"name": "Corp"}), compensating=True)

    assert check.skip is True


async def test_a_reversal_skips_recreating_an_object_its_unconfirmed_delete_never_removed() -> None:
    action = _reversal(RestoreActionType.CREATE, expected=None, payload={"name": "Corp"})
    action.outcome_unknown = True

    check = await _check(_Client({}), action, entry=_entry(action, {"name": "Corp"}), compensating=True)

    assert check.skip is True


async def test_the_reversal_of_an_unconfirmed_update_proceeds_without_an_expected_state() -> None:
    action = _reversal(RestoreActionType.UPDATE, expected=None, payload={"name": "Corp", "enabled": False})
    action.outcome_unknown = True

    check = await _check(
        _Client({"mist-0": {"name": "Corp", "enabled": True}}),
        action,
        entry=_entry(action, {"name": "Corp", "enabled": True}),
        compensating=True,
    )

    assert check.skip is False


async def test_a_reversal_refuses_a_change_made_between_the_safety_snapshot_and_its_write() -> None:
    snapshot = {"name": "Corp", "enabled": True}
    action = _reversal(RestoreActionType.UPDATE, expected=None, payload={"name": "Corp", "enabled": False})
    action.outcome_unknown = True
    client = _Client({"mist-0": {**snapshot, "vlan": 9}})

    with pytest.raises(RestoreDriftError, match="changed in Mist after the pre-restore safety snapshot"):
        await _check(client, action, entry=_entry(action, snapshot), compensating=True)
