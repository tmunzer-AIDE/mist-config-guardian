"""Restore dependency ordering tests."""

import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.models.restore import RestoreAction, RestoreActionType
from mist_config_guardian_backend.services.restore_planner import (
    RestorePlanner,
    RestorePlanningError,
    order_restore_actions,
)


def _action(
    logical_id: PydanticObjectId,
    action_type: RestoreActionType,
    *,
    depends_on: list[PydanticObjectId] | None = None,
) -> RestoreAction:
    return RestoreAction(
        logical_object_id=logical_id,
        source_version_id=PydanticObjectId(),
        order=0,
        action=action_type,
        scope="org",
        object_type="networks",
        object_name=str(logical_id),
        current_mist_id=str(logical_id),
        protected_configuration={},
        depends_on=depends_on or [],
    )


def test_restore_actions_follow_dependencies() -> None:
    network_id = PydanticObjectId()
    wlan_id = PydanticObjectId()
    actions = [
        _action(wlan_id, RestoreActionType.CREATE, depends_on=[network_id]),
        _action(network_id, RestoreActionType.CREATE),
    ]

    ordered = order_restore_actions(actions)

    assert [action.logical_object_id for action in ordered] == [network_id, wlan_id]
    assert [action.order for action in ordered] == [0, 1]


def test_restore_dependency_cycle_fails_closed() -> None:
    first_id = PydanticObjectId()
    second_id = PydanticObjectId()
    actions = [
        _action(first_id, RestoreActionType.CREATE, depends_on=[second_id]),
        _action(second_id, RestoreActionType.CREATE, depends_on=[first_id]),
    ]

    with pytest.raises(RestorePlanningError, match="contains a cycle"):
        order_restore_actions(actions)


def _site_wlan(action_type: RestoreActionType, ssid: str, *, site: str = "site-1") -> RestoreAction:
    return RestoreAction(
        logical_object_id=PydanticObjectId(),
        source_version_id=PydanticObjectId(),
        order=0,
        action=action_type,
        scope="site",
        object_type="wlans",
        object_name=ssid,
        current_mist_id=str(PydanticObjectId()),
        site_mist_id=site,
        protected_configuration={"ssid": ssid},
    )


def test_an_object_is_deleted_before_another_is_created_under_its_name() -> None:
    replacement = _site_wlan(RestoreActionType.DELETE, "Corp")
    original = _site_wlan(RestoreActionType.CREATE, "Corp")
    unrelated = _site_wlan(RestoreActionType.DELETE, "Guest")
    elsewhere = _site_wlan(RestoreActionType.DELETE, "Corp", site="site-2")
    actions = [replacement, original, unrelated, elsewhere]

    RestorePlanner._add_name_reuse_dependencies(actions)  # noqa: SLF001
    ordered = order_restore_actions(actions)

    # Only the object holding the name it needs; another name or another site is not in its way.
    assert original.depends_on == [replacement.logical_object_id]
    assert ordered.index(replacement) < ordered.index(original)
