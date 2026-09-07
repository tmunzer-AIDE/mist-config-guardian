"""Restore dependency ordering tests."""

import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.models.restore import RestoreAction, RestoreActionType
from mist_config_guardian_backend.services.restore_planner import (
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
