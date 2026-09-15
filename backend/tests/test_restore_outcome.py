"""Which terminal status a stopped restore gets, and what happens to writes in flight."""

import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.models.restore import (
    RestoreAction,
    RestoreActionStatus,
    RestoreActionType,
    RestoreStatus,
)
from mist_config_guardian_backend.services.restore_outcome import (
    mark_unconfirmed,
    possibly_applied,
    terminal_failure_status,
)


def _action(order: int, status: RestoreActionStatus, *, outcome_unknown: bool = False) -> RestoreAction:
    return RestoreAction(
        logical_object_id=PydanticObjectId(),
        source_version_id=PydanticObjectId(),
        order=order,
        action=RestoreActionType.UPDATE,
        scope="site",
        object_type="wlans",
        object_name=f"wlan-{order}",
        current_mist_id=f"mist-{order}",
        site_mist_id="site-a",
        protected_configuration={},
        status=status,
        outcome_unknown=outcome_unknown,
    )


def test_nothing_applied_is_a_plain_failure() -> None:
    actions = [_action(0, RestoreActionStatus.FAILED), _action(1, RestoreActionStatus.PENDING)]

    assert terminal_failure_status(actions) is RestoreStatus.FAILED


def test_an_applied_write_makes_the_restore_compensable() -> None:
    actions = [_action(0, RestoreActionStatus.COMPLETED), _action(1, RestoreActionStatus.FAILED)]

    assert terminal_failure_status(actions) is RestoreStatus.COMPENSATION_AVAILABLE


def test_an_unconfirmed_write_makes_the_restore_compensable() -> None:
    actions = [_action(0, RestoreActionStatus.FAILED, outcome_unknown=True)]

    assert terminal_failure_status(actions) is RestoreStatus.COMPENSATION_AVAILABLE


@pytest.mark.parametrize("status", [RestoreActionStatus.PENDING, RestoreActionStatus.SKIPPED])
def test_an_inherited_unconfirmed_flag_on_an_unattempted_action_is_a_plain_failure(
    status: RestoreActionStatus,
) -> None:
    actions = [_action(0, RestoreActionStatus.FAILED), _action(1, status, outcome_unknown=True)]

    assert terminal_failure_status(actions) is RestoreStatus.FAILED


def test_a_failed_compensation_is_a_plain_failure_even_after_applying_something() -> None:
    actions = [_action(0, RestoreActionStatus.COMPLETED), _action(1, RestoreActionStatus.FAILED)]

    assert terminal_failure_status(actions, compensating=True) is RestoreStatus.FAILED


@pytest.mark.parametrize(
    ("status", "outcome_unknown", "applied"),
    [
        (RestoreActionStatus.COMPLETED, False, True),
        (RestoreActionStatus.COMPLETED, True, True),
        (RestoreActionStatus.FAILED, True, True),
        (RestoreActionStatus.FAILED, False, False),
        (RestoreActionStatus.SKIPPED, True, False),
        (RestoreActionStatus.SKIPPED, False, False),
        (RestoreActionStatus.PENDING, True, False),
        (RestoreActionStatus.EXECUTING, True, False),
    ],
)
def test_only_a_completed_or_unconfirmed_failed_write_may_have_reached_mist(
    status: RestoreActionStatus,
    outcome_unknown: bool,  # noqa: FBT001 - a parametrized case, not a call-site flag
    applied: bool,  # noqa: FBT001 - a parametrized case, not a call-site flag
) -> None:
    assert possibly_applied(_action(0, status, outcome_unknown=outcome_unknown)) is applied


def test_writes_in_flight_are_marked_unconfirmed() -> None:
    actions = [
        _action(0, RestoreActionStatus.COMPLETED),
        _action(1, RestoreActionStatus.EXECUTING),
        _action(2, RestoreActionStatus.PENDING),
    ]

    first = mark_unconfirmed(actions, "Restore worker interrupted")

    assert first == 1
    assert actions[1].status is RestoreActionStatus.FAILED
    assert actions[1].outcome_unknown is True
    assert actions[1].error == "Restore worker interrupted"
    assert actions[0].outcome_unknown is False
    assert actions[2].status is RestoreActionStatus.PENDING


def test_nothing_in_flight_marks_nothing() -> None:
    assert mark_unconfirmed([_action(0, RestoreActionStatus.PENDING)], "reason") is None
