"""Terminal outcomes shared by the executor and the interrupted-restore janitor."""

from collections.abc import Sequence

from mist_config_guardian_backend.models.restore import RestoreAction, RestoreActionStatus, RestoreStatus


def terminal_failure_status(actions: Sequence[RestoreAction]) -> RestoreStatus:
    """Decide the status of a restore that stopped before finishing.

    Anything that reached Mist, or may have, has to stay reversible, so an
    applied or unconfirmed write keeps compensation available.
    """
    if any(action.status is RestoreActionStatus.COMPLETED or action.outcome_unknown for action in actions):
        return RestoreStatus.COMPENSATION_AVAILABLE
    return RestoreStatus.FAILED


def mark_unconfirmed(actions: list[RestoreAction], reason: str) -> int | None:
    """Close every write still in flight as possibly applied; return the first order marked."""
    first: int | None = None
    for action in actions:
        if action.status is not RestoreActionStatus.EXECUTING:
            continue
        action.status = RestoreActionStatus.FAILED
        action.outcome_unknown = True
        action.error = reason
        if first is None:
            first = action.order
    return first
