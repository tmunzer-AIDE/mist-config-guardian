"""Terminal outcomes shared by the executor and the interrupted-restore janitor."""

from collections.abc import Sequence

from mist_config_guardian_backend.models.restore import RestoreAction, RestoreActionStatus, RestoreStatus


def unconfirmed_write(action: RestoreAction) -> bool:
    """Whether Mist may have applied this action's write without confirming it.

    Only a FAILED action can be unconfirmed: a compensation action copies the
    flag of the write it reverses, and until it runs and fails it has changed
    nothing.
    """
    return action.status is RestoreActionStatus.FAILED and action.outcome_unknown


def possibly_applied(action: RestoreAction) -> bool:
    """Whether this action's write reached Mist, or may have.

    The one rule for what a stopped restore leaves to reverse: the terminal
    status and the compensation plan both read it here, so they can never
    disagree. A skipped action wrote nothing, whatever flag it carries.
    """
    return action.status is RestoreActionStatus.COMPLETED or unconfirmed_write(action)


def terminal_failure_status(actions: Sequence[RestoreAction], *, compensating: bool = False) -> RestoreStatus:
    """Decide the status of a restore that stopped before finishing.

    Anything that reached Mist, or may have, has to stay reversible, so an
    applied or unconfirmed write keeps compensation available. A compensation
    that stops is simply failed: the restore it reverses stays compensable and
    is compensated again from there, rather than the compensation itself.
    """
    if compensating:
        return RestoreStatus.FAILED
    if any(possibly_applied(action) for action in actions):
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
