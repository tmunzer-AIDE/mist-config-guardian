"""The janitor is scheduled, and its timeout outlasts any single Mist call."""

import logging
from datetime import UTC, datetime, timedelta

import pytest
from beanie import PydanticObjectId
from beanie.odm.fields import ExpressionField
from pydantic import ValidationError

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.integrations.mist_mutation import MAX_ATTEMPTS, RETRY_AFTER_CAP_SECONDS
from mist_config_guardian_backend.models.restore import (
    RestoreAction,
    RestoreActionStatus,
    RestoreActionType,
    RestoreMode,
    RestoreOperation,
    RestoreStatus,
)
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.restore_lease import MemoryRestoreLeaseStore
from mist_config_guardian_backend.services.restore_planner import RestoreOperationState
from mist_config_guardian_backend.services.restore_recovery import INTERRUPTED_REASON, RestoreRecoveryService
from mist_config_guardian_backend.tasks import restores as restore_tasks
from mist_config_guardian_backend.worker import celery_app

_REQUEST_TIMEOUT_SECONDS = 30

ORGANIZATION_ID = PydanticObjectId()
OPERATION_ID = PydanticObjectId()
OBSERVED_AT = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def test_interrupted_restores_are_recovered_every_minute() -> None:
    assert celery_app.conf.beat_schedule["recover-interrupted-restores"] == {
        "task": "restores.recover_interrupted",
        "schedule": 60.0,
    }
    assert restore_tasks.recover_interrupted_restores.name == "restores.recover_interrupted"


def test_the_heartbeat_timeout_outlasts_the_slowest_mist_call() -> None:
    slowest = MAX_ATTEMPTS * _REQUEST_TIMEOUT_SECONDS + (MAX_ATTEMPTS - 1) * RETRY_AFTER_CAP_SECONDS

    assert Settings(environment="test").restore_worker_heartbeat_timeout_minutes * 60 > slowest


@pytest.mark.parametrize("minutes", [-1, 0, 1, 4])
def test_a_heartbeat_timeout_near_the_heartbeat_interval_is_refused(minutes: int) -> None:
    """A healthy worker beats once a minute, so a timeout that close would let the janitor close it."""
    with pytest.raises(ValidationError, match="RESTORE_WORKER_HEARTBEAT_TIMEOUT_MINUTES must be at least 5"):
        Settings(environment="test", restore_worker_heartbeat_timeout_minutes=minutes)


def test_the_shortest_allowed_heartbeat_timeout_is_accepted() -> None:
    settings = Settings(environment="test", restore_worker_heartbeat_timeout_minutes=5)

    assert settings.restore_worker_heartbeat_timeout_minutes == 5


# ------------------------------------------------------------ conditional close


def _settings() -> Settings:
    return Settings(environment="test", credential_encryption_key="test-key")


_DRIVER_MESSAGE = "configuration content in a driver message"
_RECOVERY_LOGGER = "mist_config_guardian_backend.services.restore_recovery"


class _Notifications:
    def __init__(self, *, failures: int = 0) -> None:
        self.failed: list[str] = []
        self.restore_ids: list[str] = []
        self.failures = failures

    async def notify_restore_failed(self, *, organization_id, restore_id, reason, user_id=None):  # noqa: ARG002
        if self.failures:
            self.failures -= 1
            raise RuntimeError(_DRIVER_MESSAGE)
        self.failed.append(reason)
        self.restore_ids.append(restore_id)


class _Authorization:
    """Records the logout request instead of reaching Mist."""

    def __init__(self, *, error: Exception | None = None) -> None:
        self.logged_out: list[dict[str, object]] = []
        self.error = error

    async def logout_unused_credential(self, operation: dict[str, object]) -> None:
        self.logged_out.append(operation)
        if self.error is not None:
            raise self.error


class _States:
    """Plan state for the runs under test: none compensates anything unless told to."""

    def __init__(self, *, compensates: PydanticObjectId | None = None, error: Exception | None = None) -> None:
        self.compensates = compensates
        self.error = error

    async def load(self, organization_id, operation_id):
        if self.error is not None:
            raise self.error
        if self.compensates is None:
            return None
        return RestoreOperationState(
            organization_id=organization_id,
            operation_id=operation_id,
            plan_hash="plan-hash",
            compensates_operation_id=self.compensates,
        )


def _service(
    *,
    notifications: "_Notifications | None" = None,
    authorization: "_Authorization | None" = None,
    leases: object | None = None,
    store: _States | None = None,
) -> RestoreRecoveryService:
    """A janitor whose every collaborator is a fake, so no test reaches MongoDB or Mist."""
    return RestoreRecoveryService(
        _settings(),
        CredentialVault(_settings()),
        notifications=notifications or _Notifications(),
        authorization=authorization or _Authorization(),
        leases=leases or MemoryRestoreLeaseStore(),
        store=store or _States(),
    )


class _Updated:
    def __init__(self, modified_count: int) -> None:
        self.modified_count = modified_count


class _ConditionalWrites:
    """Records each compare-and-set filter and payload, answering with a chosen match count."""

    def __init__(self) -> None:
        self.calls: list[tuple[list[dict[str, object]], dict[str, object]]] = []
        self.modified = 1
        self.errors: list[Exception | None] = []


@pytest.fixture
def conditional_writes(monkeypatch: pytest.MonkeyPatch) -> _ConditionalWrites:
    writes = _ConditionalWrites()

    class _Query:
        def __init__(self, filters: tuple) -> None:
            self.filters = filters

        async def update(self, change, *_args, **_kwargs) -> _Updated:
            writes.calls.append(([criterion.query for criterion in self.filters], change))
            if writes.errors and (error := writes.errors.pop(0)) is not None:
                raise error
            return _Updated(writes.modified)

    for name in ("id", "status", "updated_at"):
        monkeypatch.setattr(RestoreOperation, name, ExpressionField(name), raising=False)
    monkeypatch.setattr(RestoreOperation, "find_one", lambda *filters, **_kwargs: _Query(filters))
    return writes


def _action(order: int, status: RestoreActionStatus) -> RestoreAction:
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
    )


def _running(actions: list[RestoreAction], *, identifier: PydanticObjectId = OPERATION_ID) -> RestoreOperation:
    return RestoreOperation.model_construct(
        id=identifier,
        organization_id=ORGANIZATION_ID,
        requested_by=PydanticObjectId(),
        mode=RestoreMode.NON_DESTRUCTIVE,
        include_dependencies=True,
        target_at=datetime(2026, 1, 1, tzinfo=UTC),
        status=RestoreStatus.RUNNING,
        actions=actions,
        warnings=[],
        preflight_errors=[],
        encrypted_delegated_credential=CredentialVault(_settings()).encrypt_for_context(
            "api-token", context=f"restore:{OPERATION_ID}"
        ),
        delegated_credential_expires_at=OBSERVED_AT + timedelta(minutes=15),
        started_at=OBSERVED_AT,
        completed_at=None,
        failure_action_order=None,
        created_at=OBSERVED_AT,
        updated_at=OBSERVED_AT,
    )


async def test_the_janitor_closes_only_the_state_it_read_and_clears_the_credential(
    conditional_writes: _ConditionalWrites,
    caplog: pytest.LogCaptureFixture,
) -> None:
    operation = _running([_action(0, RestoreActionStatus.COMPLETED), _action(1, RestoreActionStatus.EXECUTING)])
    encrypted = operation.encrypted_delegated_credential
    assert encrypted is not None
    notifications = _Notifications()
    authorization = _Authorization()
    service = _service(notifications=notifications, authorization=authorization)
    now = OBSERVED_AT + timedelta(minutes=20)

    with caplog.at_level(logging.WARNING, logger="mist_config_guardian_backend.services.restore_recovery"):
        assert await service._interrupt(operation, now) is True  # noqa: SLF001

    [(filters, change)] = conditional_writes.calls
    assert filters == [{"id": OPERATION_ID}, {"status": RestoreStatus.RUNNING}, {"updated_at": OBSERVED_AT}]
    changes = change["$set"]
    assert changes["encrypted_delegated_credential"] is None
    assert changes["delegated_credential_expires_at"] is None
    assert changes["status"] is RestoreStatus.COMPENSATION_AVAILABLE
    assert changes["failure_action_order"] == 1
    assert changes["completed_at"] == now
    assert changes["updated_at"] == now
    assert changes["actions"][1]["status"] is RestoreActionStatus.FAILED
    assert changes["actions"][1]["outcome_unknown"] is True
    assert change["$push"] == {"preflight_errors": INTERRUPTED_REASON}
    assert authorization.logged_out == [
        {"_id": OPERATION_ID, "organization_id": ORGANIZATION_ID, "encrypted_delegated_credential": encrypted}
    ]
    assert notifications.failed == [INTERRUPTED_REASON]
    assert "restore_interrupted" in caplog.text
    assert encrypted not in caplog.text
    assert "api-token" not in caplog.text


async def test_the_janitor_leaves_a_run_whose_worker_wrote_first(conditional_writes: _ConditionalWrites) -> None:
    conditional_writes.modified = 0
    notifications = _Notifications()
    authorization = _Authorization()
    service = _service(notifications=notifications, authorization=authorization)

    assert await service._interrupt(_running([_action(0, RestoreActionStatus.EXECUTING)]), OBSERVED_AT) is False  # noqa: SLF001

    assert len(conditional_writes.calls) == 1
    assert authorization.logged_out == []
    assert notifications.failed == []


def _found(monkeypatch: pytest.MonkeyPatch, operations: list[RestoreOperation]) -> None:
    class _Found:
        async def to_list(self) -> list[RestoreOperation]:
            return operations

    monkeypatch.setattr(RestoreOperation, "find", lambda *_args, **_kwargs: _Found())


def _two_stale(monkeypatch: pytest.MonkeyPatch) -> tuple[RestoreOperation, RestoreOperation]:
    first = _running([_action(0, RestoreActionStatus.EXECUTING)], identifier=PydanticObjectId())
    second = _running([_action(0, RestoreActionStatus.EXECUTING)], identifier=PydanticObjectId())
    _found(monkeypatch, [first, second])
    return first, second


@pytest.mark.usefixtures("conditional_writes")
async def test_a_lost_notification_neither_stops_recovery_nor_reaches_the_logs(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    first, second = _two_stale(monkeypatch)
    notifications = _Notifications(failures=1)
    authorization = _Authorization()
    service = _service(notifications=notifications, authorization=authorization)

    with caplog.at_level(logging.WARNING, logger=_RECOVERY_LOGGER):
        assert await service.recover_interrupted(now=OBSERVED_AT + timedelta(minutes=20)) == 2

    assert [entry["_id"] for entry in authorization.logged_out] == [first.id, second.id]
    assert notifications.restore_ids == [str(second.id)]
    assert f"restore_interrupt_notification_lost operation={first.id} error_type=RuntimeError" in caplog.text
    assert _DRIVER_MESSAGE not in caplog.text


@pytest.mark.usefixtures("conditional_writes")
async def test_a_failed_logout_still_notifies_without_logging_its_message(caplog: pytest.LogCaptureFixture) -> None:
    notifications = _Notifications()
    service = _service(notifications=notifications, authorization=_Authorization(error=RuntimeError(_DRIVER_MESSAGE)))

    with caplog.at_level(logging.WARNING, logger=_RECOVERY_LOGGER):
        closed = await service._interrupt(_running([_action(0, RestoreActionStatus.EXECUTING)]), OBSERVED_AT)  # noqa: SLF001

    assert closed is True
    assert notifications.failed == [INTERRUPTED_REASON]
    assert f"restore_interrupt_logout_failed operation={OPERATION_ID} error_type=RuntimeError" in caplog.text
    assert _DRIVER_MESSAGE not in caplog.text


class _Leases:
    """Records lease releases, optionally failing them."""

    def __init__(self, *, error: Exception | None = None) -> None:
        self.released: list[tuple[PydanticObjectId, PydanticObjectId]] = []
        self.error = error

    async def release(self, organization_id, operation_id) -> None:
        self.released.append((organization_id, operation_id))
        if self.error is not None:
            raise self.error


@pytest.mark.parametrize("modified", [1, 0])
async def test_the_janitor_releases_the_lease_only_of_a_run_it_closed(
    conditional_writes: _ConditionalWrites,
    modified: int,
) -> None:
    conditional_writes.modified = modified
    leases = _Leases()
    service = _service(leases=leases)

    closed = await service._interrupt(_running([_action(0, RestoreActionStatus.EXECUTING)]), OBSERVED_AT)  # noqa: SLF001

    assert closed is bool(modified)
    assert leases.released == ([(ORGANIZATION_ID, OPERATION_ID)] if modified else [])


@pytest.mark.usefixtures("conditional_writes")
async def test_a_failed_lease_release_still_logs_out_and_notifies_without_logging_its_message(
    caplog: pytest.LogCaptureFixture,
) -> None:
    notifications = _Notifications()
    authorization = _Authorization()
    service = _service(
        notifications=notifications, authorization=authorization, leases=_Leases(error=RuntimeError(_DRIVER_MESSAGE))
    )

    with caplog.at_level(logging.WARNING, logger=_RECOVERY_LOGGER):
        closed = await service._interrupt(_running([_action(0, RestoreActionStatus.EXECUTING)]), OBSERVED_AT)  # noqa: SLF001

    assert closed is True
    assert len(authorization.logged_out) == 1
    assert notifications.failed == [INTERRUPTED_REASON]
    assert f"restore_interrupt_lease_release_failed operation={OPERATION_ID} error_type=RuntimeError" in caplog.text
    assert _DRIVER_MESSAGE not in caplog.text


async def test_one_close_that_fails_does_not_stop_the_others(
    monkeypatch: pytest.MonkeyPatch,
    conditional_writes: _ConditionalWrites,
    caplog: pytest.LogCaptureFixture,
) -> None:
    first, second = _two_stale(monkeypatch)
    conditional_writes.errors = [RuntimeError(_DRIVER_MESSAGE)]
    notifications = _Notifications()
    service = _service(notifications=notifications)

    with caplog.at_level(logging.WARNING, logger=_RECOVERY_LOGGER):
        assert await service.recover_interrupted(now=OBSERVED_AT + timedelta(minutes=20)) == 1

    assert len(conditional_writes.calls) == 2
    assert notifications.restore_ids == [str(second.id)]
    assert f"restore_interrupt_failed operation={first.id} error_type=RuntimeError" in caplog.text
    assert _DRIVER_MESSAGE not in caplog.text


async def test_an_interrupted_compensation_fails_instead_of_offering_its_own_compensation(
    conditional_writes: _ConditionalWrites,
) -> None:
    service = _service(store=_States(compensates=PydanticObjectId()))
    operation = _running([_action(0, RestoreActionStatus.COMPLETED), _action(1, RestoreActionStatus.EXECUTING)])

    assert await service._interrupt(operation, OBSERVED_AT) is True  # noqa: SLF001

    [(_, change)] = conditional_writes.calls
    assert change["$set"]["status"] is RestoreStatus.FAILED
    assert change["$set"]["actions"][1]["outcome_unknown"] is True


async def test_a_run_whose_plan_state_cannot_be_read_is_still_closed_as_compensable(
    conditional_writes: _ConditionalWrites,
    caplog: pytest.LogCaptureFixture,
) -> None:
    notifications = _Notifications()
    service = _service(notifications=notifications, store=_States(error=RuntimeError(_DRIVER_MESSAGE)))
    operation = _running([_action(0, RestoreActionStatus.COMPLETED), _action(1, RestoreActionStatus.EXECUTING)])

    with caplog.at_level(logging.WARNING, logger=_RECOVERY_LOGGER):
        assert await service._interrupt(operation, OBSERVED_AT) is True  # noqa: SLF001

    [(_, change)] = conditional_writes.calls
    assert change["$set"]["status"] is RestoreStatus.COMPENSATION_AVAILABLE
    assert notifications.failed == [INTERRUPTED_REASON]
    assert f"restore_interrupt_state_unavailable operation={OPERATION_ID} error_type=RuntimeError" in caplog.text
    assert _DRIVER_MESSAGE not in caplog.text
