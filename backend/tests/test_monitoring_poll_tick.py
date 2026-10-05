"""The monitoring worker tick: what a poll announces, and what one failure may not cost."""

import pytest

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.monitoring import ImpactSeverity
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services import change_groups, notifications
from mist_config_guardian_backend.services.application_configuration import ApplicationConfigurationService
from mist_config_guardian_backend.services.guardian import GuardianService
from mist_config_guardian_backend.services.monitoring import MonitoringPollService
from mist_config_guardian_backend.tasks import monitoring as task
from test_change_groups import _critical_fixture
from test_notifications import _MemoryNotificationStore


async def test_a_critical_verdict_reached_by_a_poll_raises_the_impact_alert_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Most verdicts are reached by a poll, not a device event, so the poll has to announce them too."""
    groups = _critical_fixture()
    feed = _MemoryNotificationStore()
    monkeypatch.setattr(change_groups, "BeanieChangeGroupStore", lambda: groups)
    monkeypatch.setattr(notifications, "BeanieNotificationStore", lambda: feed)
    vault = CredentialVault(Settings(environment="test", database_enabled=False))
    # Built exactly as the worker builds it.
    service = MonitoringPollService(vault, ApplicationConfigurationService(vault))

    # This poll, and the next one that finds the group just as critical.
    for _ in range(2):
        await service._refresh_change_groups(groups.sessions[0])  # noqa: SLF001

    group = groups.groups[0]
    assert group.impact_severity is ImpactSeverity.CRITICAL
    assert [(item.title, item.dedupe_key) for item in feed.items] == [
        ("Harmful change detected", f"impact-detected:{group.id}")
    ]


class _MonitoringUnavailableError(RuntimeError):
    pass


class _GuardianUnavailableError(RuntimeError):
    pass


async def _tick(
    monkeypatch: pytest.MonkeyPatch,
    started: list[str],
    *,
    monitoring_fails: bool = False,
    guardian_fails: bool = False,
) -> int:
    """Run one worker tick with Guardian on, recording which polls it started."""

    class FakeDatabase:
        def __init__(self, _settings: object) -> None:
            pass

        async def connect(self) -> None: ...

        async def close(self) -> None: ...

    async def poll_active(_self: object) -> int:
        started.append("monitoring")
        if monitoring_fails:
            raise _MonitoringUnavailableError
        return 2

    async def poll_due(_self: object) -> int:
        started.append("guardian")
        if guardian_fails:
            raise _GuardianUnavailableError
        return 0

    monkeypatch.setattr(task, "get_settings", lambda: Settings(guardian_enabled=True))
    monkeypatch.setattr(task, "DatabaseManager", FakeDatabase)
    monkeypatch.setattr(MonitoringPollService, "poll_active", poll_active)
    monkeypatch.setattr(GuardianService, "poll_due", poll_due)
    return await task._poll_active_monitoring()  # noqa: SLF001


async def test_a_tick_reports_the_sessions_it_polled(monkeypatch: pytest.MonkeyPatch) -> None:
    started: list[str] = []

    assert await _tick(monkeypatch, started) == 2
    assert started == ["monitoring", "guardian"]


async def test_a_failing_monitoring_poll_does_not_skip_the_guardian_tick(monkeypatch: pytest.MonkeyPatch) -> None:
    started: list[str] = []

    # The tick still fails, so the error is reported, but Guardian ran regardless.
    with pytest.raises(_MonitoringUnavailableError):
        await _tick(monkeypatch, started, monitoring_fails=True)
    assert started == ["monitoring", "guardian"]


async def test_a_failing_guardian_tick_surfaces_after_monitoring_ran(monkeypatch: pytest.MonkeyPatch) -> None:
    started: list[str] = []

    with pytest.raises(_GuardianUnavailableError):
        await _tick(monkeypatch, started, guardian_fails=True)
    assert started == ["monitoring", "guardian"]


async def test_when_both_fail_both_errors_surface(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(_GuardianUnavailableError) as raised:
        await _tick(monkeypatch, [], monitoring_fails=True, guardian_fails=True)

    assert isinstance(raised.value.__context__, _MonitoringUnavailableError)
