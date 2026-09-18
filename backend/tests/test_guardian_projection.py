"""The Guardian projection the changes, detail and overview pages share, and what it must never change.

One read per page builds every row's ``guardian`` field. It is a presentation projection: the production
severity, its badge and its notifications are the monitoring subsystem's and are not touched here. A past view
and a counts-only read project nothing, and with Guardian off nothing is read at all.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.models.guardian import GuardianResult
from mist_config_guardian_backend.models.monitoring import ImpactSeverity
from mist_config_guardian_backend.schemas.guardian import GuardianSummary
from mist_config_guardian_backend.services import change_groups
from mist_config_guardian_backend.services.change_groups import (
    ChangeGroupFilters,
    ChangeGroupProjector,
    ChangeGroupService,
)
from mist_config_guardian_backend.services.overview import OverviewService
from test_change_groups import NOW, ORGANIZATION_ID, _group, _MemoryChangeGroupStore, _organization
from test_overview import _MemoryOverviewReader

pytestmark = pytest.mark.asyncio


def guardian_summary(peak="warning", **overrides):
    """One published Guardian root, as the root projection hands it to a page."""
    result = GuardianResult(
        run_id=PydanticObjectId(),
        run_kind="final",
        evaluated_at=NOW,
        peak=peak,
        current="none",
        recovery="recovered",
        confidence="low",
        coverage="complete",
        sources=("monitoring",),
        summary="Peak impact warning (coverage complete); current none.",
    )
    return GuardianSummary(status="done", status_reason="Final run published", result=result, **overrides)


def service(monkeypatch, *, guardian_enabled=True):
    monkeypatch.setattr(change_groups, "get_settings", lambda: SimpleNamespace(guardian_enabled=guardian_enabled))
    store = _MemoryChangeGroupStore()
    store.groups = [_group(impact_severity=ImpactSeverity.CRITICAL)]
    guardian = SimpleNamespace(summaries=AsyncMock(return_value={"audit-1": guardian_summary()}))
    return ChangeGroupService(store, guardian), store, guardian


async def test_changes_list_detail_and_overview_share_one_projection(monkeypatch):
    changes, store, guardian = service(monkeypatch)
    [row], total = await changes.list_groups(ORGANIZATION_ID, ChangeGroupFilters(), viewer_email="")
    detail = await changes.get_group(ORGANIZATION_ID, store.groups[0].id, viewer_email="")
    overview_reader = _MemoryOverviewReader()
    overview_reader.groups = store.groups
    overview = await OverviewService(overview_reader, changes).collect(
        _organization(), range_key="24h", viewer_email=""
    )
    assert total == 1
    assert row.guardian == detail.guardian == overview.change_groups[0].guardian
    assert row.guardian.status == "done"
    assert row.guardian.result.peak == "warning"
    # Production severity, its source and the overview aggregate stay the monitoring subsystem's.
    assert row.impact_severity == detail.impact_severity == ImpactSeverity.CRITICAL
    assert row.impact_source == overview.counts.impact_source == "legacy"
    assert overview.counts.impacting == 2
    assert overview.guardian_feed_counts.total == overview.guardian_feed_counts.warning == 1
    assert guardian.summaries.await_count == 3
    for call in guardian.summaries.await_args_list:
        assert call.args == (ORGANIZATION_ID, ["audit-1"])


async def test_historical_and_counts_only_reads_project_nothing(monkeypatch):
    changes, store, guardian = service(monkeypatch)
    [row] = await changes.summarize(ORGANIZATION_ID, store.groups, viewer_email="", historical=True)
    detail = await changes.get_group(ORGANIZATION_ID, store.groups[0].id, viewer_email="", as_of=NOW)
    overview_reader = _MemoryOverviewReader()
    overview_reader.groups = store.groups
    overview = OverviewService(overview_reader, changes)
    past = await overview.collect(_organization(), range_key="24h", viewer_email="", as_of=NOW)
    badges = await overview.collect(_organization(), range_key="24h", viewer_email="", counts_only=True)
    assert row.guardian is detail.guardian is past.guardian_feed_counts is badges.guardian_feed_counts is None
    assert row.impact_source is detail.impact_source is past.counts.impact_source is None
    guardian.summaries.assert_not_awaited()


async def test_nothing_is_read_while_guardian_is_disabled(monkeypatch):
    changes, store, guardian = service(monkeypatch, guardian_enabled=False)
    [row] = await changes.summarize(ORGANIZATION_ID, store.groups, viewer_email="")
    detail = await changes.get_group(ORGANIZATION_ID, store.groups[0].id, viewer_email="")
    assert row.guardian is None
    assert detail.guardian is None
    assert row.impact_severity == ImpactSeverity.CRITICAL
    guardian.summaries.assert_not_awaited()


async def test_a_projection_that_failed_is_reported_unavailable(monkeypatch):
    changes, store, guardian = service(monkeypatch)
    guardian.summaries.return_value = {"audit-1": GuardianSummary.unavailable()}
    [row] = await changes.summarize(ORGANIZATION_ID, store.groups, viewer_email="")
    overview_reader = _MemoryOverviewReader()
    overview_reader.groups = store.groups
    overview = await OverviewService(overview_reader, changes).collect(
        _organization(), range_key="24h", viewer_email=""
    )
    assert row.guardian.availability == "unavailable"
    assert row.guardian.result is None
    assert overview.guardian_feed_counts.unavailable == 1
    assert overview.guardian_feed_counts.none == 0


async def test_guardian_disagreement_does_not_change_notification_decisions(monkeypatch):
    changes, store, guardian = service(monkeypatch)
    notifications = SimpleNamespace(notify_impact_detected=AsyncMock())
    projector = ChangeGroupProjector(store, notifications=notifications)
    await changes.summarize(ORGANIZATION_ID, store.groups, viewer_email="")
    await projector._announce(store.groups[0])  # noqa: SLF001
    notifications.notify_impact_detected.assert_awaited_once()  # The monitoring verdict alone decides this.
    notifications.notify_impact_detected.reset_mock()
    store.groups[0].impact_severity = ImpactSeverity.NONE
    guardian.summaries.return_value = {"audit-1": guardian_summary(peak="critical")}
    await changes.summarize(ORGANIZATION_ID, store.groups, viewer_email="")
    await projector._announce(store.groups[0])  # noqa: SLF001
    notifications.notify_impact_detected.assert_not_awaited()
