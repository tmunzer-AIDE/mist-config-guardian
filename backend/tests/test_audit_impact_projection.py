"""Shared audit projections preserve revision identity and isolate production consumers."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from beanie import PydanticObjectId
from pymongo.errors import ConnectionFailure

from mist_config_guardian_backend.models.investigation import ImpactInvestigation, InvestigationRevision
from mist_config_guardian_backend.models.monitoring import ImpactSeverity
from mist_config_guardian_backend.schemas.audit_impact import AuditImpactSummary
from mist_config_guardian_backend.services import change_groups
from mist_config_guardian_backend.services.audit_impact_reads import PublishedAuditImpactReader
from mist_config_guardian_backend.services.change_groups import (
    ChangeGroupFilters,
    ChangeGroupProjector,
    ChangeGroupService,
)
from mist_config_guardian_backend.services.overview import OverviewService
from test_change_groups import NOW, ORGANIZATION_ID, _group, _MemoryChangeGroupStore, _organization
from test_overview import _MemoryOverviewReader


def documents(*, impact="none", coverage="complete"):
    root = {
        "_id": PydanticObjectId(),
        "audit_id": "audit-1",
        "report_id": PydanticObjectId(),
        "revision": 3,
        "status": "monitoring",
    }
    artifact = {
        "_id": root["report_id"],
        "investigation_id": root["_id"],
        "revision": 3,
        "assessment": {
            "audit_id": root["audit_id"],
            "policy_version": "wlan-removal.v1",
            "evaluated_at": NOW,
            "impact": impact,
            "confidence": "medium" if coverage == "complete" else "low",
            "coverage": coverage,
            "gaps": [] if coverage == "complete" else ["Missing evidence"],
        },
        "plan": {"unmapped": [] if coverage == "complete" else ["vlan_id"]},
    }
    return root, artifact


def collections(monkeypatch, roots, artifacts):
    root_store = SimpleNamespace(find=Mock(return_value=SimpleNamespace(to_list=AsyncMock(return_value=roots))))
    artifact_store = SimpleNamespace(find=Mock(return_value=SimpleNamespace(to_list=AsyncMock(return_value=artifacts))))
    monkeypatch.setattr(ImpactInvestigation, "get_pymongo_collection", lambda *_: root_store)
    monkeypatch.setattr(InvestigationRevision, "get_pymongo_collection", lambda *_: artifact_store)
    return root_store, artifact_store


async def test_projection_batches_exact_tenant_publications_and_omits_raw_evidence(monkeypatch):
    root, artifact = documents()
    roots, artifacts = collections(monkeypatch, [root], [artifact])
    result = await PublishedAuditImpactReader().summaries(ORGANIZATION_ID, ["audit-1", "audit-2", "audit-1"])
    assert result["audit-1"].report_id == str(root["report_id"])
    assert result["audit-1"].revision == 3
    assert result["audit-2"].result == "not_recorded"
    roots.find.assert_called_once()
    assert roots.find.call_args.args[0] == {
        "organization_id": ORGANIZATION_ID,
        "audit_id": {"$in": ["audit-1", "audit-2"]},
    }
    query, projection = artifacts.find.call_args.args
    assert query == {
        "organization_id": ORGANIZATION_ID,
        "$or": [
            {
                "_id": root["report_id"],
                "investigation_id": root["_id"],
                "revision": 3,
            }
        ],
    }
    assert "evidence" not in projection
    assert "assessment.findings" not in projection
    assert set(projection.values()) == {1}  # Inclusion projection, not a raw-document read.
    artifacts.find.return_value.to_list.assert_awaited_once_with(length=500)


@pytest.mark.parametrize(
    ("impact", "coverage", "expected"),
    [
        ("none", "complete", "no_observed_disconnect"),
        ("none", "partial", "insufficient_evidence"),
        ("info", "unmapped", "insufficient_evidence"),
        ("info", "partial", "insufficient_evidence"),
        ("warning", "partial", "possible_disruption"),
    ],
)
async def test_result_preserves_coverage_separately_from_band(monkeypatch, impact, coverage, expected):
    root, artifact = documents(impact=impact, coverage=coverage)
    collections(monkeypatch, [root], [artifact])
    result = (await PublishedAuditImpactReader().summaries(ORGANIZATION_ID, ["audit-1"]))["audit-1"]
    assert result.result == expected
    assert result.coverage == coverage
    assert result.confidence == artifact["assessment"]["confidence"]
    assert result.unmapped_count == len(artifact["plan"]["unmapped"])


@pytest.mark.parametrize("mismatch", ["revision", "investigation_id", "_id", "audit_id"])
async def test_foreign_or_unpublished_artifact_never_becomes_a_verdict(monkeypatch, mismatch):
    root, artifact = documents()
    if mismatch == "audit_id":
        artifact["assessment"]["audit_id"] = "foreign-audit"
    else:
        artifact[mismatch] = 4 if mismatch == "revision" else PydanticObjectId()
    collections(monkeypatch, [root], [artifact])
    result = (await PublishedAuditImpactReader().summaries(ORGANIZATION_ID, ["audit-1"]))["audit-1"]
    assert result.result == "unavailable"
    assert result.impact is None
    assert result.report_id is None


@pytest.mark.parametrize(("status", "expected"), [("collecting", "pending"), ("incomplete", "unavailable")])
async def test_no_published_artifact_is_never_clean(monkeypatch, status, expected):
    root, _ = documents()
    root.update(report_id=None, revision=0, status=status)
    _, artifacts = collections(monkeypatch, [root], [])
    result = (await PublishedAuditImpactReader().summaries(ORGANIZATION_ID, ["audit-1"]))["audit-1"]
    assert result.result == expected
    assert result.impact is None
    artifacts.find.assert_not_called()


async def test_shadow_database_failure_is_explicit_and_does_not_fail_production_page(monkeypatch):
    roots, _ = collections(monkeypatch, [], [])
    roots.find.side_effect = ConnectionFailure("internal connection detail")
    result = await PublishedAuditImpactReader().summaries(ORGANIZATION_ID, ["audit-1"])
    assert result["audit-1"].result == "unavailable"
    assert "internal connection" not in result["audit-1"].model_dump_json()


async def test_empty_and_oversized_batches_do_not_query(monkeypatch):
    roots, artifacts = collections(monkeypatch, [], [])
    reader = PublishedAuditImpactReader()
    assert await reader.summaries(ORGANIZATION_ID, []) == {}
    with pytest.raises(ValueError, match="page limit"):
        await reader.summaries(ORGANIZATION_ID, [str(index) for index in range(501)])
    roots.find.assert_not_called()
    artifacts.find.assert_not_called()


def service(monkeypatch):
    monkeypatch.setattr(change_groups, "get_settings", lambda: SimpleNamespace(impact_engine_mode="shadow"))
    store = _MemoryChangeGroupStore()
    store.groups = [_group(impact_severity=ImpactSeverity.CRITICAL)]
    projection = AuditImpactSummary(
        result="no_observed_disconnect",
        report_id=str(PydanticObjectId()),
        revision=3,
        impact="none",
        confidence="medium",
        coverage="complete",
    )
    reader = SimpleNamespace(summaries=AsyncMock(return_value={"audit-1": projection}))
    return ChangeGroupService(store, reader), store, reader


async def test_changes_list_detail_and_overview_share_projection_without_replacing_production(monkeypatch):
    changes, store, reader = service(monkeypatch)
    [row], total = await changes.list_groups(ORGANIZATION_ID, ChangeGroupFilters(severity="critical"), viewer_email="")
    detail = await changes.get_group(ORGANIZATION_ID, store.groups[0].id, viewer_email="")
    overview_reader = _MemoryOverviewReader()
    overview_reader.groups = store.groups
    overview = await OverviewService(overview_reader, changes).collect(
        _organization(), range_key="24h", viewer_email=""
    )
    assert total == 1
    assert row.shadow_impact == detail.shadow_impact == overview.change_groups[0].shadow_impact
    assert row.impact_severity == detail.impact_severity == ImpactSeverity.CRITICAL
    assert overview.counts.impacting == 2  # Production aggregate is not replaced by feed-local shadow counts.
    assert row.impact_source == overview.counts.impact_source == "legacy"
    assert overview.shadow_feed_counts.scope == "returned_feed"
    assert overview.shadow_feed_counts.total == overview.shadow_feed_counts.no_observed_disconnect == 1
    assert reader.summaries.await_count == 3
    for call in reader.summaries.await_args_list:
        assert call.args == (ORGANIZATION_ID, ["audit-1"])


async def test_historical_and_counts_only_reads_do_not_fetch_live_shadow(monkeypatch):
    changes, store, reader = service(monkeypatch)
    [row] = await changes.summarize(ORGANIZATION_ID, store.groups, viewer_email="", historical=True)
    detail = await changes.get_group(ORGANIZATION_ID, store.groups[0].id, viewer_email="", as_of=NOW)
    overview_reader = _MemoryOverviewReader()
    overview_reader.groups = store.groups
    overview = OverviewService(overview_reader, changes)
    past = await overview.collect(_organization(), range_key="24h", viewer_email="", as_of=NOW)
    badges = await overview.collect(_organization(), range_key="24h", viewer_email="", counts_only=True)
    assert row.shadow_impact is detail.shadow_impact is past.shadow_feed_counts is badges.shadow_feed_counts is None
    assert row.impact_source is detail.impact_source is past.counts.impact_source is None
    reader.summaries.assert_not_awaited()


async def test_legacy_mode_never_queries_shadow_collections(monkeypatch):
    changes, store, reader = service(monkeypatch)
    monkeypatch.setattr(change_groups, "get_settings", lambda: SimpleNamespace(impact_engine_mode="legacy"))
    [row] = await changes.summarize(ORGANIZATION_ID, store.groups, viewer_email="")
    assert row.shadow_impact is None
    reader.summaries.assert_not_awaited()


async def test_incomplete_runtime_cannot_present_an_older_clean_checkpoint_as_complete(monkeypatch):
    root, artifact = documents()
    root.update(status="incomplete", stop_reason="Investigation expired before a checkpoint could be published.")
    collections(monkeypatch, [root], [artifact])
    result = (await PublishedAuditImpactReader().summaries(ORGANIZATION_ID, ["audit-1"]))["audit-1"]
    assert result.result == "insufficient_evidence"
    assert result.evaluated_at == NOW
    assert result.coverage == "complete"  # Coverage is for the preserved checkpoint, not the whole investigation.
    assert result.status == "incomplete"


async def test_shadow_disagreement_does_not_change_notification_decisions(monkeypatch):
    changes, store, reader = service(monkeypatch)
    notifications = SimpleNamespace(notify_impact_detected=AsyncMock())
    projector = ChangeGroupProjector(store, notifications=notifications)
    await changes.summarize(ORGANIZATION_ID, store.groups, viewer_email="")
    await projector._announce(store.groups[0])  # noqa: SLF001
    notifications.notify_impact_detected.assert_awaited_once()  # Legacy critical remains authoritative during shadow.
    notifications.notify_impact_detected.reset_mock()
    store.groups[0].impact_severity = ImpactSeverity.NONE
    reader.summaries.return_value = {"audit-1": AuditImpactSummary(result="possible_disruption", impact="warning")}
    await changes.summarize(ORGANIZATION_ID, store.groups, viewer_email="")
    await projector._announce(store.groups[0])  # noqa: SLF001
    notifications.notify_impact_detected.assert_not_awaited()


def test_feed_counts_are_exclusive_and_never_reclassify_missing_evidence_as_clean():
    from mist_config_guardian_backend.schemas.change_group import ChangeGroupSummaryResponse  # noqa: PLC0415
    from mist_config_guardian_backend.services.overview import shadow_feed_counts  # noqa: PLC0415

    states = [
        "possible_disruption",
        "no_observed_disconnect",
        "insufficient_evidence",
        "pending",
        "unavailable",
        "not_recorded",
    ]
    rows = [
        ChangeGroupSummaryResponse.model_construct(shadow_impact=AuditImpactSummary(result=state)) for state in states
    ]
    counts = shadow_feed_counts(rows)
    assert counts.total == 6
    assert all(getattr(counts, state) == 1 for state in states)
    assert counts.total == sum(getattr(counts, state) for state in states)
    assert shadow_feed_counts([]) is None
    assert shadow_feed_counts([ChangeGroupSummaryResponse.model_construct(shadow_impact=None)]) is None
