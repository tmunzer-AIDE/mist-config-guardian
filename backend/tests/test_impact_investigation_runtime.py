"""Worker fencing, immutable publication and per-audit bounds, without MongoDB."""

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

from beanie import PydanticObjectId

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.investigation import ImpactInvestigation, InvestigationRevision
from mist_config_guardian_backend.models.organization import MistCloudRegion, OrganizationStatus
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services import impact_investigations as runtime
from mist_config_guardian_backend.services.impact_investigations import ImpactInvestigationService
from test_wlan_investigation import LATER, NOW, ORG, inputs


def setup_runtime(monkeypatch, *, fence_matches=True, enabled=True):
    data = inputs()
    root = ImpactInvestigation.model_construct(
        id=PydanticObjectId(),
        organization_id=ORG,
        audit_id="audit-one",
        changed_at=NOW,
        first_due_at=NOW + timedelta(seconds=60),
        expires_at=NOW + timedelta(hours=1),
        next_poll_at=LATER,
        generation=3,
        revision=2,
        lease_until=LATER + timedelta(minutes=3),
    )
    service = ImpactInvestigationService(CredentialVault(Settings(environment="test", database_enabled=False)))
    service._configurations = SimpleNamespace(  # noqa: SLF001
        versions_for_audit=AsyncMock(return_value=data["after"]),
        logical_objects=AsyncMock(return_value=data["logicals"]),
        versions_at=AsyncMock(return_value=data["before"]),
    )
    organization = SimpleNamespace(
        status=OrganizationStatus.VERIFIED if enabled else OrganizationStatus.DISABLED,
        cloud_region=MistCloudRegion.GLOBAL_01,
        encrypted_service_token="encrypted-test-token",
    )
    monkeypatch.setattr(runtime, "utc_now", lambda: LATER)
    monkeypatch.setattr(runtime.Organization, "get", AsyncMock(return_value=organization))
    monkeypatch.setattr(runtime, "service_token", AsyncMock(return_value="test-token"))
    collection = SimpleNamespace(update_one=AsyncMock(return_value=SimpleNamespace(matched_count=int(fence_matches))))
    monkeypatch.setattr(ImpactInvestigation, "get_pymongo_collection", lambda *_: collection)
    # Initialize documents through a validating BaseModel path without a database.
    monkeypatch.setattr(InvestigationRevision, "get_pymongo_collection", lambda *_: collection)
    inserted = []

    async def insert(artifact, **_kwargs):
        artifact.id = PydanticObjectId()
        inserted.append(artifact)
        return artifact

    monkeypatch.setattr(InvestigationRevision, "insert", insert)
    return service, root, collection, inserted, organization


async def test_one_audit_checkpoint_issues_two_wlan_queries_and_publishes_one_revision(monkeypatch, httpx_mock):
    service, root, collection, inserted, _ = setup_runtime(monkeypatch)
    for start, end in [(NOW - timedelta(hours=1), NOW), (NOW, LATER)]:
        httpx_mock.add_response(
            json={"start": int(start.timestamp()), "end": int(end.timestamp()), "results": [], "total": 0}
        )
    await service._poll(root)  # noqa: SLF001
    assert len(httpx_mock.get_requests()) == 2
    assert len(inserted) == 1
    artifact = inserted[0]
    assert artifact.investigation_id == root.id
    assert artifact.revision == 3
    assert artifact.assessment.impact == "none"
    writes = collection.update_one.await_args_list
    assert len(writes) == 3
    for dispatch in writes[:2]:
        assert dispatch.args[0]["generation"] == 3
        assert dispatch.args[0]["lease_until"] == {"$gt": LATER}
        assert dispatch.args[0]["calls_used"] == {"$lt": 56}
        assert dispatch.args[1] == {"$inc": {"calls_used": 1}}
    predicate, publication = writes[-1].args
    assert predicate["revision"] == 2
    assert publication["$set"]["report_id"] == artifact.id
    assert publication["$set"]["next_poll_at"] == NOW + timedelta(minutes=20)
    assert "changed_at" not in publication["$set"]


async def test_lost_lease_prevents_dispatch_and_cannot_publish_over_new_owner(monkeypatch, httpx_mock):
    service, root, collection, inserted, _ = setup_runtime(monkeypatch, fence_matches=False)
    await service._poll(root)  # noqa: SLF001
    assert not httpx_mock.get_requests()
    assert inserted[0].assessment.impact == "info"
    assert all(e.state == "budget_exhausted" for e in inserted[0].evidence)
    predicate = collection.update_one.await_args_list[-1].args[0]
    assert predicate["generation"] == root.generation
    assert predicate["lease_until"] == {"$gt": LATER}


async def test_disabled_organization_dispatches_no_checks(monkeypatch, httpx_mock):
    service, root, collection, inserted, _ = setup_runtime(monkeypatch, enabled=False)
    await service._poll(root)  # noqa: SLF001
    assert not httpx_mock.get_requests()
    runtime.service_token.assert_not_awaited()
    assert inserted[0].assessment.coverage == "partial"
    assert collection.update_one.await_count == 1


async def test_late_worker_finishes_incomplete_without_starting_a_fresh_hour(monkeypatch, httpx_mock):
    service, root, collection, inserted, _ = setup_runtime(monkeypatch)
    root.expires_at = NOW + timedelta(minutes=1)
    await service._poll(root)  # noqa: SLF001
    assert not httpx_mock.get_requests()
    publication = collection.update_one.await_args_list[-1].args[1]["$set"]
    assert publication["status"] == "incomplete"
    assert publication["next_poll_at"] is None
    assert inserted[0].assessment.impact == "info"


async def test_credential_rotation_between_collection_and_dispatch_revokes_access(monkeypatch, httpx_mock):
    service, root, _, inserted, organization = setup_runtime(monkeypatch)
    rotated = SimpleNamespace(status=OrganizationStatus.VERIFIED, encrypted_service_token="new-token")
    monkeypatch.setattr(runtime.Organization, "get", AsyncMock(side_effect=[organization, rotated, rotated]))
    await service._poll(root)  # noqa: SLF001
    assert not httpx_mock.get_requests()
    assert inserted[0].assessment.impact == "info"


async def test_ensure_uses_insert_only_fields_and_preserves_audit_budgets(monkeypatch):
    service, root, collection, _, _ = setup_runtime(monkeypatch)
    monkeypatch.setattr(
        runtime.AuditChangeGroup, "find_one", AsyncMock(return_value=SimpleNamespace(audit_id=root.audit_id))
    )
    for _ in range(3):
        await service.ensure(ORG, root.audit_id, changed_at=NOW, anchor_known=True)
    for call in collection.update_one.await_args_list:
        predicate, update = call.args
        assert predicate == {"organization_id": ORG, "audit_id": root.audit_id}
        assert set(update) == {"$setOnInsert"}
        assert update["$setOnInsert"]["changed_at"] == NOW
        assert update["$setOnInsert"]["expires_at"] == NOW + timedelta(hours=1)
        assert update["$setOnInsert"]["first_due_at"] == LATER + timedelta(seconds=60)
        assert call.kwargs["upsert"] is True
    indexes = ImpactInvestigation.Settings.indexes
    unique = next(index.document for index in indexes if index.document.get("unique"))
    assert dict(unique["key"]) == {"organization_id": 1, "audit_id": 1}


async def test_preview_reads_only_the_published_revision_and_hides_client_identifiers(monkeypatch, httpx_mock):
    from mist_config_guardian_backend.services.investigation_reads import shadow_investigation  # noqa: PLC0415

    service, root, _, inserted, _ = setup_runtime(monkeypatch)
    for start, end in [(NOW - timedelta(hours=1), NOW), (NOW, LATER)]:
        httpx_mock.add_response(
            json={"start": int(start.timestamp()), "end": int(end.timestamp()), "results": [], "total": 0}
        )
    await service._poll(root)  # noqa: SLF001
    artifact = inserted[0]
    root.report_id = artifact.id
    root.revision = artifact.revision
    group_id = PydanticObjectId()
    group_lookup = AsyncMock(return_value=SimpleNamespace(audit_id=root.audit_id))
    root_lookup = AsyncMock(return_value=root)
    artifact_lookup = AsyncMock(return_value=artifact)
    monkeypatch.setattr(runtime.AuditChangeGroup, "find_one", group_lookup)
    monkeypatch.setattr(ImpactInvestigation, "find_one", root_lookup)
    monkeypatch.setattr(InvestigationRevision, "find_one", artifact_lookup)
    result = await shadow_investigation(ORG, group_id)
    group_lookup.assert_awaited_once_with({"_id": group_id, "organization_id": ORG})
    root_lookup.assert_awaited_once_with({"organization_id": ORG, "audit_id": root.audit_id})
    artifact_lookup.assert_awaited_once_with(
        {
            "_id": artifact.id,
            "organization_id": ORG,
            "investigation_id": root.id,
            "revision": root.revision,
        }
    )
    assert result.mode == "shadow"
    assert result.assessment.impact == "none"
    assert "client_mac" not in result.model_dump_json()
    assert len(result.checks) == 2


async def test_foreign_group_does_not_expose_an_investigation(monkeypatch):
    from mist_config_guardian_backend.services.investigation_reads import shadow_investigation  # noqa: PLC0415

    monkeypatch.setattr(runtime.AuditChangeGroup, "find_one", AsyncMock(return_value=None))
    lookup = AsyncMock()
    monkeypatch.setattr(ImpactInvestigation, "find_one", lookup)
    assert await shadow_investigation(ORG, PydanticObjectId()) is None
    lookup.assert_not_awaited()


async def test_repeated_checkpoint_failures_have_a_terminal_stopping_rule(monkeypatch, httpx_mock):
    service, root, collection, inserted, _ = setup_runtime(monkeypatch)
    root.generation = 11
    await service._poll(root)  # noqa: SLF001
    assert not httpx_mock.get_requests()
    assert inserted == []
    update = collection.update_one.await_args.args[1]["$set"]
    assert update["status"] == "incomplete"
    assert update["next_poll_at"] is None
    assert "attempt limit" in update["stop_reason"]


async def test_shadow_mode_never_invokes_the_legacy_device_ai(monkeypatch):
    from mist_config_guardian_backend.services import monitoring  # noqa: PLC0415

    monkeypatch.setattr(monitoring, "get_settings", lambda: SimpleNamespace(impact_engine_mode="shadow"))
    provider = AsyncMock()
    monkeypatch.setattr(monitoring, "OpenAiCompatibleImpactProvider", provider)
    service = monitoring.MonitoringPollService(
        CredentialVault(Settings(environment="test", database_enabled=False)),
        AsyncMock(),
    )
    await service._assess_with_ai(None, None, None)  # noqa: SLF001
    provider.assert_not_called()
