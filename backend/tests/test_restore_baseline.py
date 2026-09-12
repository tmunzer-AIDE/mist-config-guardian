"""Fresh backups and retained credentials respect a separate review boundary."""

# ruff: noqa: SLF001 - exercise the backup boundary without a live Mist organization

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from beanie import PydanticObjectId
from beanie.odm.fields import ExpressionField

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.organization import MistCloudRegion, Organization
from mist_config_guardian_backend.models.restore import RestoreOperation, RestoreStatus
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services import restore_baseline as baseline_module
from mist_config_guardian_backend.services.restore_authorization import (
    RestoreAuthorizationError,
    RestoreAuthorizationService,
)
from mist_config_guardian_backend.services.restore_baseline import RestoreBaselineService
from mist_config_guardian_backend.services.restore_planner import RestorePlanningError
from mist_config_guardian_backend.snapshots.canonical import configuration_hash
from mist_config_guardian_backend.snapshots.secrets import reveal_configuration


@pytest.fixture
def capture(monkeypatch):
    vault = CredentialVault(Settings(environment="test"))
    logical_id, org_id = PydanticObjectId(), PydanticObjectId()
    previous = SimpleNamespace(version=2, incarnation_id=PydanticObjectId(), configuration={"name": "test"})
    logical = SimpleNamespace(
        scope="org",
        object_type="networktemplates",
        current_mist_id="mist-id",
        site_mist_id=None,
        is_deleted=False,
        organization_id=org_id,
    )
    manifest = SimpleNamespace(id=PydanticObjectId(), created_versions=0, unchanged_objects=0)
    versions = []

    class Version:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)
            self.id = PydanticObjectId()

        async def insert(self):
            versions.append(self)

    monkeypatch.setattr(baseline_module, "ObjectVersion", Version)
    monkeypatch.setattr(baseline_module, "latest_version", AsyncMock(return_value=previous))
    monkeypatch.setattr(
        baseline_module,
        "LogicalObject",
        SimpleNamespace(
            id=ExpressionField("id"),
            find_one=MagicMock(return_value=SimpleNamespace(update=AsyncMock())),
        ),
    )
    client = SimpleNamespace(
        get_current=AsyncMock(
            return_value={
                "id": "mist-id",
                "name": "test",
                "switch_mgmt": {"root_password": "recoverable-secret"},
            }
        )
    )
    return (
        RestoreBaselineService(vault, AsyncMock()),
        client,
        SimpleNamespace(mist_org_id="org"),
        {logical_id: logical},
        manifest,
        versions,
        vault,
    )


async def test_backup_pins_admin_response_and_encrypts_root_password(capture):
    service, client, org, objects, manifest, versions, vault = capture
    baselines = await service._capture(client, org, objects, manifest, "admin")
    assert len(versions) == 1
    version = versions[0]
    assert version.snapshot_id == manifest.id
    assert version.version == 3
    assert baselines[next(iter(objects))] is version
    assert "recoverable-secret" not in str(version.configuration)
    assert reveal_configuration(version.configuration, vault) == client.get_current.return_value
    assert version.configuration_hash == configuration_hash(client.get_current.return_value)
    assert manifest.created_versions == 1


async def test_masked_backup_is_rejected_before_version_is_saved(capture):
    service, client, org, objects, manifest, versions, _vault = capture
    client.get_current.return_value["switch_mgmt"]["root_password"] = "********"
    with pytest.raises(RestorePlanningError, match="unavailable secrets"):
        await service._capture(client, org, objects, manifest, "admin")
    assert versions == []


async def test_deleted_object_requires_history_refresh(capture):
    service, client, org, objects, manifest, versions, _vault = capture
    client.get_current.return_value = None
    with pytest.raises(RestorePlanningError, match="created or deleted"):
        await service._capture(client, org, objects, manifest, "admin")
    assert versions == []


@pytest.fixture
def authorization(monkeypatch):
    settings = Settings(environment="test")
    vault = CredentialVault(settings)
    operation = RestoreOperation.model_construct(
        id=PydanticObjectId(),
        organization_id=PydanticObjectId(),
        status=RestoreStatus.PLANNED,
        baseline_snapshot_id=PydanticObjectId(),
        preflight_errors=[],
        actions=[],
        delegated_credential_expires_at=utc_now() + timedelta(minutes=5),
    )
    operation.encrypted_delegated_credential = vault.encrypt_for_context(
        "prepared-token", context=f"restore:{operation.id}"
    )
    organization = SimpleNamespace(mist_org_id="org", cloud_region=MistCloudRegion.GLOBAL_02)
    for field in ("id", "organization_id", "status"):
        monkeypatch.setattr(RestoreOperation, field, ExpressionField(field), raising=False)
    monkeypatch.setattr(Organization, "get", AsyncMock(return_value=organization))
    monkeypatch.setattr(RestoreOperation, "get", AsyncMock(return_value=operation))
    query = SimpleNamespace(update=AsyncMock(return_value=SimpleNamespace(modified_count=1)))

    async def load():
        return operation

    monkeypatch.setattr(RestoreOperation, "find_one", MagicMock(side_effect=[load(), query]))
    mist = AsyncMock()
    mist.verify_write_token.return_value = SimpleNamespace(actor="admin")
    return RestoreAuthorizationService(settings, vault, mist), operation, query, mist


async def test_execution_reuses_credential_without_extending_expiry(authorization):
    service, operation, query, mist = authorization
    expires = operation.delegated_credential_expires_at
    await service.authorize(operation.organization_id, operation.id, None, "task")
    mist.login.assert_not_called()
    assert mist.verify_write_token.call_args.kwargs["token"] == "prepared-token"
    saved = query.update.call_args.args[0]["$set"]
    assert saved["status"] is RestoreStatus.QUEUED
    assert saved["delegated_credential_expires_at"] == expires


async def test_expired_preparation_cannot_queue(authorization):
    service, operation, query, mist = authorization
    operation.delegated_credential_expires_at = utc_now() - timedelta(seconds=1)
    with pytest.raises(RestoreAuthorizationError, match="expired"):
        await service.authorize(operation.organization_id, operation.id, None, "task")
    query.update.assert_not_awaited()
    mist.verify_write_token.assert_not_awaited()


async def test_duplicate_prepared_execution_cannot_reserve_twice(authorization):
    service, operation, query, _mist = authorization
    query.update.return_value.modified_count = 0
    with pytest.raises(RestoreAuthorizationError, match="another request"):
        await service.authorize(operation.organization_id, operation.id, None, "task")


async def test_plan_uses_pinned_backup_even_if_background_history_changes(monkeypatch):
    from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectVersion  # noqa: PLC0415
    from mist_config_guardian_backend.services.restore_planner import RestorePlanner  # noqa: PLC0415

    vault = CredentialVault(Settings(environment="test"))
    logical_id, org_id = PydanticObjectId(), PydanticObjectId()
    logical = LogicalObject.model_construct(
        id=logical_id,
        organization_id=org_id,
        scope="org",
        object_type="networktemplates",
        current_mist_id="mist-id",
        name="test",
    )
    target = ObjectVersion.model_construct(
        id=PydanticObjectId(),
        logical_object_id=logical_id,
        configuration={"name": "old", "switch_mgmt": {"root_password": "historical-secret"}},
        configuration_hash="target",
    )
    pinned = ObjectVersion.model_construct(id=PydanticObjectId(), configuration_hash="fresh-backup")
    planner = RestorePlanner(AsyncMock(), vault=vault)
    planner._baselines = {logical_id: pinned}
    latest = AsyncMock(side_effect=AssertionError("must not use a later service-token snapshot"))
    monkeypatch.setattr(planner, "_latest_version", latest)
    monkeypatch.setattr(planner, "_action_dependencies", AsyncMock(return_value=[]))
    actions = await planner._build_actions(org_id, {logical_id: target}, {logical_id: logical}, set())
    assert len(actions) == 1
    assert actions[0].expected_current_hash == "fresh-backup"
    assert actions[0].source_version_id == target.id
    assert "historical-secret" not in str(actions[0].protected_configuration)
    latest.assert_not_awaited()


async def test_prepare_returns_new_plan_without_queueing_or_logging_out(monkeypatch):
    from mist_config_guardian_backend.models.snapshot import SnapshotStatus  # noqa: PLC0415

    vault = CredentialVault(Settings(environment="test"))
    source = RestoreOperation.model_construct(
        id=PydanticObjectId(),
        organization_id=PydanticObjectId(),
        requested_by=PydanticObjectId(),
        requested_version_ids=[PydanticObjectId()],
        mode="non_destructive",
        include_dependencies=True,
        status=RestoreStatus.FAILED,
    )
    plan = RestoreOperation.model_construct(id=PydanticObjectId(), status=RestoreStatus.PLANNED, warnings=[])
    manifest = SimpleNamespace(id=PydanticObjectId(), insert=AsyncMock(), save=AsyncMock(), touch=MagicMock())
    monkeypatch.setattr(baseline_module, "SnapshotManifest", MagicMock(return_value=manifest))
    monkeypatch.setattr(RestoreOperation, "save", AsyncMock())
    client = SimpleNamespace(close_transport=AsyncMock())
    monkeypatch.setattr(baseline_module, "MistMutationClient", MagicMock(return_value=client))
    planner = SimpleNamespace(create_plan=AsyncMock(return_value=plan))
    monkeypatch.setattr(baseline_module, "RestorePlanner", MagicMock(return_value=planner))
    service = RestoreBaselineService(vault, AsyncMock())
    result = await service.prepare(
        SimpleNamespace(cloud_region=MistCloudRegion.GLOBAL_02), source, source.requested_by, "admin-token", "admin"
    )
    assert result.id != source.id
    assert result.status is RestoreStatus.PLANNED
    assert source.status is RestoreStatus.FAILED
    assert result.baseline_snapshot_id == manifest.id
    assert result.encrypted_delegated_credential is None
    assert manifest.status is SnapshotStatus.COMPLETED
    assert manifest.active is False
    client.close_transport.assert_awaited_once()
