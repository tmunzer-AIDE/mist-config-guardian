"""Restore dependency expansion rejects accidental organization-root matches."""

from unittest.mock import AsyncMock

import pytest
from beanie import PydanticObjectId
from beanie.odm.fields import ExpressionField

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.snapshot import (
    LogicalObject,
    ObjectIncarnation,
    ObjectReference,
    ObjectVersion,
    VersionEvent,
)
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.restore_planner import RestorePlanner


@pytest.mark.parametrize(("target_type", "expected_count"), [("data", 0), ("maps", 1)])
async def test_only_child_objects_are_inferred_as_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    target_type: str,
    expected_count: int,
) -> None:
    organization_id = PydanticObjectId()
    device_id = PydanticObjectId()
    target_id = PydanticObjectId()
    target_mist_id = "8aa21779-1178-4357-b3e0-42c02b93b870"
    device = LogicalObject.model_construct(
        id=device_id,
        organization_id=organization_id,
        scope="site",
        object_type="devices",
        source_key="device-1",
        current_mist_id="device-1",
        site_mist_id="site-1",
        name="Switch",
        is_deleted=False,
        current_version=2,
    )
    target = LogicalObject.model_construct(
        id=target_id,
        organization_id=organization_id,
        scope="org" if target_type == "data" else "site",
        object_type=target_type,
        source_key="target-1",
        current_mist_id=target_mist_id,
        site_mist_id=None if target_type == "data" else "site-1",
        name="Target",
        is_deleted=False,
        current_version=1,
    )
    incarnation = ObjectIncarnation.model_construct(
        id=PydanticObjectId(),
        organization_id=organization_id,
        logical_object_id=target_id,
        mist_object_id=target_mist_id,
        ordinal=1,
    )
    version = ObjectVersion.model_construct(
        id=PydanticObjectId(),
        organization_id=organization_id,
        logical_object_id=device_id,
        incarnation_id=PydanticObjectId(),
        version=1,
        event=VersionEvent.UPDATED,
        configuration={},
        configuration_hash="hash",
        references=[ObjectReference(target_mist_id=target_mist_id, field_path="tag_uuid")],
        is_deleted=False,
    )
    monkeypatch.setattr(ObjectIncarnation, "find_one", AsyncMock(return_value=incarnation))
    monkeypatch.setattr(LogicalObject, "get", AsyncMock(return_value=target))
    monkeypatch.setattr(
        ObjectIncarnation,
        "organization_id",
        ExpressionField("organization_id"),
        raising=False,
    )
    monkeypatch.setattr(
        ObjectIncarnation,
        "mist_object_id",
        ExpressionField("mist_object_id"),
        raising=False,
    )
    planner = RestorePlanner(
        store=AsyncMock(),
        vault=CredentialVault(Settings(environment="test", credential_encryption_key="test-key")),
    )

    related = await planner._related_logical_objects(organization_id, device, version)  # noqa: SLF001

    assert related == [target] * expected_count
