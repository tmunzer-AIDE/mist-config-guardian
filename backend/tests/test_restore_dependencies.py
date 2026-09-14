"""Restore dependency expansion stays within explicitly selected containers."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from beanie import PydanticObjectId
from beanie.odm.fields import ExpressionField

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.restore import RestoreActionType, RestoreMode
from mist_config_guardian_backend.models.snapshot import (
    LogicalObject,
    ObjectIncarnation,
    ObjectReference,
    ObjectVersion,
    VersionEvent,
)
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.restore_planner import PlanningContext, RestorePlanner


def _logical(
    organization_id: PydanticObjectId,
    *,
    object_type: str,
    mist_id: str,
    site_mist_id: str | None = "site-1",
    is_deleted: bool = False,
) -> LogicalObject:
    return LogicalObject.model_construct(
        id=PydanticObjectId(),
        organization_id=organization_id,
        scope="org" if object_type == "data" else "site",
        object_type=object_type,
        source_key=mist_id,
        current_mist_id=mist_id,
        site_mist_id=None if object_type == "data" else site_mist_id,
        name=object_type,
        is_deleted=is_deleted,
        current_version=1,
    )


def _version(
    organization_id: PydanticObjectId,
    logical: LogicalObject,
    *,
    references: list[ObjectReference] | None = None,
) -> ObjectVersion:
    assert logical.id is not None
    return ObjectVersion.model_construct(
        id=PydanticObjectId(),
        organization_id=organization_id,
        logical_object_id=logical.id,
        incarnation_id=PydanticObjectId(),
        version=1,
        event=VersionEvent.UPDATED,
        configuration={},
        configuration_hash="hash",
        references=references or [],
        is_deleted=False,
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _planner() -> RestorePlanner:
    return RestorePlanner(
        store=AsyncMock(),
        vault=CredentialVault(Settings(environment="test", credential_encryption_key="test-key")),
    )


@pytest.mark.parametrize("target_type", ["data", "sites", "maps"])
@pytest.mark.parametrize("field_path", ["tag_uuid", "inventory.tag_uuid", "tag_uuid.0"])
async def test_legacy_inventory_tag_references_are_never_followed(
    monkeypatch: pytest.MonkeyPatch,
    target_type: str,
    field_path: str,
) -> None:
    organization_id = PydanticObjectId()
    device = _logical(organization_id, object_type="devices", mist_id="device-1")
    target_mist_id = "8aa21779-1178-4357-b3e0-42c02b93b870"
    target = _logical(organization_id, object_type=target_type, mist_id=target_mist_id)
    assert target.id is not None
    incarnation = ObjectIncarnation.model_construct(
        id=PydanticObjectId(),
        organization_id=organization_id,
        logical_object_id=target.id,
        mist_object_id=target_mist_id,
        ordinal=1,
    )
    version = _version(
        organization_id,
        device,
        references=[ObjectReference(target_mist_id=target_mist_id, field_path=field_path)],
    )
    find_one = AsyncMock(return_value=incarnation)
    monkeypatch.setattr(ObjectIncarnation, "find_one", find_one)
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

    related = await _planner()._related_logical_objects(  # noqa: SLF001
        organization_id,
        device,
        version,
        include_contained=False,
    )

    assert related == []
    find_one.assert_not_awaited()


@pytest.mark.parametrize("target_type", ["data", "sites", "maps"])
async def test_configuration_references_still_include_the_target(
    monkeypatch: pytest.MonkeyPatch,
    target_type: str,
) -> None:
    organization_id = PydanticObjectId()
    source = _logical(organization_id, object_type="networktemplates", mist_id="template-1")
    target_mist_id = "8aa21779-1178-4357-b3e0-42c02b93b870"
    target = _logical(organization_id, object_type=target_type, mist_id=target_mist_id)
    assert target.id is not None
    incarnation = ObjectIncarnation.model_construct(
        id=PydanticObjectId(),
        organization_id=organization_id,
        logical_object_id=target.id,
        mist_object_id=target_mist_id,
        ordinal=1,
    )
    version = _version(
        organization_id,
        source,
        references=[ObjectReference(target_mist_id=target_mist_id, field_path="applies.site_ids.0")],
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

    related = await _planner()._related_logical_objects(  # noqa: SLF001
        organization_id,
        source,
        version,
        include_contained=False,
    )

    assert related == [target]


@pytest.mark.parametrize("container_type", ["data", "sites"])
async def test_unselected_container_does_not_query_or_include_its_contents(
    monkeypatch: pytest.MonkeyPatch,
    container_type: str,
) -> None:
    organization_id = PydanticObjectId()
    container = _logical(organization_id, object_type=container_type, mist_id="container-1")
    child = _logical(organization_id, object_type="wlans", mist_id="wlan-1")
    version = _version(organization_id, container)

    class ContainedQuery:
        async def to_list(self) -> list[LogicalObject]:
            return [child]

    find = MagicMock(return_value=ContainedQuery())
    monkeypatch.setattr(LogicalObject, "find", find)
    monkeypatch.setattr(
        LogicalObject,
        "organization_id",
        ExpressionField("organization_id"),
        raising=False,
    )
    monkeypatch.setattr(
        LogicalObject,
        "site_mist_id",
        ExpressionField("site_mist_id"),
        raising=False,
    )

    related = await _planner()._related_logical_objects(  # noqa: SLF001
        organization_id,
        container,
        version,
        include_contained=False,
    )

    assert related == []
    find.assert_not_called()


@pytest.mark.parametrize("container_type", ["data", "sites"])
@pytest.mark.parametrize("arrival", ["forward_reference", "reverse_dependent"])
async def test_inferred_containers_do_not_expand_their_contents(
    monkeypatch: pytest.MonkeyPatch,
    container_type: str,
    arrival: str,
) -> None:
    organization_id = PydanticObjectId()
    root = _logical(
        organization_id,
        object_type="devices",
        mist_id="device-1",
        is_deleted=arrival == "reverse_dependent",
    )
    container = _logical(organization_id, object_type=container_type, mist_id="container-1")
    child = _logical(organization_id, object_type="wlans", mist_id="wlan-1")
    root_version = _version(organization_id, root)
    container_version = _version(organization_id, container)
    child_version = _version(organization_id, child)
    assert root.id is not None
    assert container.id is not None
    assert child.id is not None
    context = PlanningContext(
        organization_id=organization_id,
        selected={root.id: root_version},
        requested_logical_ids=frozenset({root.id}),
        logical_objects={root.id: root},
        force_delete=set(),
        target_at=root_version.observed_at,
        mode=RestoreMode.NON_DESTRUCTIVE,
    )
    containment_flags: list[tuple[str, bool]] = []

    async def related(
        _organization_id: PydanticObjectId,
        logical: LogicalObject,
        _version: ObjectVersion,
        *,
        include_contained: bool,
    ) -> list[LogicalObject]:
        containment_flags.append((logical.object_type, include_contained))
        if logical is root and arrival == "forward_reference":
            return [container]
        if logical is container and include_contained:
            return [child]
        return []

    planner = _planner()
    monkeypatch.setattr(planner, "_related_logical_objects", related)
    monkeypatch.setattr(planner, "_version_at", AsyncMock(side_effect=[container_version, child_version]))
    monkeypatch.setattr(
        planner,
        "_reverse_dependents",
        AsyncMock(return_value=[(container, container_version)] if arrival == "reverse_dependent" else []),
    )

    await planner._expand_dependencies(context)  # noqa: SLF001

    assert container.id in context.selected
    assert child.id not in context.selected
    assert (container_type, False) in containment_flags


@pytest.mark.parametrize("container_type", ["data", "sites"])
async def test_explicitly_selected_container_expands_its_contents(
    monkeypatch: pytest.MonkeyPatch,
    container_type: str,
) -> None:
    organization_id = PydanticObjectId()
    container = _logical(organization_id, object_type=container_type, mist_id="container-1")
    child = _logical(organization_id, object_type="wlans", mist_id="wlan-1")
    container_version = _version(organization_id, container)
    child_version = _version(organization_id, child)
    assert container.id is not None
    assert child.id is not None
    context = PlanningContext(
        organization_id=organization_id,
        selected={container.id: container_version},
        requested_logical_ids=frozenset({container.id}),
        logical_objects={container.id: container},
        force_delete=set(),
        target_at=container_version.observed_at,
        mode=RestoreMode.NON_DESTRUCTIVE,
    )

    async def related(
        _organization_id: PydanticObjectId,
        logical: LogicalObject,
        _version: ObjectVersion,
        *,
        include_contained: bool,
    ) -> list[LogicalObject]:
        if logical is container and include_contained:
            return [child]
        return []

    planner = _planner()
    monkeypatch.setattr(planner, "_related_logical_objects", related)
    monkeypatch.setattr(planner, "_version_at", AsyncMock(return_value=child_version))

    await planner._expand_dependencies(context)  # noqa: SLF001

    assert child.id in context.selected


async def test_legacy_inventory_tag_is_not_a_reverse_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization_id = PydanticObjectId()
    referenced = _logical(organization_id, object_type="maps", mist_id="shared-id", is_deleted=True)
    dependent = _logical(organization_id, object_type="devices", mist_id="device-1")
    candidate = _version(
        organization_id,
        dependent,
        references=[ObjectReference(target_mist_id="shared-id", field_path="tag_uuid")],
    )

    class CandidateQuery:
        async def to_list(self) -> list[ObjectVersion]:
            return [candidate]

    monkeypatch.setattr(ObjectVersion, "find", lambda *_args, **_kwargs: CandidateQuery())
    monkeypatch.setattr(
        ObjectVersion,
        "organization_id",
        ExpressionField("organization_id"),
        raising=False,
    )
    latest = AsyncMock(return_value=candidate)
    planner = _planner()
    monkeypatch.setattr(planner, "_latest_version", latest)

    dependents = await planner._reverse_dependents(organization_id, referenced)  # noqa: SLF001

    assert dependents == []
    latest.assert_not_awaited()


async def test_legacy_inventory_tag_does_not_create_action_ordering_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization_id = PydanticObjectId()
    source = _logical(
        organization_id,
        object_type="devices",
        mist_id="device-1",
        site_mist_id=None,
    )
    accidental_target = _logical(organization_id, object_type="maps", mist_id="shared-id", is_deleted=True)
    source_version = _version(
        organization_id,
        source,
        references=[ObjectReference(target_mist_id="shared-id", field_path="tag_uuid")],
    )
    assert source.id is not None
    assert accidental_target.id is not None
    find_one = AsyncMock()
    monkeypatch.setattr(ObjectIncarnation, "find_one", find_one)

    dependencies = await _planner()._action_dependencies(  # noqa: SLF001
        organization_id,
        source_version,
        {source.id: source_version, accidental_target.id: _version(organization_id, accidental_target)},
        {source.id: source, accidental_target.id: accidental_target},
        RestoreActionType.UPDATE,
    )

    assert dependencies == []
    find_one.assert_not_awaited()
