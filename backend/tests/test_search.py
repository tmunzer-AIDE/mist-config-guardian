"""Global search service and API tests."""

import re
from collections.abc import Sequence

import httpx
from beanie import PydanticObjectId

from mist_config_guardian_backend.api.dependencies import get_current_user, require_organization
from mist_config_guardian_backend.api.routes.search import get_search_service
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.main import create_app
from mist_config_guardian_backend.models.monitoring import ImpactSeverity
from mist_config_guardian_backend.models.organization import (
    MistCloudRegion,
    Organization,
    OrganizationStatus,
)
from mist_config_guardian_backend.models.restore import (
    RestoreMode,
    RestoreOperation,
    RestoreStatus,
)
from mist_config_guardian_backend.models.snapshot import LogicalObject
from mist_config_guardian_backend.models.user import User, UserRole
from mist_config_guardian_backend.models.webhook import (
    AuditChangeGroup,
    ChangedObjectRef,
    RecoveryState,
)
from mist_config_guardian_backend.services.search import PER_KIND_LIMIT, SearchService

ORGANIZATION_ID = PydanticObjectId()
OTHER_ORGANIZATION_ID = PydanticObjectId()
SEATTLE = "site-seattle-1234"


def _logical(
    *,
    name: str,
    object_type: str = "wlans",
    scope: str = "org",
    mist_id: str | None = None,
    organization_id: PydanticObjectId = ORGANIZATION_ID,
) -> LogicalObject:
    return LogicalObject.model_construct(
        id=PydanticObjectId(),
        organization_id=organization_id,
        scope=scope,
        object_type=object_type,
        source_key=name,
        current_mist_id=mist_id or f"mist-{name}",
        site_mist_id=None,
        name=name,
        is_deleted=False,
        current_version=15,
        created_at=None,
        updated_at=None,
    )


def _group(
    *,
    audit_id: str,
    actor: str,
    object_name: str = "NW-Corp",
    organization_id: PydanticObjectId = ORGANIZATION_ID,
) -> AuditChangeGroup:
    return AuditChangeGroup.model_construct(
        id=PydanticObjectId(),
        organization_id=organization_id,
        audit_id=audit_id,
        actor=actor,
        method="PUT",
        message="modify wlan",
        occurred_at=None,
        receipt_ids=[],
        affected_site_ids=[SEATTLE],
        affected_object_ids=[],
        changed_objects=[
            ChangedObjectRef(
                logical_object_id=PydanticObjectId(),
                object_type="gatewaytemplates",
                object_name=object_name,
                scope="org",
                event="updated",
            )
        ],
        affected_devices=[],
        monitoring_session_ids=[],
        impact_severity=ImpactSeverity.CRITICAL,
        recovery_state=RecoveryState.UNRECOVERED,
        degraded_metrics=[],
        evidence=[],
        summary="",
    )


def _restore(*, organization_id: PydanticObjectId = ORGANIZATION_ID) -> RestoreOperation:
    return RestoreOperation.model_construct(
        id=PydanticObjectId(),
        organization_id=organization_id,
        requested_by=PydanticObjectId(),
        mode=RestoreMode.NON_DESTRUCTIVE,
        include_dependencies=True,
        target_at=None,
        status=RestoreStatus.COMPLETED,
        actions=[],
        warnings=[],
        preflight_errors=[],
    )


class _MemorySearchReader:
    """Reader double applying the escaped pattern the service builds."""

    def __init__(self) -> None:
        self.objects_: list[LogicalObject] = []
        self.groups: list[AuditChangeGroup] = []
        self.restore_operations: list[RestoreOperation] = []
        self.patterns: list[str] = []
        self.limits: list[int] = []

    def _search(self, pattern: str, value: str | None) -> bool:
        return bool(value) and re.search(pattern, str(value), re.IGNORECASE) is not None

    async def objects(
        self,
        organization_id: PydanticObjectId,
        pattern: str,
        *,
        limit: int,
    ) -> list[LogicalObject]:
        self.patterns.append(pattern)
        self.limits.append(limit)
        matched = [
            logical
            for logical in self.objects_
            if logical.organization_id == organization_id
            and (self._search(pattern, logical.name) or self._search(pattern, logical.object_type))
        ]
        return matched[:limit]

    async def change_groups(
        self,
        organization_id: PydanticObjectId,
        pattern: str,
        *,
        limit: int,
    ) -> list[AuditChangeGroup]:
        self.limits.append(limit)
        matched = [
            group
            for group in self.groups
            if group.organization_id == organization_id
            and (
                self._search(pattern, group.audit_id)
                or self._search(pattern, group.actor)
                or any(self._search(pattern, ref.object_name) for ref in group.changed_objects)
            )
        ]
        return matched[:limit]

    async def sites(
        self,
        organization_id: PydanticObjectId,
        pattern: str,
        *,
        limit: int,
    ) -> list[LogicalObject]:
        self.limits.append(limit)
        matched = [
            logical
            for logical in self.objects_
            if logical.organization_id == organization_id
            and logical.object_type == "sites"
            and (self._search(pattern, logical.name) or self._search(pattern, logical.current_mist_id))
        ]
        return matched[:limit]

    async def restores(
        self,
        organization_id: PydanticObjectId,
        pattern: str,
        *,
        limit: int,
    ) -> list[RestoreOperation]:
        self.limits.append(limit)
        matched = [
            operation
            for operation in self.restore_operations
            if operation.organization_id == organization_id and self._search(pattern, str(operation.id))
        ]
        return matched[:limit]


def _reader() -> _MemorySearchReader:
    reader = _MemorySearchReader()
    reader.objects_.extend(
        [
            _logical(name="NW-Corp"),
            _logical(name="NW-Guest"),
            _logical(name="Indoor-Dense-6G", object_type="rftemplates"),
            _logical(name="Seattle-DC", object_type="sites", mist_id=SEATTLE),
        ]
    )
    reader.groups.extend(
        [
            _group(audit_id="9F2A-C41", actor="j.mercer"),
            _group(audit_id="4C81-0AE", actor="a.osei", object_name="Portland-2"),
        ]
    )
    reader.restore_operations.append(_restore())
    return reader


def _viewer() -> User:
    return User.model_construct(
        id=PydanticObjectId(),
        email="viewer@example.com",
        display_name="Viewer",
        password_hash="unused",
        role=UserRole.VIEWER,
        is_active=True,
    )


def _organization(organization_id: PydanticObjectId = ORGANIZATION_ID) -> Organization:
    return Organization.model_construct(
        id=organization_id,
        mist_org_id="org-1",
        name="Northwind Retail",
        cloud_region=MistCloudRegion.GLOBAL_01,
        status=OrganizationStatus.VERIFIED,
        encrypted_service_token="v1:encrypted-value",
        service_token_last_four="4f21",
    )


def _kinds(items: Sequence[object]) -> list[str]:
    return [getattr(item, "kind", "") for item in items]


# -------------------------------------------------------------------- service


async def test_short_terms_never_reach_the_database() -> None:
    reader = _reader()

    results = await SearchService(reader).search(ORGANIZATION_ID, "n")

    assert results.items == []
    assert results.total == 0
    assert reader.patterns == []


async def test_object_names_match_and_deep_link_into_history() -> None:
    reader = _reader()

    results = await SearchService(reader).search(ORGANIZATION_ID, "NW-")

    objects = [item for item in results.items if item.kind == "object"]
    assert [item.title for item in objects] == ["NW-Corp", "NW-Guest"]
    assert objects[0].subtitle == "Organization WLAN"
    assert objects[0].target == "history"
    assert objects[0].target_params == {"object": objects[0].id}
    assert objects[0].meta == "v15"


async def test_object_types_match_by_name() -> None:
    results = await SearchService(_reader()).search(ORGANIZATION_ID, "rftemplate")

    assert [item.title for item in results.items if item.kind == "object"] == ["Indoor-Dense-6G"]


async def test_audit_identifiers_match_and_deep_link_into_changes() -> None:
    results = await SearchService(_reader()).search(ORGANIZATION_ID, "9f2a")

    audits = [item for item in results.items if item.kind == "audit_id"]
    assert len(audits) == 1
    assert audits[0].title == "Gateway template updated · NW-Corp"
    assert audits[0].subtitle == "9F2A-C41"
    assert audits[0].meta == "CRITICAL"
    assert audits[0].target == "changes"
    assert set(audits[0].target_params) == {"group"}


async def test_actors_match_as_both_a_change_and_an_actor_row() -> None:
    results = await SearchService(_reader()).search(ORGANIZATION_ID, "osei")

    kinds = _kinds(results.items)
    assert "change_group" in kinds
    assert "actor" in kinds
    actor = next(item for item in results.items if item.kind == "actor")
    assert actor.title == "a.osei"
    assert actor.meta == "1 change group"
    assert actor.target_params == {"actor": "a.osei"}


async def test_sites_match_by_name_and_by_identifier() -> None:
    service = SearchService(_reader())

    by_name = await service.search(ORGANIZATION_ID, "Seattle")
    by_id = await service.search(ORGANIZATION_ID, "1234")

    site = next(item for item in by_name.items if item.kind == "site")
    assert site.title == "Seattle-DC"
    assert site.target_params == {"site": SEATTLE}
    assert [item.kind for item in by_id.items if item.kind == "site"] == ["site"]


async def test_restore_operations_match_on_their_identifier() -> None:
    reader = _reader()
    operation = reader.restore_operations[0]
    assert operation.id is not None

    results = await SearchService(reader).search(ORGANIZATION_ID, str(operation.id)[-8:])

    restores = [item for item in results.items if item.kind == "restore"]
    assert len(restores) == 1
    assert restores[0].target == "restore"
    assert restores[0].target_params == {"operation": str(operation.id)}
    assert restores[0].meta == "COMPLETED"


async def test_regex_metacharacters_are_searched_literally() -> None:
    reader = _reader()
    reader.objects_.append(_logical(name="a.b-literal"))
    reader.objects_.append(_logical(name="axb-regex"))

    results = await SearchService(reader).search(ORGANIZATION_ID, "a.b")

    assert [item.title for item in results.items if item.kind == "object"] == ["a.b-literal"]
    assert reader.patterns[0] == re.escape("a.b")


async def test_search_never_crosses_organizations() -> None:
    reader = _reader()
    reader.objects_.append(_logical(name="NW-Foreign", organization_id=OTHER_ORGANIZATION_ID))
    reader.groups.append(_group(audit_id="9F2A-FOREIGN", actor="x", organization_id=OTHER_ORGANIZATION_ID))
    reader.restore_operations.append(_restore(organization_id=OTHER_ORGANIZATION_ID))

    results = await SearchService(reader).search(ORGANIZATION_ID, "NW-")

    assert all("Foreign" not in item.title for item in results.items)


async def test_the_work_is_capped_per_kind_and_by_the_requested_limit() -> None:
    reader = _reader()
    reader.objects_.extend(_logical(name=f"NW-{index}") for index in range(40))

    results = await SearchService(reader).search(ORGANIZATION_ID, "NW-", limit=4)

    assert set(reader.limits) == {PER_KIND_LIMIT}
    assert len(results.items) == 4
    assert results.total >= 4


# ----------------------------------------------------------------------- api


def _app(service: SearchService) -> object:
    app = create_app(Settings(environment="test", database_enabled=False))
    app.dependency_overrides[get_current_user] = _viewer
    app.dependency_overrides[require_organization] = _organization
    app.dependency_overrides[get_search_service] = lambda: service
    return app


async def test_search_endpoint_returns_the_contract() -> None:
    app = _app(SearchService(_reader()))

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(
            f"/api/v1/organizations/{ORGANIZATION_ID}/search",
            params={"q": "NW-", "limit": 25},
        )

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"items", "total"}
    assert set(body["items"][0]) == {
        "kind",
        "id",
        "title",
        "subtitle",
        "meta",
        "target",
        "target_params",
    }


async def test_search_endpoint_rejects_a_one_character_term() -> None:
    app = _app(SearchService(_reader()))

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(
            f"/api/v1/organizations/{ORGANIZATION_ID}/search",
            params={"q": "n"},
        )

    assert response.status_code == 422
