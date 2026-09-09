"""Restore target discovery, filtering, and facet counts."""

from datetime import UTC, datetime

import httpx
from beanie import PydanticObjectId

from mist_config_guardian_backend.api.dependencies import get_current_user, require_organization
from mist_config_guardian_backend.api.routes.restores import get_restore_target_service
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.main import create_app
from mist_config_guardian_backend.models.organization import (
    MistCloudRegion,
    Organization,
    OrganizationStatus,
)
from mist_config_guardian_backend.models.snapshot import LogicalObject
from mist_config_guardian_backend.models.user import User, UserRole
from mist_config_guardian_backend.services.restore_targets import (
    RestorableVersion,
    RestoreTargetQuery,
    RestoreTargetService,
)

ORGANIZATION_ID = PydanticObjectId()
OBSERVED_AT = datetime(2026, 2, 1, tzinfo=UTC)


def _logical(  # noqa: PLR0913 - one keyword per logical object field a test varies
    name: str,
    object_type: str,
    *,
    scope: str = "site",
    site_mist_id: str | None = "site-a",
    mist_id: str | None = None,
    is_deleted: bool = False,
) -> LogicalObject:
    return LogicalObject.model_construct(
        id=PydanticObjectId(),
        organization_id=ORGANIZATION_ID,
        scope=scope,
        object_type=object_type,
        source_key=name,
        current_mist_id=mist_id or f"mist-{name}",
        site_mist_id=site_mist_id,
        name=name,
        is_deleted=is_deleted,
        current_version=1,
    )


class _MemoryTargetStore:
    """In-memory logical objects and their newest restorable versions."""

    def __init__(self, objects: list[LogicalObject], *, without_versions: set[str] | None = None) -> None:
        self.objects = objects
        self._without = without_versions or set()

    async def logical_objects(self, organization_id: PydanticObjectId) -> list[LogicalObject]:
        return [item for item in self.objects if item.organization_id == organization_id]

    async def restorable_versions(
        self,
        organization_id: PydanticObjectId,
    ) -> dict[PydanticObjectId, RestorableVersion]:
        return {
            item.id: RestorableVersion(version_id=PydanticObjectId(), version=3, observed_at=OBSERVED_AT)
            for item in self.objects
            if item.organization_id == organization_id and item.id is not None and item.name not in self._without
        }


def _catalog() -> list[LogicalObject]:
    return [
        _logical("Alpha", "sites", scope="org", site_mist_id=None, mist_id="site-a"),
        _logical("Bravo", "sites", scope="org", site_mist_id=None, mist_id="site-b"),
        _logical("Corp WLAN", "wlans", site_mist_id="site-a"),
        _logical("Guest WLAN", "wlans", site_mist_id="site-b"),
        _logical("Lab WLAN", "wlans", site_mist_id="site-a", is_deleted=True),
        _logical("Corp network", "networks", scope="org", site_mist_id=None),
    ]


def _service(objects: list[LogicalObject] | None = None, **kwargs) -> RestoreTargetService:
    return RestoreTargetService(_MemoryTargetStore(objects or _catalog(), **kwargs))


async def test_every_object_with_a_restorable_version_is_offered() -> None:
    page = await _service().search(RestoreTargetQuery(organization_id=ORGANIZATION_ID))

    assert page.total == 6
    assert {target.name for target in page.items} == {
        "Alpha",
        "Bravo",
        "Corp WLAN",
        "Guest WLAN",
        "Lab WLAN",
        "Corp network",
    }


async def test_objects_without_a_restorable_version_are_not_offered() -> None:
    service = _service(without_versions={"Lab WLAN"})

    page = await service.search(RestoreTargetQuery(organization_id=ORGANIZATION_ID))

    assert page.total == 5
    assert "Lab WLAN" not in {target.name for target in page.items}


async def test_site_scoped_targets_carry_their_site_name() -> None:
    page = await _service().search(
        RestoreTargetQuery(organization_id=ORGANIZATION_ID, object_type="wlans", site_id="site-a"),
    )

    assert [target.name for target in page.items] == ["Corp WLAN", "Lab WLAN"]
    assert {target.site_name for target in page.items} == {"Alpha"}


async def test_scope_filter_separates_organization_and_site_objects() -> None:
    organization = await _service().search(RestoreTargetQuery(organization_id=ORGANIZATION_ID, scope="org"))
    site = await _service().search(RestoreTargetQuery(organization_id=ORGANIZATION_ID, scope="site"))

    assert {target.name for target in organization.items} == {"Alpha", "Bravo", "Corp network"}
    assert {target.name for target in site.items} == {"Corp WLAN", "Guest WLAN", "Lab WLAN"}


async def test_free_text_matches_name_and_type() -> None:
    by_name = await _service().search(RestoreTargetQuery(organization_id=ORGANIZATION_ID, q="corp"))
    by_type = await _service().search(RestoreTargetQuery(organization_id=ORGANIZATION_ID, q="WLANS"))

    assert {target.name for target in by_name.items} == {"Corp WLAN", "Corp network"}
    assert {target.name for target in by_type.items} == {"Corp WLAN", "Guest WLAN", "Lab WLAN"}


async def test_type_facets_ignore_the_selected_type_but_honour_the_site() -> None:
    page = await _service().search(
        RestoreTargetQuery(organization_id=ORGANIZATION_ID, object_type="wlans", site_id="site-a"),
    )

    assert [(item.type, item.count) for item in page.types] == [("wlans", 2)]
    assert page.total == 2


async def test_type_facets_count_every_type_when_no_type_is_selected() -> None:
    page = await _service().search(RestoreTargetQuery(organization_id=ORGANIZATION_ID))

    assert [(item.type, item.count) for item in page.types] == [
        ("wlans", 3),
        ("sites", 2),
        ("networks", 1),
    ]


async def test_site_facets_ignore_the_selected_site() -> None:
    page = await _service().search(RestoreTargetQuery(organization_id=ORGANIZATION_ID, site_id="site-a"))

    assert [(item.id, item.name) for item in page.sites] == [("site-a", "Alpha"), ("site-b", "Bravo")]
    assert {target.name for target in page.items} == {"Corp WLAN", "Lab WLAN"}


async def test_pagination_reports_the_unpaged_total() -> None:
    page = await _service().search(RestoreTargetQuery(organization_id=ORGANIZATION_ID, skip=1, limit=2))

    assert page.total == 6
    assert len(page.items) == 2


async def test_another_organizations_objects_are_never_returned() -> None:
    foreign = _logical("Foreign", "wlans")
    foreign.organization_id = PydanticObjectId()

    page = await _service([*_catalog(), foreign]).search(RestoreTargetQuery(organization_id=ORGANIZATION_ID))

    assert "Foreign" not in {target.name for target in page.items}


# ------------------------------------------------------------------------ api


def _organization() -> Organization:
    return Organization.model_construct(
        id=ORGANIZATION_ID,
        mist_org_id="org-1",
        name="Lab",
        cloud_region=MistCloudRegion.GLOBAL_01,
        status=OrganizationStatus.VERIFIED,
        encrypted_service_token="v1:encrypted-value",
        service_token_last_four="alue",
    )


def _user(role: UserRole) -> User:
    return User.model_construct(
        id=PydanticObjectId(),
        email=f"{role.value}@example.com",
        display_name=role.value,
        password_hash="unused",
        role=role,
        is_active=True,
        totp=None,
    )


def _default_service() -> RestoreTargetService:
    return _service()


def _app(role: UserRole):
    app = create_app(Settings(environment="test", database_enabled=False))
    app.dependency_overrides[get_current_user] = lambda: _user(role)
    app.dependency_overrides[require_organization] = _organization
    app.dependency_overrides[get_restore_target_service] = _default_service
    return app


async def test_operator_reads_targets_with_facets() -> None:
    transport = httpx.ASGITransport(app=_app(UserRole.OPERATOR))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            f"/api/v1/organizations/{ORGANIZATION_ID}/restores/targets",
            params={"scope": "site", "object_type": "wlans"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 3
    assert payload["types"] == [{"type": "wlans", "count": 3}]
    assert payload["sites"] == [{"id": "site-a", "name": "Alpha"}, {"id": "site-b", "name": "Bravo"}]
    first = payload["items"][0]
    assert set(first) == {
        "logical_object_id",
        "version_id",
        "name",
        "object_type",
        "scope",
        "site_mist_id",
        "site_name",
        "version",
        "observed_at",
    }


async def test_viewer_is_refused_the_target_list() -> None:
    transport = httpx.ASGITransport(app=_app(UserRole.VIEWER))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(f"/api/v1/organizations/{ORGANIZATION_ID}/restores/targets")

    assert response.status_code == 403
