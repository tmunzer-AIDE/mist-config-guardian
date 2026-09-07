"""Point-in-time navigation and state reconstruction tests."""

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

import httpx
from beanie import PydanticObjectId

from mist_config_guardian_backend.api.dependencies import get_current_user, require_organization
from mist_config_guardian_backend.api.routes.point_in_time import get_point_in_time_service
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.main import create_app
from mist_config_guardian_backend.models.monitoring import ImpactSeverity
from mist_config_guardian_backend.models.organization import (
    MistCloudRegion,
    Organization,
    OrganizationStatus,
)
from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectVersion, VersionEvent
from mist_config_guardian_backend.models.user import User, UserRole
from mist_config_guardian_backend.models.webhook import (
    AuditChangeGroup,
    ChangedObjectRef,
    RecoveryState,
)
from mist_config_guardian_backend.services.point_in_time import (
    PointInTimeService,
    ReconstructedVersion,
)

ORGANIZATION_ID = PydanticObjectId()
OTHER_ORGANIZATION_ID = PydanticObjectId()
DAY_ONE = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
DAY_TWO = DAY_ONE + timedelta(days=1)
DAY_THREE = DAY_ONE + timedelta(days=2)
SEATTLE = "site-seattle"
PORTLAND = "site-portland"


def _logical(
    *,
    name: str,
    object_type: str = "wlans",
    site: str | None = None,
    is_deleted: bool = False,
    organization_id: PydanticObjectId = ORGANIZATION_ID,
) -> LogicalObject:
    return LogicalObject.model_construct(
        id=PydanticObjectId(),
        organization_id=organization_id,
        scope="site" if site else "org",
        object_type=object_type,
        source_key=name,
        current_mist_id=f"mist-{name}",
        site_mist_id=site,
        name=name,
        is_deleted=is_deleted,
        current_version=1,
        created_at=DAY_ONE,
        updated_at=DAY_ONE,
    )


def _version(
    logical: LogicalObject,
    *,
    version: int,
    observed_at: datetime,
    is_deleted: bool = False,
) -> ObjectVersion:
    return ObjectVersion.model_construct(
        id=PydanticObjectId(),
        organization_id=logical.organization_id,
        logical_object_id=logical.id,
        incarnation_id=PydanticObjectId(),
        snapshot_id=None,
        version=version,
        event=VersionEvent.DELETED if is_deleted else VersionEvent.UPDATED,
        configuration={"name": logical.name, "psk": {"$encrypted": "v1:cipher"}},
        configuration_hash=f"hash-{version}",
        changed_fields=[],
        references=[],
        is_deleted=is_deleted,
        observed_at=observed_at,
        actor="j.mercer",
        audit_id="audit-1",
    )


def _group(*, audit_id: str, occurred_at: datetime, severity: ImpactSeverity) -> AuditChangeGroup:
    return AuditChangeGroup.model_construct(
        id=PydanticObjectId(),
        organization_id=ORGANIZATION_ID,
        audit_id=audit_id,
        actor="j.mercer",
        method="PUT",
        message="modify wlan",
        occurred_at=occurred_at,
        receipt_ids=[],
        affected_site_ids=[SEATTLE],
        affected_object_ids=[],
        changed_objects=[
            ChangedObjectRef(
                logical_object_id=PydanticObjectId(),
                object_type="gatewaytemplates",
                object_name="NW-Edge-Standard",
                scope="org",
                event="updated",
            )
        ],
        affected_devices=[],
        monitoring_session_ids=[],
        impact_severity=severity,
        recovery_state=RecoveryState.NOT_APPLICABLE,
        degraded_metrics=[],
        evidence=[],
        summary="",
        created_at=occurred_at,
        updated_at=occurred_at,
    )


class _MemoryPointInTimeReader:
    """Reader double that reconstructs from an in-memory version history."""

    def __init__(self) -> None:
        self.groups: list[AuditChangeGroup] = []
        self.logicals: list[LogicalObject] = []
        self.versions: list[ObjectVersion] = []

    async def markers(
        self,
        organization_id: PydanticObjectId,
        *,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> list[AuditChangeGroup]:
        matched = [
            group
            for group in self.groups
            if group.organization_id == organization_id
            and group.occurred_at is not None
            and start <= group.occurred_at <= end
        ]
        matched.sort(key=lambda group: group.occurred_at or start)
        return matched[:limit]

    async def logical_object(
        self,
        organization_id: PydanticObjectId,
        logical_object_id: PydanticObjectId,
    ) -> LogicalObject | None:
        return next(
            (
                logical
                for logical in self.logicals
                if logical.organization_id == organization_id and logical.id == logical_object_id
            ),
            None,
        )

    async def version_at(
        self,
        organization_id: PydanticObjectId,
        logical_object_id: PydanticObjectId,
        at: datetime,
    ) -> ObjectVersion | None:
        candidates = [
            version
            for version in self.versions
            if version.organization_id == organization_id
            and version.logical_object_id == logical_object_id
            and version.observed_at <= at
        ]
        return max(candidates, key=lambda version: version.version, default=None)

    async def scope_objects(
        self,
        organization_id: PydanticObjectId,
        *,
        site_id: str | None,
        limit: int,
    ) -> list[LogicalObject]:
        matched = [
            logical
            for logical in self.logicals
            if logical.organization_id == organization_id and (site_id is None or logical.site_mist_id == site_id)
        ]
        return matched[:limit]

    async def versions_at(
        self,
        organization_id: PydanticObjectId,
        logical_object_ids: Sequence[PydanticObjectId],
        at: datetime,
    ) -> list[ReconstructedVersion]:
        wanted = set(logical_object_ids)
        newest: dict[PydanticObjectId, ObjectVersion] = {}
        for version in self.versions:
            if (
                version.organization_id != organization_id
                or version.logical_object_id not in wanted
                or version.observed_at > at
            ):
                continue
            current = newest.get(version.logical_object_id)
            if current is None or version.version > current.version:
                newest[version.logical_object_id] = version
        return [
            ReconstructedVersion(
                logical_object_id=version.logical_object_id,
                version_id=version.id,
                version=version.version,
                is_deleted=version.is_deleted,
            )
            for version in newest.values()
            if not version.is_deleted
        ]


def _history() -> _MemoryPointInTimeReader:
    """A three-day history exercising creation, deletion, and survival."""
    reader = _MemoryPointInTimeReader()
    survivor = _logical(name="NW-Corp", site=SEATTLE)
    deleted_later = _logical(name="NW-Legacy", site=SEATTLE, is_deleted=True)
    born_later = _logical(name="NW-Guest", site=SEATTLE)
    elsewhere = _logical(name="PDX-Corp", site=PORTLAND)
    reader.logicals.extend([survivor, deleted_later, born_later, elsewhere])
    reader.versions.extend(
        [
            _version(survivor, version=1, observed_at=DAY_ONE),
            _version(survivor, version=2, observed_at=DAY_THREE),
            _version(deleted_later, version=1, observed_at=DAY_ONE),
            _version(deleted_later, version=2, observed_at=DAY_THREE, is_deleted=True),
            _version(born_later, version=1, observed_at=DAY_THREE),
            _version(elsewhere, version=1, observed_at=DAY_ONE),
        ]
    )
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


# ------------------------------------------------------------------- markers


async def test_markers_carry_the_time_severity_and_templated_label() -> None:
    reader = _MemoryPointInTimeReader()
    now = datetime.now(tz=UTC)
    reader.groups.extend(
        [
            _group(
                audit_id="critical",
                occurred_at=now - timedelta(hours=2),
                severity=ImpactSeverity.CRITICAL,
            ),
            _group(
                audit_id="quiet",
                occurred_at=now - timedelta(hours=1),
                severity=ImpactSeverity.NONE,
            ),
        ]
    )

    markers = await PointInTimeService(reader).markers(ORGANIZATION_ID, range_key="24h")

    assert [item.severity for item in markers.items] == [ImpactSeverity.CRITICAL, ImpactSeverity.NONE]
    assert markers.items[0].label == "Gateway template updated · NW-Edge-Standard"
    assert markers.items[0].change_group_id == str(reader.groups[0].id)
    assert markers.range_start < markers.range_end


async def test_markers_respect_the_range_and_the_as_of_instant() -> None:
    reader = _MemoryPointInTimeReader()
    now = datetime.now(tz=UTC)
    reader.groups.extend(
        [
            _group(audit_id="old", occurred_at=now - timedelta(days=5), severity=ImpactSeverity.NONE),
            _group(audit_id="recent", occurred_at=now - timedelta(hours=2), severity=ImpactSeverity.NONE),
        ]
    )
    service = PointInTimeService(reader)

    day = await service.markers(ORGANIZATION_ID, range_key="24h")
    week = await service.markers(ORGANIZATION_ID, range_key="7d")
    historical = await service.markers(
        ORGANIZATION_ID,
        range_key="24h",
        as_of=now - timedelta(days=4),
    )

    assert len(day.items) == 1
    assert len(week.items) == 2
    assert len(historical.items) == 1
    assert historical.range_end == now - timedelta(days=4)


async def test_markers_never_cross_organizations() -> None:
    reader = _MemoryPointInTimeReader()
    reader.groups.append(
        _group(
            audit_id="mine",
            occurred_at=datetime.now(tz=UTC) - timedelta(hours=1),
            severity=ImpactSeverity.NONE,
        )
    )

    markers = await PointInTimeService(reader).markers(OTHER_ORGANIZATION_ID, range_key="24h")

    assert markers.items == []


# ------------------------------------------------------------ reconstruction


async def test_state_excludes_objects_tombstoned_before_the_instant() -> None:
    reader = _history()

    state = await PointInTimeService(reader).state_at(ORGANIZATION_ID, at=DAY_THREE + timedelta(hours=1))

    assert [item.name for item in state.objects] == ["NW-Corp", "NW-Guest", "PDX-Corp"]
    assert state.object_count == 3


async def test_state_includes_objects_that_were_deleted_after_the_instant() -> None:
    reader = _history()

    state = await PointInTimeService(reader).state_at(ORGANIZATION_ID, at=DAY_TWO)

    names = {item.name: item for item in state.objects}
    assert set(names) == {"NW-Corp", "NW-Legacy", "PDX-Corp"}
    assert names["NW-Corp"].version == 1
    # The object existed then, and today it is gone; the browser marks it.
    assert names["NW-Legacy"].is_deleted is True
    assert names["NW-Corp"].is_deleted is False


async def test_state_excludes_objects_that_did_not_exist_yet() -> None:
    reader = _history()

    state = await PointInTimeService(reader).state_at(ORGANIZATION_ID, at=DAY_ONE - timedelta(hours=1))

    assert state.objects == []
    assert state.object_count == 0


async def test_state_narrows_to_one_site() -> None:
    reader = _history()

    state = await PointInTimeService(reader).state_at(
        ORGANIZATION_ID,
        at=DAY_TWO,
        scope="site",
        site_id=PORTLAND,
    )

    assert state.scope == "site"
    assert [item.name for item in state.objects] == ["PDX-Corp"]


async def test_state_never_crosses_organizations() -> None:
    reader = _history()

    state = await PointInTimeService(reader).state_at(OTHER_ORGANIZATION_ID, at=DAY_THREE)

    assert state.objects == []


async def test_object_at_returns_the_newest_version_before_the_instant() -> None:
    reader = _history()
    survivor = reader.logicals[0]
    assert survivor.id is not None

    early = await PointInTimeService(reader).object_at(ORGANIZATION_ID, survivor.id, DAY_TWO)
    late = await PointInTimeService(reader).object_at(ORGANIZATION_ID, survivor.id, DAY_THREE)

    assert early is not None
    assert early.version == 1
    assert late is not None
    assert late.version == 2


async def test_object_at_reports_nothing_for_an_object_that_did_not_exist() -> None:
    reader = _history()
    born_later = reader.logicals[2]
    tombstoned = reader.logicals[1]
    assert born_later.id is not None
    assert tombstoned.id is not None
    service = PointInTimeService(reader)

    assert await service.object_at(ORGANIZATION_ID, born_later.id, DAY_TWO) is None
    assert await service.object_at(ORGANIZATION_ID, tombstoned.id, DAY_THREE) is None
    assert await service.object_at(OTHER_ORGANIZATION_ID, born_later.id, DAY_THREE) is None


# ----------------------------------------------------------------------- api


def _app(
    service: PointInTimeService,
    *,
    organization_id: PydanticObjectId = ORGANIZATION_ID,
) -> object:
    app = create_app(Settings(environment="test", database_enabled=False))
    app.dependency_overrides[get_current_user] = _viewer
    app.dependency_overrides[require_organization] = lambda: _organization(organization_id)
    app.dependency_overrides[get_point_in_time_service] = lambda: service
    return app


async def test_markers_endpoint_returns_the_contract() -> None:
    reader = _MemoryPointInTimeReader()
    reader.groups.append(
        _group(
            audit_id="critical",
            occurred_at=datetime.now(tz=UTC) - timedelta(hours=1),
            severity=ImpactSeverity.CRITICAL,
        )
    )
    app = _app(PointInTimeService(reader))

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(
            f"/api/v1/organizations/{ORGANIZATION_ID}/point-in-time/markers",
            params={"range": "24h"},
        )

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"items", "range_start", "range_end"}
    assert set(body["items"][0]) == {"at", "severity", "change_group_id", "label"}


async def test_mode_endpoint_reads_the_as_of_header() -> None:
    app = _app(PointInTimeService(_MemoryPointInTimeReader()))
    path = f"/api/v1/organizations/{ORGANIZATION_ID}/point-in-time/mode"

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        live = await client.get(path)
        historical = await client.get(
            path,
            headers={"X-Config-Guardian-As-Of": "2026-09-02T12:00:00Z"},
        )

    assert live.json() == {"historical": False, "as_of": None}
    assert historical.json()["historical"] is True
    assert historical.json()["as_of"].startswith("2026-09-02T12:00:00")


async def test_state_endpoint_requires_a_site_for_site_scope() -> None:
    app = _app(PointInTimeService(_history()))

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(
            f"/api/v1/organizations/{ORGANIZATION_ID}/point-in-time/state",
            params={"at": DAY_TWO.isoformat(), "scope": "site"},
        )

    assert response.status_code == 422


async def test_state_endpoint_requires_an_instant() -> None:
    app = _app(PointInTimeService(_history()))

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(f"/api/v1/organizations/{ORGANIZATION_ID}/point-in-time/state")

    assert response.status_code == 422


async def test_object_endpoint_redacts_secrets_and_404s_outside_the_lifetime() -> None:
    reader = _history()
    survivor = reader.logicals[0]
    born_later = reader.logicals[2]
    assert survivor.id is not None
    assert born_later.id is not None
    app = _app(PointInTimeService(reader))
    base = f"/api/v1/organizations/{ORGANIZATION_ID}/point-in-time/objects"

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        found = await client.get(f"{base}/{survivor.id}", params={"at": DAY_TWO.isoformat()})
        missing = await client.get(f"{base}/{born_later.id}", params={"at": DAY_TWO.isoformat()})

    assert found.status_code == 200
    assert found.json()["configuration"]["psk"] == "********"
    assert missing.status_code == 404


async def test_object_endpoint_falls_back_to_the_as_of_header() -> None:
    reader = _history()
    survivor = reader.logicals[0]
    assert survivor.id is not None
    app = _app(PointInTimeService(reader))
    path = f"/api/v1/organizations/{ORGANIZATION_ID}/point-in-time/objects/{survivor.id}"

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        historical = await client.get(path, headers={"X-Config-Guardian-As-Of": DAY_TWO.isoformat()})
        live = await client.get(path)

    assert historical.json()["version"] == 1
    assert live.json()["version"] == 2
