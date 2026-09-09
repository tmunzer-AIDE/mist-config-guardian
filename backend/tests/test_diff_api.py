"""Deterministic diff API tests."""

import json
from datetime import UTC, datetime

import httpx
from beanie import PydanticObjectId

from mist_config_guardian_backend.api.dependencies import require_organization
from mist_config_guardian_backend.api.routes.diff import get_version_repository
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.main import create_app
from mist_config_guardian_backend.models.organization import (
    MistCloudRegion,
    Organization,
    OrganizationStatus,
)
from mist_config_guardian_backend.models.snapshot import ObjectVersion, VersionEvent

ORGANIZATION_ID = PydanticObjectId()
BEFORE_ID = PydanticObjectId()
AFTER_ID = PydanticObjectId()
FOREIGN_ID = PydanticObjectId()


def _organization() -> Organization:
    return Organization.model_construct(
        id=ORGANIZATION_ID,
        mist_org_id="org-1",
        name="Lab",
        cloud_region=MistCloudRegion.GLOBAL_01,
        status=OrganizationStatus.VERIFIED,
    )


def _version(version_id: PydanticObjectId, version: int, configuration: dict[str, object]) -> ObjectVersion:
    return ObjectVersion.model_construct(
        id=version_id,
        organization_id=ORGANIZATION_ID,
        logical_object_id=PydanticObjectId(),
        incarnation_id=PydanticObjectId(),
        version=version,
        event=VersionEvent.UPDATED,
        configuration=configuration,
        configuration_hash=f"hash-{version}",
        changed_fields=[],
        references=[],
        is_deleted=False,
        observed_at=datetime(2026, 9, 7, 9, 12, tzinfo=UTC),
        actor="j.mercer",
        audit_id=None,
    )


_BEFORE = {
    "name": "NW-Corp",
    "band_5": {"power_max": 17, "channels": [36, 40]},
    "psk": {"$encrypted": "v1:secret-ciphertext"},
    "description": "old",
}
_AFTER = {
    "name": "NW-Corp",
    "band_5": {"power_max": 11, "channels": [36, 40]},
    "psk": {"$encrypted": "v1:rotated-ciphertext"},
    "description": "new",
}


class _FakeVersionRepository:
    def __init__(self, versions: dict[PydanticObjectId, ObjectVersion]) -> None:
        self._versions = versions

    async def load(
        self,
        organization_id: PydanticObjectId,
        version_id: PydanticObjectId,
    ) -> ObjectVersion | None:
        version = self._versions.get(version_id)
        if version is None or version.organization_id != organization_id:
            return None
        return version


def _client_app() -> tuple[object, _FakeVersionRepository]:
    app = create_app(Settings(environment="test", database_enabled=False))
    repository = _FakeVersionRepository(
        {
            BEFORE_ID: _version(BEFORE_ID, 14, _BEFORE),
            AFTER_ID: _version(AFTER_ID, 15, _AFTER),
        }
    )
    app.dependency_overrides[require_organization] = _organization
    app.dependency_overrides[get_version_repository] = lambda: repository
    return app, repository


def _url(path: str = "") -> str:
    return f"/api/v1/organizations/{ORGANIZATION_ID}/diff{path}"


async def test_compare_versions_returns_structured_secret_safe_diff() -> None:
    app, _repository = _client_app()

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(
            _url(),
            params={"from_version_id": str(BEFORE_ID), "to_version_id": str(AFTER_ID)},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["counts"] == {"changed": 3, "added": 0, "modified": 3, "removed": 0}
    assert payload["summary"] == "3 fields changed · 0 added · 3 modified · 0 removed"
    assert payload["mode"] == "chips"
    assert payload["from_version"]["version"] == 14
    assert payload["to_version"]["version"] == 15
    assert payload["to_version"]["actor"] == "j.mercer"
    fields = {entry["field"] for entry in payload["entries"]}
    assert fields == {"band_5.power_max", "psk", "description"}
    assert "secret-ciphertext" not in response.text
    assert "$encrypted" not in response.text


async def test_compare_versions_supports_metadata_only_and_section_filter() -> None:
    app, _repository = _client_app()

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        metadata = await client.get(
            _url(),
            params={
                "from_version_id": str(BEFORE_ID),
                "to_version_id": str(AFTER_ID),
                "include_entries": "false",
            },
        )
        filtered = await client.get(
            _url(),
            params={
                "from_version_id": str(BEFORE_ID),
                "to_version_id": str(AFTER_ID),
                "sections": "band_5",
            },
        )

    assert metadata.status_code == 200
    body = metadata.json()
    assert body["entries_included"] is False
    assert body["counts"]["changed"] == 3
    assert all(section["entries"] == [] for section in body["sections"])
    assert {section["key"]: section["counts"]["changed"] for section in body["sections"]} == {
        "band_5": 1,
        "psk": 1,
        "description": 1,
    }

    assert filtered.status_code == 200
    sections = {section["key"]: section for section in filtered.json()["sections"]}
    assert sections["band_5"]["entries_included"] is True
    assert len(sections["band_5"]["entries"]) == 1
    assert sections["description"]["entries_included"] is False


async def test_compare_versions_rejects_unknown_or_foreign_versions() -> None:
    app, _repository = _client_app()

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(
            _url(),
            params={"from_version_id": str(BEFORE_ID), "to_version_id": str(FOREIGN_ID)},
        )

    assert response.status_code == 404
    assert response.json()["detail"] == "Version not found for this organization"


async def test_raw_diff_returns_redacted_documents_and_line_count() -> None:
    app, _repository = _client_app()

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(
            _url("/raw"),
            params={"from_version_id": str(BEFORE_ID), "to_version_id": str(AFTER_ID)},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["before"]["psk"] == "********"
    assert payload["after"]["psk"] == "********"
    assert payload["line_count"] > 0
    assert "ciphertext" not in response.text


async def test_export_returns_structured_json_download() -> None:
    app, _repository = _client_app()

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(
            _url("/export"),
            params={
                "from_version_id": str(BEFORE_ID),
                "to_version_id": str(AFTER_ID),
                "format": "json",
            },
        )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert f'filename="diff-{BEFORE_ID}-{AFTER_ID}.json"' in response.headers["content-disposition"]
    assert json.loads(response.text)["counts"]["changed"] == 3


async def test_export_returns_json_patch_download() -> None:
    app, _repository = _client_app()

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(
            _url("/export"),
            params={
                "from_version_id": str(BEFORE_ID),
                "to_version_id": str(AFTER_ID),
                "format": "patch",
            },
        )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json-patch+json")
    assert f'filename="diff-{BEFORE_ID}-{AFTER_ID}.patch.json"' in response.headers["content-disposition"]
    patch = json.loads(response.text)
    assert {"op": "replace", "path": "/band_5/power_max", "value": 11} in patch
    assert {"op": "replace", "path": "/description", "value": "new"} in patch
    assert "ciphertext" not in response.text


async def test_diff_requires_authentication() -> None:
    app = create_app(Settings(environment="test", database_enabled=False))

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(
            _url(),
            params={"from_version_id": str(BEFORE_ID), "to_version_id": str(AFTER_ID)},
        )

    assert response.status_code == 401
