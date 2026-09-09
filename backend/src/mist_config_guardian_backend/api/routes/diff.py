"""Deterministic structured configuration comparison endpoints."""

import json
from typing import Annotated, Literal

from beanie import PydanticObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field

from mist_config_guardian_backend.api.dependencies import require_organization
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.snapshot import ObjectVersion
from mist_config_guardian_backend.schemas.diff import (
    ConfigurationDiff,
    DiffVersionRef,
    RawConfigurationDiff,
)
from mist_config_guardian_backend.services.diff import (
    build_json_patch,
    count_document_lines,
    diff_configurations,
    redact_document,
)

router = APIRouter(prefix="/organizations/{organization_id}/diff")

_JSON_PATCH_MEDIA_TYPE = "application/json-patch+json"


class VersionRepository:
    """Load immutable versions scoped to one organization."""

    async def load(
        self,
        organization_id: PydanticObjectId,
        version_id: PydanticObjectId,
    ) -> ObjectVersion | None:
        """Return a version only when it belongs to the given organization."""
        return await ObjectVersion.find_one(
            ObjectVersion.id == version_id,
            ObjectVersion.organization_id == organization_id,
        )


def get_version_repository() -> VersionRepository:
    """Build the organization-scoped version repository."""
    return VersionRepository()


class DiffQuery(BaseModel):
    """Version selection and lazy-section options."""

    from_version_id: PydanticObjectId
    to_version_id: PydanticObjectId
    sections: str | None = Field(default=None, max_length=1024)
    include_entries: bool = True

    @property
    def section_keys(self) -> list[str] | None:
        """Return the requested section filter, if any."""
        if self.sections is None:
            return None
        return [part.strip() for part in self.sections.split(",") if part.strip()]


class RawDiffQuery(BaseModel):
    """Version selection for the raw side-by-side view."""

    from_version_id: PydanticObjectId
    to_version_id: PydanticObjectId


class DiffExportQuery(RawDiffQuery):
    """Version selection and export encoding."""

    export_format: Literal["json", "patch"] = Field(default="json", alias="format")


async def load_version_pair(
    repository: VersionRepository,
    organization_id: PydanticObjectId,
    from_version_id: PydanticObjectId,
    to_version_id: PydanticObjectId,
) -> tuple[ObjectVersion, ObjectVersion]:
    """Load both compared versions, or fail with 404."""
    before = await repository.load(organization_id, from_version_id)
    after = await repository.load(organization_id, to_version_id)
    if before is None or after is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Version not found for this organization",
        )
    return before, after


@router.get("")
async def compare_versions(
    organization_id: PydanticObjectId,
    _organization: Annotated[Organization, Depends(require_organization)],
    repository: Annotated[VersionRepository, Depends(get_version_repository)],
    query: Annotated[DiffQuery, Query()],
) -> ConfigurationDiff:
    """Return the deterministic, secret-safe diff between two versions."""
    before, after = await load_version_pair(
        repository,
        organization_id,
        query.from_version_id,
        query.to_version_id,
    )
    diff = diff_configurations(
        before.configuration,
        after.configuration,
        include_entries=query.include_entries,
        sections=query.section_keys,
    )
    diff.from_version = DiffVersionRef.from_document(before)
    diff.to_version = DiffVersionRef.from_document(after)
    return diff


@router.get("/raw")
async def compare_versions_raw(
    organization_id: PydanticObjectId,
    _organization: Annotated[Organization, Depends(require_organization)],
    repository: Annotated[VersionRepository, Depends(get_version_repository)],
    query: Annotated[RawDiffQuery, Query()],
) -> RawConfigurationDiff:
    """Return both redacted documents for the raw side-by-side view."""
    before, after = await load_version_pair(
        repository,
        organization_id,
        query.from_version_id,
        query.to_version_id,
    )
    return RawConfigurationDiff(
        before=redact_document(before.configuration),
        after=redact_document(after.configuration),
        line_count=count_document_lines(before.configuration, after.configuration),
        from_version=DiffVersionRef.from_document(before),
        to_version=DiffVersionRef.from_document(after),
    )


@router.get("/export")
async def export_diff(
    organization_id: PydanticObjectId,
    _organization: Annotated[Organization, Depends(require_organization)],
    repository: Annotated[VersionRepository, Depends(get_version_repository)],
    query: Annotated[DiffExportQuery, Query()],
) -> Response:
    """Return a downloadable structured diff or RFC 6902 JSON Patch."""
    before, after = await load_version_pair(
        repository,
        organization_id,
        query.from_version_id,
        query.to_version_id,
    )
    stem = f"diff-{query.from_version_id}-{query.to_version_id}"
    if query.export_format == "patch":
        payload = build_json_patch(before.configuration, after.configuration)
        return _download(json.dumps(payload, indent=2), f"{stem}.patch.json", _JSON_PATCH_MEDIA_TYPE)
    diff = diff_configurations(before.configuration, after.configuration)
    diff.from_version = DiffVersionRef.from_document(before)
    diff.to_version = DiffVersionRef.from_document(after)
    return _download(diff.model_dump_json(indent=2), f"{stem}.json", "application/json")


def _download(body: str, filename: str, media_type: str) -> Response:
    return Response(
        content=body,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
