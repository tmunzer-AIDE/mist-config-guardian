"""Mist credential verification tests."""

import pytest
from pytest_httpx import HTTPXMock

from mist_config_guardian_backend.integrations.mist import (
    MistAccessMode,
    MistVerificationError,
    MistVerificationService,
)
from mist_config_guardian_backend.models.organization import MistCloudRegion


@pytest.mark.parametrize("role", ["read", "viewer", "readonly", "read_only"])
async def test_verify_accepts_read_only_roles(httpx_mock: HTTPXMock, role: str) -> None:
    httpx_mock.add_response(
        url="https://api.mist.com/api/v1/self",
        json={
            "privileges": [
                {"org_id": "org-1", "org_name": "Lab", "scope": "org", "role": role},
            ]
        },
    )

    access = await MistVerificationService().verify_read_only_token(
        token="token",
        region=MistCloudRegion.GLOBAL_01,
    )

    assert access.org_name == "Lab"
    assert access.org_id == "org-1"
    assert access.access_mode is MistAccessMode.READ_ONLY


async def test_verify_rejects_write_token(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url="https://api.mist.com/api/v1/self",
        json={"privileges": [{"org_id": "org-1", "scope": "org", "role": "admin"}]},
    )

    with pytest.raises(MistVerificationError, match="must be read-only"):
        await MistVerificationService().verify_read_only_token(
            token="token",
            region=MistCloudRegion.GLOBAL_01,
        )


async def test_verify_rejects_missing_organization(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(url="https://api.eu.mist.com/api/v1/self", json={"privileges": []})

    with pytest.raises(MistVerificationError, match="exactly one organization"):
        await MistVerificationService().verify_read_only_token(
            token="token",
            region=MistCloudRegion.EMEA_01,
        )


async def test_verify_rejects_token_with_multiple_organizations(
    httpx_mock: HTTPXMock,
) -> None:
    httpx_mock.add_response(
        url="https://api.gc7.mist.com/api/v1/self",
        json={
            "privileges": [
                {"org_id": "org-1", "scope": "org", "role": "read"},
                {"org_id": "org-2", "scope": "org", "role": "read"},
            ]
        },
    )

    with pytest.raises(MistVerificationError, match="exactly one organization"):
        await MistVerificationService().verify_read_only_token(
            token="token",
            region=MistCloudRegion.APAC_03,
        )


async def test_verify_routes_to_selected_cloud(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url="https://api.ac6.mist.com/api/v1/self",
        json={
            "privileges": [
                {"org_id": "org-1", "scope": "org", "role": "read"},
            ]
        },
    )

    await MistVerificationService().verify_read_only_token(
        token="token",
        region=MistCloudRegion.EMEA_03,
    )


async def test_verify_write_token_accepts_admin_and_returns_actor(
    httpx_mock: HTTPXMock,
) -> None:
    httpx_mock.add_response(
        url="https://api.mist.com/api/v1/self",
        json={
            "email": "mist-admin@example.com",
            "privileges": [{"org_id": "org-1", "scope": "org", "role": "admin"}],
        },
    )

    access = await MistVerificationService().verify_write_token(
        token="temporary-admin-token",
        org_id="org-1",
        region=MistCloudRegion.GLOBAL_01,
    )

    assert access.access_mode is MistAccessMode.WRITE
    assert access.actor == "mist-admin@example.com"


async def test_verify_write_token_rejects_read_only_role(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url="https://api.mist.com/api/v1/self",
        json={"privileges": [{"org_id": "org-1", "scope": "org", "role": "read"}]},
    )

    with pytest.raises(MistVerificationError, match="write access is required"):
        await MistVerificationService().verify_write_token(
            token="read-token",
            org_id="org-1",
            region=MistCloudRegion.GLOBAL_01,
        )
