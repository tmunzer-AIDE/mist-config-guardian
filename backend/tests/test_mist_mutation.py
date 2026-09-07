"""Short-lived Mist mutation client tests."""

import pytest
from pytest_httpx import HTTPXMock

from mist_config_guardian_backend.integrations.mist_mutation import (
    MistMutationClient,
    MistMutationError,
)
from mist_config_guardian_backend.models.organization import MistCloudRegion
from mist_config_guardian_backend.snapshots.registry import ORG_OBJECTS


async def test_create_configuration_uses_admin_token(
    httpx_mock: HTTPXMock,
) -> None:
    definition = next(item for item in ORG_OBJECTS if item.key == "networks")
    httpx_mock.add_response(
        method="POST",
        url="https://api.mist.com/api/v1/orgs/org-1/networks",
        match_headers={"Authorization": "Token temporary-admin-token"},
        match_json={"name": "Corporate"},
        json={"id": "network-1", "name": "Corporate"},
        status_code=201,
    )

    async with MistMutationClient(
        token="temporary-admin-token",
        region=MistCloudRegion.GLOBAL_01,
    ) as client:
        created = await client.create(
            definition,
            {"name": "Corporate"},
            org_id="org-1",
            site_id=None,
        )

    assert created["id"] == "network-1"


async def test_mutation_error_does_not_expose_response_body(
    httpx_mock: HTTPXMock,
) -> None:
    definition = next(item for item in ORG_OBJECTS if item.key == "networks")
    httpx_mock.add_response(
        method="DELETE",
        url="https://api.mist.com/api/v1/orgs/org-1/networks/network-1",
        text="sensitive upstream response",
        status_code=400,
    )

    async with MistMutationClient(
        token="temporary-admin-token",
        region=MistCloudRegion.GLOBAL_01,
    ) as client:
        with pytest.raises(MistMutationError, match=r"\(400\)") as error:
            await client.delete(
                definition,
                "network-1",
                org_id="org-1",
                site_id=None,
            )

    assert "sensitive upstream response" not in str(error.value)


async def test_get_current_returns_none_for_missing_object(
    httpx_mock: HTTPXMock,
) -> None:
    definition = next(item for item in ORG_OBJECTS if item.key == "networks")
    httpx_mock.add_response(
        method="GET",
        url="https://api.mist.com/api/v1/orgs/org-1/networks/network-1",
        status_code=404,
    )

    async with MistMutationClient(
        token="temporary-admin-token",
        region=MistCloudRegion.GLOBAL_01,
    ) as client:
        current = await client.get_current(
            definition,
            "network-1",
            org_id="org-1",
            site_id=None,
        )

    assert current is None
