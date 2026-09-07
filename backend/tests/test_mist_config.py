"""Read-only Mist configuration client tests."""

from pytest_httpx import HTTPXMock

from mist_config_guardian_backend.integrations.mist_config import MistConfigurationClient
from mist_config_guardian_backend.models.organization import MistCloudRegion
from mist_config_guardian_backend.snapshots.registry import ORG_OBJECTS, SITE_OBJECTS


async def test_fetch_paginates_list_responses(httpx_mock: HTTPXMock) -> None:
    definition = next(item for item in ORG_OBJECTS if item.key == "sites")
    httpx_mock.add_response(
        url="https://api.mist.com/api/v1/orgs/org-1/sites?limit=1000&page=1",
        json=[{"id": "site-1"}],
        headers={"X-Page-Total": "2", "X-Page-Limit": "1"},
    )
    httpx_mock.add_response(
        url="https://api.mist.com/api/v1/orgs/org-1/sites?limit=1000&page=2",
        json=[{"id": "site-2"}],
        headers={"X-Page-Total": "2", "X-Page-Limit": "1"},
    )

    async with MistConfigurationClient(token="read-token", region=MistCloudRegion.GLOBAL_01) as client:
        objects = await client.fetch(definition, org_id="org-1")

    assert objects == [{"id": "site-1"}, {"id": "site-2"}]


async def test_fetch_wraps_singleton_response(httpx_mock: HTTPXMock) -> None:
    definition = next(item for item in SITE_OBJECTS if item.key == "settings")
    httpx_mock.add_response(
        url="https://api.eu.mist.com/api/v1/sites/site-1/setting",
        json={"timezone": "UTC"},
    )

    async with MistConfigurationClient(token="read-token", region=MistCloudRegion.EMEA_01) as client:
        objects = await client.fetch(definition, org_id="org-1", site_id="site-1")

    assert objects == [{"timezone": "UTC"}]


async def test_fetch_retries_transient_mist_error(httpx_mock: HTTPXMock) -> None:
    definition = next(item for item in ORG_OBJECTS if item.key == "networks")
    httpx_mock.add_response(status_code=503)
    httpx_mock.add_response(
        json=[{"id": "network-1", "name": "Corporate"}],
        headers={"X-Page-Total": "1", "X-Page-Limit": "1000"},
    )

    async with MistConfigurationClient(
        token="read-token",
        region=MistCloudRegion.GLOBAL_01,
    ) as client:
        result = await client.fetch(definition, org_id="org-1")

    assert result[0]["id"] == "network-1"
