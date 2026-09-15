"""Short-lived Mist mutation client tests."""

import httpx
import pytest
from pytest_httpx import HTTPXMock

from mist_config_guardian_backend.integrations.mist_mutation import (
    MistMutationClient,
    MistMutationError,
    MistMutationStatusError,
    MistMutationTransportError,
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


NETWORKS_URL = "https://api.mist.com/api/v1/orgs/org-1/networks"
NETWORK_URL = f"{NETWORKS_URL}/network-1"


def _networks():
    return next(item for item in ORG_OBJECTS if item.key == "networks")


class _Sleeps:
    """Records every back-off instead of waiting."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


def _client(sleeps: _Sleeps) -> MistMutationClient:
    return MistMutationClient(token="temporary-admin-token", region=MistCloudRegion.GLOBAL_01, sleep=sleeps)


async def test_a_throttled_update_is_retried_after_the_advertised_delay(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="PUT", url=NETWORK_URL, status_code=429, headers={"Retry-After": "7"})
    httpx_mock.add_response(method="PUT", url=NETWORK_URL, json={"id": "network-1"})
    sleeps = _Sleeps()

    async with _client(sleeps) as client:
        result = await client.update(_networks(), "network-1", {"name": "Corp"}, org_id="org-1", site_id=None)

    assert result == {"id": "network-1"}
    assert sleeps.delays == [7.0]


async def test_retry_after_is_capped(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="GET", url=NETWORK_URL, status_code=503, headers={"Retry-After": "600"})
    httpx_mock.add_response(method="GET", url=NETWORK_URL, json={"id": "network-1"})
    sleeps = _Sleeps()

    async with _client(sleeps) as client:
        await client.get_current(_networks(), "network-1", org_id="org-1", site_id=None)

    assert sleeps.delays == [30.0]


@pytest.mark.parametrize("status", [502, 503, 504])
async def test_a_delete_gives_up_after_three_attempts_with_an_unknown_outcome(
    httpx_mock: HTTPXMock, status: int
) -> None:
    for _ in range(3):
        httpx_mock.add_response(method="DELETE", url=NETWORK_URL, status_code=status)
    sleeps = _Sleeps()

    async with _client(sleeps) as client:
        with pytest.raises(MistMutationStatusError) as error:
            await client.delete(_networks(), "network-1", org_id="org-1", site_id=None)

    assert error.value.outcome_unknown is True
    assert error.value.status_code == status
    assert len(httpx_mock.get_requests()) == 3
    assert sleeps.delays == [0.5, 1.0]


async def test_a_create_that_times_out_is_not_retried_and_may_have_happened(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_exception(httpx.ReadTimeout("slow"), method="POST", url=NETWORKS_URL)
    sleeps = _Sleeps()

    async with _client(sleeps) as client:
        with pytest.raises(MistMutationTransportError) as error:
            await client.create(_networks(), {"name": "Corp"}, org_id="org-1", site_id=None)

    assert error.value.outcome_unknown is True
    assert len(httpx_mock.get_requests()) == 1
    assert sleeps.delays == []


async def test_a_create_answered_with_a_server_error_is_not_retried(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="POST", url=NETWORKS_URL, status_code=503)

    async with _client(_Sleeps()) as client:
        with pytest.raises(MistMutationStatusError) as error:
            await client.create(_networks(), {"name": "Corp"}, org_id="org-1", site_id=None)

    assert error.value.outcome_unknown is True
    assert len(httpx_mock.get_requests()) == 1


async def test_a_throttled_create_is_retried_because_mist_did_not_process_it(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="POST", url=NETWORKS_URL, status_code=429)
    httpx_mock.add_response(method="POST", url=NETWORKS_URL, status_code=201, json={"id": "network-1", "name": "Corp"})
    sleeps = _Sleeps()

    async with _client(sleeps) as client:
        created = await client.create(_networks(), {"name": "Corp"}, org_id="org-1", site_id=None)

    assert created["id"] == "network-1"
    assert sleeps.delays == [0.5]


async def test_a_read_that_cannot_reach_mist_is_retried_and_changed_nothing(httpx_mock: HTTPXMock) -> None:
    for _ in range(3):
        httpx_mock.add_exception(httpx.ConnectError("refused"), method="GET", url=NETWORK_URL)

    async with _client(_Sleeps()) as client:
        with pytest.raises(MistMutationTransportError) as error:
            await client.get_current(_networks(), "network-1", org_id="org-1", site_id=None)

    assert error.value.outcome_unknown is False
    assert len(httpx_mock.get_requests()) == 3


def _queue(httpx_mock: HTTPXMock, method: str, steps: list[int | Exception]) -> None:
    """Answer successive requests with a status, or fail them in transport."""
    for step in steps:
        if isinstance(step, Exception):
            httpx_mock.add_exception(step, method=method, url=NETWORK_URL)
        else:
            httpx_mock.add_response(method=method, url=NETWORK_URL, status_code=step)


async def _write(client: MistMutationClient, method: str) -> None:
    """Issue the idempotent write under test."""
    if method == "PUT":
        await client.update(_networks(), "network-1", {"name": "Corp"}, org_id="org-1", site_id=None)
    else:
        await client.delete(_networks(), "network-1", org_id="org-1", site_id=None)


@pytest.mark.parametrize(
    ("steps", "delays"),
    [
        pytest.param([503, 404], [0.5], id="503-404"),
        pytest.param([502, 503, 404], [0.5, 1.0], id="502-503-404"),
        pytest.param([httpx.ReadTimeout("slow"), 404], [0.5], id="timeout-404"),
    ],
)
async def test_a_retried_delete_that_finds_the_object_gone_has_completed(
    httpx_mock: HTTPXMock,
    steps: list[int | Exception],
    delays: list[float],
) -> None:
    _queue(httpx_mock, "DELETE", steps)
    sleeps = _Sleeps()

    async with _client(sleeps) as client:
        await client.delete(_networks(), "network-1", org_id="org-1", site_id=None)

    assert len(httpx_mock.get_requests()) == len(steps)
    assert sleeps.delays == delays


@pytest.mark.parametrize(
    ("method", "steps", "status"),
    [
        pytest.param("PUT", [503, 404], 404, id="put-503-404"),
        pytest.param("PUT", [httpx.ReadTimeout("slow"), 409], 409, id="put-timeout-409"),
        pytest.param("DELETE", [503, 400], 400, id="delete-503-400"),
        pytest.param("PUT", [503, 429, 429], 429, id="put-503-then-throttled-out"),
    ],
)
async def test_a_write_that_fails_after_an_ambiguous_attempt_may_have_been_applied(
    httpx_mock: HTTPXMock,
    method: str,
    steps: list[int | Exception],
    status: int,
) -> None:
    _queue(httpx_mock, method, steps)

    async with _client(_Sleeps()) as client:
        with pytest.raises(MistMutationStatusError) as error:
            await _write(client, method)

    assert error.value.outcome_unknown is True
    assert error.value.status_code == status
    assert len(httpx_mock.get_requests()) == len(steps)


@pytest.mark.parametrize(
    "steps",
    [
        pytest.param([404], id="404"),
        pytest.param([429, 404], id="429-404"),
    ],
)
async def test_a_delete_answered_404_without_an_ambiguous_attempt_is_a_plain_failure(
    httpx_mock: HTTPXMock,
    steps: list[int | Exception],
) -> None:
    _queue(httpx_mock, "DELETE", steps)

    async with _client(_Sleeps()) as client:
        with pytest.raises(MistMutationStatusError) as error:
            await _write(client, "DELETE")

    # A 429 proves Mist did not process the request, so the 404 is the
    # object's real state before this restore touched it.
    assert error.value.outcome_unknown is False
    assert error.value.status_code == 404
    assert len(httpx_mock.get_requests()) == len(steps)


async def test_a_rejected_update_is_not_retried_and_was_not_applied(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="PUT", url=NETWORK_URL, status_code=400, text="sensitive upstream response")

    async with _client(_Sleeps()) as client:
        with pytest.raises(MistMutationStatusError) as error:
            await client.update(_networks(), "network-1", {"name": "Corp"}, org_id="org-1", site_id=None)

    assert error.value.outcome_unknown is False
    assert "sensitive upstream response" not in str(error.value)
    assert len(httpx_mock.get_requests()) == 1
