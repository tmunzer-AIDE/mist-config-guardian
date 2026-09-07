"""Read-only Mist configuration API client."""

import asyncio
from collections.abc import AsyncIterator, Mapping
from contextlib import AbstractAsyncContextManager
from http import HTTPStatus
from types import TracebackType
from typing import Self, cast

import httpx

from mist_config_guardian_backend.integrations.mist import _REGION_HOSTS
from mist_config_guardian_backend.models.organization import MistCloudRegion
from mist_config_guardian_backend.snapshots.registry import ObjectDefinition

_MAX_READ_ATTEMPTS = 3


class MistReadError(RuntimeError):
    """Raised when Mist configuration cannot be read."""


class MistConfigurationClient(AbstractAsyncContextManager["MistConfigurationClient"]):
    """Organization-scoped read-only client with explicit pagination."""

    def __init__(self, *, token: str, region: MistCloudRegion) -> None:
        self._client = httpx.AsyncClient(
            base_url=_REGION_HOSTS[region],
            headers={"Authorization": f"Token {token}"},
            timeout=30,
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self._client.aclose()

    async def fetch(
        self,
        definition: ObjectDefinition,
        *,
        org_id: str,
        site_id: str | None = None,
    ) -> list[dict[str, object]]:
        """Fetch every object for a registry definition."""
        path = definition.path(org_id=org_id, site_id=site_id)
        if not definition.is_list:
            payload = await self._get_json(path, params=dict(definition.request_params))
            if not isinstance(payload, dict):
                msg = f"Mist returned an invalid object for {definition.key}"
                raise MistReadError(msg)
            return [cast("dict[str, object]", payload)]

        return [
            item
            async for item in self._paginate(
                path,
                definition.key,
                request_params=dict(definition.request_params),
                response_items_key=definition.response_items_key,
            )
        ]

    async def _paginate(
        self,
        path: str,
        object_type: str,
        request_params: dict[str, str],
        response_items_key: str | None,
    ) -> AsyncIterator[dict[str, object]]:
        page = 1
        while True:
            params: dict[str, str | int] = {
                **request_params,
                "limit": 1000,
                "page": page,
            }
            response = await self._get(path, params=params)
            payload = self._response_json(response, object_type)
            if response_items_key is not None and isinstance(payload, dict):
                payload = payload.get(response_items_key)
            if not isinstance(payload, list):
                msg = f"Mist returned an invalid list for {object_type}"
                raise MistReadError(msg)
            for item in payload:
                if isinstance(item, dict):
                    yield cast("dict[str, object]", item)

            total = self._integer_header(response, "X-Page-Total")
            limit = self._integer_header(response, "X-Page-Limit") or len(payload)
            if not payload or total is None or page * limit >= total:
                return
            page += 1

    async def _get_json(self, path: str, *, params: dict[str, str]) -> object:
        response = await self._get(path, params=params)
        return self._response_json(response, path)

    async def _get(
        self,
        path: str,
        *,
        params: Mapping[str, str | int],
    ) -> httpx.Response:
        for attempt in range(_MAX_READ_ATTEMPTS):
            try:
                response = await self._client.get(path, params=params)
            except httpx.RequestError as exc:
                if attempt == _MAX_READ_ATTEMPTS - 1:
                    msg = f"Unable to reach Mist while reading {path}"
                    raise MistReadError(msg) from exc
            else:
                if (
                    response.status_code != HTTPStatus.TOO_MANY_REQUESTS
                    and response.status_code < HTTPStatus.INTERNAL_SERVER_ERROR
                ):
                    return response
                if attempt == _MAX_READ_ATTEMPTS - 1:
                    return response
                retry_after = response.headers.get("Retry-After")
                delay = float(retry_after) if retry_after and retry_after.isdigit() else 0.25 * 2**attempt
                await asyncio.sleep(min(delay, 5))
                continue
            await asyncio.sleep(0.25 * 2**attempt)
        msg = f"Unable to read {path} from Mist"
        raise MistReadError(msg)

    @staticmethod
    def _response_json(response: httpx.Response, object_type: str) -> object:
        try:
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError) as exc:
            msg = f"Unable to read {object_type} from Mist"
            raise MistReadError(msg) from exc

    @staticmethod
    def _integer_header(response: httpx.Response, name: str) -> int | None:
        value = response.headers.get(name)
        if value is None:
            return None
        try:
            return int(value)
        except ValueError:
            return None
