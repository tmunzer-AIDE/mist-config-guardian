"""Short-lived Mist configuration mutation client."""

from contextlib import AbstractAsyncContextManager
from http import HTTPStatus
from types import TracebackType
from typing import Self, cast

import httpx

from mist_config_guardian_backend.integrations.mist import _REGION_HOSTS
from mist_config_guardian_backend.models.organization import MistCloudRegion
from mist_config_guardian_backend.snapshots.registry import ObjectDefinition


class MistMutationError(RuntimeError):
    """Raised when an authenticated Mist write fails."""


class MistMutationClient(AbstractAsyncContextManager["MistMutationClient"]):
    """Use a freshly verified administrator token for bounded writes."""

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

    async def create(
        self,
        definition: ObjectDefinition,
        configuration: dict[str, object],
        *,
        org_id: str,
        site_id: str | None,
    ) -> dict[str, object]:
        """Create one configuration object."""
        response = await self._client.post(
            definition.path(org_id=org_id, site_id=site_id),
            json=configuration,
        )
        payload = self._response_payload(response, "create", definition.key)
        if not isinstance(payload, dict):
            msg = f"Mist did not return the created {definition.key}"
            raise MistMutationError(msg)
        return cast("dict[str, object]", payload)

    async def get_current(
        self,
        definition: ObjectDefinition,
        object_id: str,
        *,
        org_id: str,
        site_id: str | None,
    ) -> dict[str, object] | None:
        """Read the live object immediately before executing a plan."""
        response = await self._client.get(
            definition.item_path(object_id, org_id=org_id, site_id=site_id),
        )
        if response.status_code == HTTPStatus.NOT_FOUND:
            return None
        payload = self._response_payload(response, "read", definition.key)
        if not isinstance(payload, dict):
            msg = f"Mist did not return the current {definition.key}"
            raise MistMutationError(msg)
        return cast("dict[str, object]", payload)

    async def update(
        self,
        definition: ObjectDefinition,
        object_id: str,
        configuration: dict[str, object],
        *,
        org_id: str,
        site_id: str | None,
    ) -> dict[str, object] | None:
        """Replace one configuration object."""
        response = await self._client.put(
            definition.item_path(object_id, org_id=org_id, site_id=site_id),
            json=configuration,
        )
        payload = self._response_payload(response, "update", definition.key)
        return cast("dict[str, object]", payload) if isinstance(payload, dict) else None

    async def delete(
        self,
        definition: ObjectDefinition,
        object_id: str,
        *,
        org_id: str,
        site_id: str | None,
    ) -> None:
        """Delete one configuration object."""
        response = await self._client.delete(definition.item_path(object_id, org_id=org_id, site_id=site_id))
        self._response_payload(response, "delete", definition.key)

    @staticmethod
    def _response_payload(
        response: httpx.Response,
        action: str,
        object_type: str,
    ) -> object:
        if response.status_code not in {
            HTTPStatus.OK,
            HTTPStatus.CREATED,
            HTTPStatus.ACCEPTED,
            HTTPStatus.NO_CONTENT,
        }:
            msg = f"Mist failed to {action} {object_type} ({response.status_code})"
            raise MistMutationError(msg)
        if response.status_code == HTTPStatus.NO_CONTENT or not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            msg = f"Mist returned invalid JSON after {action} of {object_type}"
            raise MistMutationError(msg) from exc
