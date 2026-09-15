"""Short-lived Mist configuration mutation client."""

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from http import HTTPStatus
from types import TracebackType
from typing import Literal, Self, cast

import httpx

from mist_config_guardian_backend.integrations.mist import REGION_HOSTS
from mist_config_guardian_backend.integrations.mist_session import SESSION_PREFIX, credential_headers, logout_session
from mist_config_guardian_backend.models.organization import MistCloudRegion
from mist_config_guardian_backend.snapshots.registry import ObjectDefinition

MAX_ATTEMPTS = 3
BACKOFF_BASE_SECONDS = 0.5
RETRY_AFTER_CAP_SECONDS = 30.0

_RETRYABLE_STATUSES = frozenset(
    {
        HTTPStatus.TOO_MANY_REQUESTS,
        HTTPStatus.BAD_GATEWAY,
        HTTPStatus.SERVICE_UNAVAILABLE,
        HTTPStatus.GATEWAY_TIMEOUT,
    }
)
_SUCCESS_STATUSES = frozenset({HTTPStatus.OK, HTTPStatus.CREATED, HTTPStatus.ACCEPTED, HTTPStatus.NO_CONTENT})

Method = Literal["GET", "POST", "PUT", "DELETE"]


class MistMutationError(RuntimeError):
    """Raised when an authenticated Mist read or write fails.

    ``outcome_unknown`` is the one fact the executor cannot recover on its own:
    whether a write Mist never confirmed may nevertheless have been applied. It
    is true only for writes that failed in transport, were answered with a
    server error, succeeded with an unreadable body, or failed after an earlier
    attempt of the same write ended in one of those ways.
    """

    def __init__(self, message: str, *, outcome_unknown: bool = False, status_code: int | None = None) -> None:
        super().__init__(message)
        self.outcome_unknown = outcome_unknown
        self.status_code = status_code


class MistMutationStatusError(MistMutationError):
    """Mist answered with a status the request did not succeed with."""


class MistMutationTransportError(MistMutationError):
    """The request never produced an answer this client could use."""


@dataclass(frozen=True)
class _Sent:
    """The final answer to a request, and whether an earlier attempt may already have applied it.

    A retried write whose first attempt timed out or hit a gateway error may
    have reached Mist, so the final answer alone no longer says what Mist holds.
    """

    response: httpx.Response
    ambiguous: bool = False


def _backoff(attempt: int) -> float:
    """Compute the exponential back-off delay before retry number ``attempt``."""
    return BACKOFF_BASE_SECONDS * 2 ** (attempt - 1)


def _retry_delay(response: httpx.Response, attempt: int) -> float:
    """Prefer Mist's advertised `Retry-After`, capped, over our own back-off."""
    advertised = response.headers.get("Retry-After", "")
    if advertised.isdigit():
        return min(float(advertised), RETRY_AFTER_CAP_SECONDS)
    return _backoff(attempt)


class MistMutationClient(AbstractAsyncContextManager["MistMutationClient"]):
    """Use a freshly verified administrator token for bounded writes."""

    def __init__(
        self,
        *,
        token: str,
        region: MistCloudRegion,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._session = token.startswith(SESSION_PREFIX)
        self._sleep = sleep
        self._client = httpx.AsyncClient(
            base_url=REGION_HOSTS[region],
            headers=credential_headers(token),
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
        if self._session:
            await logout_session(self._client)
        await self._client.aclose()

    async def close_transport(self) -> None:
        """Close the HTTP transport while a caller retains ownership of the session."""
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
        sent = await self._send(
            "POST",
            definition.path(org_id=org_id, site_id=site_id),
            action="create",
            object_type=definition.key,
            json=configuration,
        )
        payload = self._response_payload(sent.response, "create", definition.key, write=True, ambiguous=sent.ambiguous)
        if not isinstance(payload, dict):
            msg = f"Mist did not return the created {definition.key}"
            raise MistMutationError(msg, outcome_unknown=True)
        return cast("dict[str, object]", payload)

    async def get_current(
        self,
        definition: ObjectDefinition,
        object_id: str,
        *,
        org_id: str,
        site_id: str | None,
    ) -> dict[str, object] | None:
        """Read one live object; ``None`` when Mist says it does not exist."""
        sent = await self._send(
            "GET",
            definition.item_path(object_id, org_id=org_id, site_id=site_id),
            action="read",
            object_type=definition.key,
        )
        if sent.response.status_code == HTTPStatus.NOT_FOUND:
            return None
        payload = self._response_payload(sent.response, "read", definition.key, write=False)
        if not isinstance(payload, dict):
            msg = f"Mist did not return the current {definition.key}"
            raise MistMutationError(msg)
        return cast("dict[str, object]", payload)

    async def list_objects(
        self,
        definition: ObjectDefinition,
        *,
        org_id: str,
        site_id: str | None,
    ) -> list[dict[str, object]]:
        """List every live object of one type at one scope.

        Paged and filtered exactly as the collector reads the same type, so a
        restore sees what a backup would: an object on a later page, or behind a
        response envelope, is still there.
        """
        path = definition.path(org_id=org_id, site_id=site_id)
        items: list[dict[str, object]] = []
        page = 1
        while True:
            params: dict[str, str | int] = {**dict(definition.request_params), "limit": 1000, "page": page}
            sent = await self._send("GET", path, action="list", object_type=definition.key, params=params)
            payload = self._response_payload(sent.response, "list", definition.key, write=False)
            if definition.response_items_key is not None and isinstance(payload, dict):
                payload = payload.get(definition.response_items_key)
            if not isinstance(payload, list):
                msg = f"Mist returned an invalid list for {definition.key}"
                raise MistMutationError(msg)
            items.extend(cast("dict[str, object]", item) for item in payload if isinstance(item, dict))
            total = self._integer_header(sent.response, "X-Page-Total")
            limit = self._integer_header(sent.response, "X-Page-Limit") or len(payload)
            if not payload or total is None or page * limit >= total:
                return items
            page += 1

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
        sent = await self._send(
            "PUT",
            definition.item_path(object_id, org_id=org_id, site_id=site_id),
            action="update",
            object_type=definition.key,
            json=configuration,
        )
        payload = self._response_payload(sent.response, "update", definition.key, write=True, ambiguous=sent.ambiguous)
        return cast("dict[str, object]", payload) if isinstance(payload, dict) else None

    async def delete(
        self,
        definition: ObjectDefinition,
        object_id: str,
        *,
        org_id: str,
        site_id: str | None,
    ) -> None:
        """Delete one configuration object.

        A retry answered ``404`` after an attempt that may have reached Mist
        means that attempt deleted the object: the restore got what it asked for.
        """
        sent = await self._send(
            "DELETE",
            definition.item_path(object_id, org_id=org_id, site_id=site_id),
            action="delete",
            object_type=definition.key,
        )
        if sent.ambiguous and sent.response.status_code == HTTPStatus.NOT_FOUND:
            return
        self._response_payload(sent.response, "delete", definition.key, write=True, ambiguous=sent.ambiguous)

    async def _send(  # noqa: PLR0913 - request identity, logging context and payload are all distinct
        self,
        method: Method,
        path: str,
        *,
        action: str,
        object_type: str,
        json: dict[str, object] | None = None,
        params: Mapping[str, str | int] | None = None,
    ) -> _Sent:
        """Send one request, retrying only where a retry cannot apply a write twice.

        GET, PUT and DELETE are idempotent and are retried on throttling,
        gateway errors and transport failures. POST is retried only on 429,
        the one answer that proves Mist did not process it.

        A PUT or DELETE attempt that failed in transport or with a retried
        gateway error may have been applied, so the result carries that
        ambiguity to the caller; a 429 proves nothing was processed and never
        makes a write ambiguous.
        """
        write = method != "GET"
        ambiguous = False
        for attempt in range(1, MAX_ATTEMPTS + 1):
            last = attempt == MAX_ATTEMPTS
            try:
                response = await self._client.request(method, path, json=json, params=params)
            except httpx.TransportError as exc:
                if method == "POST" or last:
                    msg = f"Unable to reach Mist to {action} {object_type}"
                    raise MistMutationTransportError(msg, outcome_unknown=write) from exc
                ambiguous = ambiguous or write
                await self._sleep(_backoff(attempt))
                continue
            except httpx.HTTPError as exc:
                msg = f"Mist returned an unusable answer to {action} {object_type}"
                raise MistMutationTransportError(msg, outcome_unknown=write) from exc
            retryable = response.status_code in _RETRYABLE_STATUSES and (
                method != "POST" or response.status_code == HTTPStatus.TOO_MANY_REQUESTS
            )
            if not retryable or last:
                return _Sent(response, ambiguous=ambiguous)
            ambiguous = ambiguous or (write and response.status_code >= HTTPStatus.INTERNAL_SERVER_ERROR)
            await self._sleep(_retry_delay(response, attempt))
        msg = f"Unable to {action} {object_type} in Mist"
        raise MistMutationTransportError(msg, outcome_unknown=write)

    @staticmethod
    def _response_payload(
        response: httpx.Response,
        action: str,
        object_type: str,
        *,
        write: bool,
        ambiguous: bool = False,
    ) -> object:
        """Classify the final answer; ``ambiguous`` says an earlier attempt may already have applied the write."""
        if response.status_code not in _SUCCESS_STATUSES:
            msg = f"Mist failed to {action} {object_type} ({response.status_code})"
            raise MistMutationStatusError(
                msg,
                outcome_unknown=write and (ambiguous or response.status_code >= HTTPStatus.INTERNAL_SERVER_ERROR),
                status_code=response.status_code,
            )
        if response.status_code == HTTPStatus.NO_CONTENT or not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            msg = f"Mist returned invalid JSON after {action} of {object_type}"
            raise MistMutationError(msg, outcome_unknown=write) from exc

    @staticmethod
    def _integer_header(response: httpx.Response, name: str) -> int | None:
        """Read a paging header the way the collector does, so both walk the same pages."""
        value = response.headers.get(name)
        if value is None:
            return None
        try:
            return int(value)
        except ValueError:
            return None
