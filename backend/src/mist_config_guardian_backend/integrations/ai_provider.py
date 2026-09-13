"""Generalised OpenAI-compatible provider adapter.

Only bounded, already-redacted evidence is ever passed to :meth:`complete`;
the adapter itself never inspects or logs configuration values.
"""

import json
import time
from collections.abc import Sequence
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from types import TracebackType
from typing import Protocol, Self, runtime_checkable

import httpx

_DEFAULT_TIMEOUT = 45.0
_DEFAULT_MAX_TOKENS = 1500
_TEST_MAX_TOKENS = 16
_UNAUTHORIZED_STATUSES = frozenset({401, 403})
_NOT_FOUND = 404
_TOO_MANY_REQUESTS = 429
_SERVER_ERROR_FLOOR = 500


class AiProviderError(RuntimeError):
    """Raised when an AI provider call fails in an unexpected way."""


@dataclass(frozen=True)
class AiMessage:
    """One chat message sent to the provider."""

    role: str
    content: str


@dataclass(frozen=True)
class AiCompletion:
    """A completion plus the usage the provider reported for it."""

    content: str
    model: str
    request_tokens: int | None = None
    response_tokens: int | None = None
    duration_ms: int = 0


@dataclass(frozen=True)
class AiModel:
    """One model advertised by the provider."""

    id: str
    owned_by: str | None = None
    context_window: int | None = None


@runtime_checkable
class AiProvider(Protocol):
    """The provider surface used by services, so tests can substitute a fake."""

    async def complete(
        self,
        messages: Sequence[AiMessage],
        *,
        max_tokens: int | None = None,
        json_object: bool = False,
    ) -> AiCompletion:
        """Return a chat completion for the supplied messages."""
        ...

    async def list_models(self) -> list[AiModel]:
        """Return the models the provider advertises, sorted by identifier."""
        ...

    async def test_connection(self) -> tuple[bool, str]:
        """Return whether credentials and model work, plus a readable detail."""
        ...

    async def aclose(self) -> None:
        """Release the underlying transport."""
        ...


def describe_http_failure(error: Exception, *, model: str, timeout: float) -> str:
    """Map an httpx failure onto a readable, secret-free detail string."""
    if isinstance(error, httpx.TimeoutException):
        return f"The provider did not respond within {timeout:g} seconds."
    if isinstance(error, httpx.HTTPStatusError):
        return _describe_status(error.response.status_code, model=model)
    if isinstance(error, httpx.HTTPError):
        return f"The provider could not be reached: {type(error).__name__}."
    return "The provider returned an unusable response."


def _describe_status(status_code: int, *, model: str) -> str:
    if status_code in _UNAUTHORIZED_STATUSES:
        return f"The provider rejected the API key (HTTP {status_code})."
    if status_code == _NOT_FOUND:
        return f"The provider does not expose model '{model}' at this base URL (HTTP 404)."
    if status_code == _TOO_MANY_REQUESTS:
        return "The provider is rate limiting this deployment (HTTP 429)."
    if status_code >= _SERVER_ERROR_FLOOR:
        return f"The provider reported a server error (HTTP {status_code})."
    return f"The provider rejected the request (HTTP {status_code})."


class OpenAiCompatibleProvider(AbstractAsyncContextManager["OpenAiCompatibleProvider"]):
    """Chat completion, model discovery, and health checks over one HTTP client."""

    def __init__(  # noqa: PLR0913 - provider transport and response bounds
        self,
        *,
        base_url: str,
        model: str,
        api_key: str,
        timeout: float = _DEFAULT_TIMEOUT,
        max_response_tokens: int = _DEFAULT_MAX_TOKENS,
        max_response_bytes: int = 1_048_576,
    ) -> None:
        self._model = model
        self._timeout = timeout
        self._max_response_tokens = max_response_tokens
        self._max_response_bytes = max_response_bytes
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
            timeout=timeout,
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    @property
    def model(self) -> str:
        """Return the configured model identifier."""
        return self._model

    async def complete(
        self,
        messages: Sequence[AiMessage],
        *,
        max_tokens: int | None = None,
        json_object: bool = False,
    ) -> AiCompletion:
        """Return a chat completion, raising :class:`AiProviderError` on failure."""
        payload: dict[str, object] = {
            "model": self._model,
            "temperature": 0,
            "max_tokens": max_tokens or self._max_response_tokens,
            "messages": [{"role": message.role, "content": message.content} for message in messages],
        }
        if json_object:
            payload["response_format"] = {"type": "json_object"}
        started = time.perf_counter()
        try:
            async with self._client.stream("POST", "/chat/completions", json=payload) as response:
                response.raise_for_status()
                data = bytearray()
                async for chunk in response.aiter_bytes():
                    data.extend(chunk)
                    if len(data) > self._max_response_bytes:
                        msg = "The provider response exceeded the byte limit."
                        raise AiProviderError(msg)
                envelope = json.loads(data)
            content = envelope["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
            detail = describe_http_failure(exc, model=self._model, timeout=self._timeout)
            raise AiProviderError(detail) from exc
        if not isinstance(content, str):
            msg = "The provider returned a completion without text content."
            raise AiProviderError(msg)
        usage = envelope.get("usage") if isinstance(envelope, dict) else None
        return AiCompletion(
            content=content,
            model=str(envelope.get("model") or self._model),
            request_tokens=_usage_value(usage, "prompt_tokens"),
            response_tokens=_usage_value(usage, "completion_tokens"),
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    async def list_models(self) -> list[AiModel]:
        """Return the provider's advertised models sorted by identifier."""
        try:
            response = await self._client.get("/models")
            response.raise_for_status()
            envelope = response.json()
            entries = envelope["data"]
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
            detail = describe_http_failure(exc, model=self._model, timeout=self._timeout)
            raise AiProviderError(detail) from exc
        if not isinstance(entries, list):
            msg = "The provider returned a model list that is not an array."
            raise AiProviderError(msg)
        models = [_parse_model(entry) for entry in entries]
        return sorted((model for model in models if model is not None), key=lambda model: model.id)

    async def test_connection(self) -> tuple[bool, str]:
        """Prove credentials and model with a minimal completion."""
        try:
            completion = await self.complete(
                [
                    AiMessage(role="system", content="Reply with the single word OK."),
                    AiMessage(role="user", content="OK"),
                ],
                max_tokens=_TEST_MAX_TOKENS,
            )
        except AiProviderError as exc:
            return False, str(exc)
        return True, f"Connected to {completion.model}."


def _usage_value(usage: object, key: str) -> int | None:
    if not isinstance(usage, dict):
        return None
    value = usage.get(key)
    return value if type(value) is int and value >= 0 else None


def _parse_model(entry: object) -> AiModel | None:
    if isinstance(entry, str):
        return AiModel(id=entry)
    if not isinstance(entry, dict):
        return None
    identifier = entry.get("id")
    if not isinstance(identifier, str) or not identifier:
        return None
    owned_by = entry.get("owned_by")
    context_window = entry.get("context_window") or entry.get("context_length")
    return AiModel(
        id=identifier,
        owned_by=owned_by if isinstance(owned_by, str) else None,
        context_window=context_window if isinstance(context_window, int) else None,
    )
