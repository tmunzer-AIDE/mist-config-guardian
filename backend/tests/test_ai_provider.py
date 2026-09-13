"""Generalised OpenAI-compatible provider adapter tests."""

import httpx
import pytest
from pytest_httpx import HTTPXMock

from mist_config_guardian_backend.integrations.ai_provider import (
    AiMessage,
    AiProviderError,
    OpenAiCompatibleProvider,
)

BASE_URL = "https://ai.example.test/v1"
COMPLETIONS_URL = f"{BASE_URL}/chat/completions"
MODELS_URL = f"{BASE_URL}/models"


def _provider(timeout: float = 45.0) -> OpenAiCompatibleProvider:
    return OpenAiCompatibleProvider(
        base_url=f"{BASE_URL}/",
        model="test-model",
        api_key="provider-secret-key",
        timeout=timeout,
        max_response_tokens=1500,
    )


async def test_complete_returns_content_and_usage(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        method="POST",
        url=COMPLETIONS_URL,
        json={
            "model": "test-model-0125",
            "choices": [{"message": {"content": "A summary."}}],
            "usage": {"prompt_tokens": 120, "completion_tokens": 40},
        },
    )

    async with _provider() as provider:
        completion = await provider.complete(
            [AiMessage(role="user", content="evidence")],
            max_tokens=256,
        )

    request = httpx_mock.get_request()
    assert request is not None
    assert request.headers["Authorization"] == "Bearer provider-secret-key"
    body = request.read().decode()
    assert '"max_tokens":256' in body.replace(" ", "")
    assert completion.content == "A summary."
    assert completion.model == "test-model-0125"
    assert completion.request_tokens == 120
    assert completion.response_tokens == 40


async def test_complete_requests_json_object_when_asked(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        method="POST",
        url=COMPLETIONS_URL,
        json={"choices": [{"message": {"content": "{}"}}]},
    )

    async with _provider() as provider:
        await provider.complete([AiMessage(role="user", content="e")], json_object=True)

    request = httpx_mock.get_request()
    assert request is not None
    assert "json_object" in request.read().decode()


async def test_complete_maps_malformed_responses_to_provider_error(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="POST", url=COMPLETIONS_URL, json={"choices": []})

    async with _provider() as provider:
        with pytest.raises(AiProviderError, match="unusable response"):
            await provider.complete([AiMessage(role="user", content="e")])


async def test_list_models_returns_sorted_identifiers(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        method="GET",
        url=MODELS_URL,
        json={
            "data": [
                {"id": "gpt-4o", "owned_by": "openai"},
                {"id": "gpt-4o-mini", "owned_by": "openai", "context_length": 128000},
                {"id": "llama-3.3-70b-instruct"},
            ]
        },
    )

    async with _provider() as provider:
        models = await provider.list_models()

    assert [model.id for model in models] == ["gpt-4o", "gpt-4o-mini", "llama-3.3-70b-instruct"]
    assert models[1].context_window == 128000
    assert models[0].owned_by == "openai"


async def test_list_models_reports_unreachable_provider(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_exception(httpx.ConnectError("refused"), method="GET", url=MODELS_URL)

    async with _provider() as provider:
        with pytest.raises(AiProviderError, match="could not be reached"):
            await provider.list_models()


async def test_test_connection_succeeds(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        method="POST",
        url=COMPLETIONS_URL,
        json={"model": "test-model", "choices": [{"message": {"content": "OK"}}]},
    )

    async with _provider() as provider:
        ok, detail = await provider.test_connection()

    assert ok is True
    assert detail == "Connected to test-model."


async def test_test_connection_reports_rejected_credentials(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="POST", url=COMPLETIONS_URL, status_code=401, json={"error": "no"})

    async with _provider() as provider:
        ok, detail = await provider.test_connection()

    assert ok is False
    assert detail == "The provider rejected the API key (HTTP 401)."


async def test_test_connection_reports_unknown_model(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="POST", url=COMPLETIONS_URL, status_code=404, json={"error": "no"})

    async with _provider() as provider:
        ok, detail = await provider.test_connection()

    assert ok is False
    assert "test-model" in detail
    assert "404" in detail


async def test_test_connection_reports_timeout(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_exception(httpx.ReadTimeout("slow"), method="POST", url=COMPLETIONS_URL)

    async with _provider(timeout=5.0) as provider:
        ok, detail = await provider.test_connection()

    assert ok is False
    assert detail == "The provider did not respond within 5 seconds."


async def test_test_connection_reports_rate_limit(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="POST", url=COMPLETIONS_URL, status_code=429, json={"error": "slow down"})

    async with _provider() as provider:
        ok, detail = await provider.test_connection()

    assert ok is False
    assert "429" in detail


async def test_completion_response_size_is_bounded(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="POST", url=COMPLETIONS_URL, content=b"x" * 2048)
    async with OpenAiCompatibleProvider(
        base_url=BASE_URL, model="test-model", api_key="", max_response_bytes=1024
    ) as provider:
        with pytest.raises(AiProviderError, match="byte limit"):
            await provider.complete([AiMessage(role="user", content="evidence")])


@pytest.mark.parametrize("usage", [-1, True, "123"])
async def test_invalid_provider_token_counts_remain_unknown(httpx_mock: HTTPXMock, usage) -> None:
    httpx_mock.add_response(
        method="POST",
        url=COMPLETIONS_URL,
        json={
            "choices": [{"message": {"content": "{}"}}],
            "usage": {"prompt_tokens": usage, "completion_tokens": usage},
        },
    )
    async with _provider() as provider:
        result = await provider.complete([AiMessage(role="user", content="evidence")])
    assert result.request_tokens is result.response_tokens is None
