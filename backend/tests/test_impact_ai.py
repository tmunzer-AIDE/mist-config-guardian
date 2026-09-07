"""Optional AI impact adapter tests."""

import json

import pytest
from pytest_httpx import HTTPXMock

from mist_config_guardian_backend.integrations.impact_ai import (
    AiImpactError,
    OpenAiCompatibleImpactProvider,
)
from mist_config_guardian_backend.models.monitoring import ImpactSeverity
from mist_config_guardian_backend.services.impact_analysis import ImpactAssessment


def _assessment() -> ImpactAssessment:
    return ImpactAssessment(
        severity=ImpactSeverity.WARNING,
        summary="Potential impact",
        degraded_metrics=("coverage",),
        metric_deltas={"coverage": -12.0},
        incident_types=("AP_DISCONNECTED",),
    )


async def test_ai_adapter_sends_only_derived_evidence(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        method="POST",
        url="https://ai.example.test/v1/chat/completions",
        json={
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "severity": "warning",
                                "confidence": 0.8,
                                "explanation": "Coverage dropped.",
                                "recommendations": [],
                            }
                        )
                    }
                }
            ]
        },
    )

    async with OpenAiCompatibleImpactProvider(
        base_url="https://ai.example.test/v1",
        model="test-model",
        api_key="secret-key",
    ) as provider:
        result = await provider.assess(_assessment())

    request = httpx_mock.get_request()
    assert request is not None
    body = request.content.decode()
    assert "coverage" in body
    assert "device_mac" not in body
    assert result["severity"] == "warning"


async def test_ai_adapter_rejects_invalid_response(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        method="POST",
        url="https://ai.example.test/v1/chat/completions",
        json={"choices": []},
    )

    async with OpenAiCompatibleImpactProvider(
        base_url="https://ai.example.test/v1",
        model="test-model",
        api_key="secret-key",
    ) as provider:
        with pytest.raises(AiImpactError):
            await provider.assess(_assessment())
