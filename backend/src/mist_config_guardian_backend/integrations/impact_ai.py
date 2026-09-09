"""Optional provider-neutral AI impact assessment adapter."""

import json
from contextlib import AbstractAsyncContextManager
from types import TracebackType
from typing import Self, cast

import httpx

from mist_config_guardian_backend.services.impact_analysis import ImpactAssessment


class AiImpactError(RuntimeError):
    """Raised when optional AI assessment fails."""


class OpenAiCompatibleImpactProvider(AbstractAsyncContextManager["OpenAiCompatibleImpactProvider"]):
    """Send only derived, non-identifying evidence to a compatible provider."""

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: str,
    ) -> None:
        self._model = model
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
            timeout=45,
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

    async def assess(self, assessment: ImpactAssessment) -> dict[str, object]:
        """Return a supplemental structured assessment."""
        evidence = {
            "deterministic_severity": assessment.severity,
            "metric_deltas": assessment.metric_deltas,
            "degraded_metrics": assessment.degraded_metrics,
            "incident_types": assessment.incident_types,
            "device_findings": assessment.device_findings,
        }
        try:
            response = await self._client.post(
                "/chat/completions",
                json={
                    "model": self._model,
                    "temperature": 0,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "Assess whether derived network evidence indicates "
                                "harm from a configuration change. Return JSON with "
                                "severity, confidence, explanation, and recommendations."
                            ),
                        },
                        {
                            "role": "user",
                            "content": json.dumps(evidence, separators=(",", ":")),
                        },
                    ],
                },
            )
            response.raise_for_status()
            envelope = response.json()
            content = envelope["choices"][0]["message"]["content"]
            result = json.loads(content)
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
            msg = "AI impact provider returned an invalid response"
            raise AiImpactError(msg) from exc
        if not isinstance(result, dict):
            msg = "AI impact provider response must be a JSON object"
            raise AiImpactError(msg)
        return cast("dict[str, object]", result)
