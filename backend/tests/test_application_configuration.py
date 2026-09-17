"""Application configuration tests."""

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
from pydantic import SecretStr, ValidationError

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.guardian.agent_schema import (
    ACTION_SCHEMA,
    ACTION_SCHEMA_VERSION,
    capability_fingerprint,
)
from mist_config_guardian_backend.integrations.ai_provider import (
    JSON_OBJECT,
    TEXT,
    AiCompletion,
    AiMessage,
    AiProviderError,
    JsonSchemaFormat,
)
from mist_config_guardian_backend.models.application_configuration import (
    ApplicationConfiguration,
    StructuredOutputCapability,
)
from mist_config_guardian_backend.schemas.application_configuration import (
    AiProviderDraft,
    ImpactAiSettingsUpdate,
)
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.application_configuration import (
    AiRequestRecord,
    ApplicationConfigurationError,
    ApplicationConfigurationService,
    structured_output_mode,
)


def _configuration() -> ApplicationConfiguration:
    return ApplicationConfiguration.model_construct(
        key="global",
        impact_ai_enabled=False,
        impact_ai_base_url="",
        impact_ai_model="",
        encrypted_impact_ai_api_key=None,
        impact_ai_api_key_last_four=None,
    )


def test_enabled_ai_requires_provider_identity() -> None:
    with pytest.raises(ValidationError, match="base URL and model"):
        ImpactAiSettingsUpdate(enabled=True)


async def test_enabled_ai_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    service = ApplicationConfigurationService(
        CredentialVault(
            Settings(
                environment="test",
                database_enabled=False,
                credential_encryption_key=SecretStr("test-encryption-key"),
            )
        )
    )
    monkeypatch.setattr(service, "_get_or_create", AsyncMock(return_value=_configuration()))

    with pytest.raises(ApplicationConfigurationError, match="API key is required"):
        await service.update_impact_ai(
            ImpactAiSettingsUpdate(
                enabled=True,
                base_url="https://ai.example.test/v1",
                model="test-model",
            )
        )


async def test_ai_api_key_is_encrypted_and_not_returned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault = CredentialVault(
        Settings(
            environment="test",
            database_enabled=False,
            credential_encryption_key=SecretStr("test-encryption-key"),
        )
    )
    service = ApplicationConfigurationService(vault)
    configuration = _configuration()
    monkeypatch.setattr(service, "_get_or_create", AsyncMock(return_value=configuration))
    monkeypatch.setattr(ApplicationConfiguration, "save", AsyncMock())

    response = await service.update_impact_ai(
        ImpactAiSettingsUpdate(
            enabled=True,
            base_url="https://ai.example.test/v1/",
            model="test-model",
            api_key=SecretStr("provider-secret-key"),
        )
    )

    assert response.api_key_set is True
    assert response.api_key_last_four == "-key"
    assert configuration.encrypted_impact_ai_api_key is not None
    assert "provider-secret-key" not in configuration.encrypted_impact_ai_api_key
    assert (
        vault.decrypt_for_context(
            configuration.encrypted_impact_ai_api_key,
            context="impact-ai-api-key",
        )
        == "provider-secret-key"
    )


# --- structured-output capability ---------------------------------------


class _FakeProvider:
    """A provider that answers the capability probe the way a real one would, without a network."""

    def __init__(self, *, replies: dict[str, str | Exception], connected: bool = True) -> None:
        self.replies = replies
        self.connected = connected
        self.requests: list[tuple[str, tuple[AiMessage, ...]]] = []
        self.formats: list[object] = []
        self.closed = False

    async def complete(self, messages, *, max_tokens=None, response_format=TEXT) -> AiCompletion:  # noqa: ARG002 - the fake mirrors the provider protocol
        kind = (
            "json_schema"
            if isinstance(response_format, JsonSchemaFormat)
            else "json_object"
            if response_format is JSON_OBJECT
            else "text"
        )
        self.requests.append((kind, tuple(messages)))
        self.formats.append(response_format)
        reply = self.replies.get(kind)
        if isinstance(reply, Exception):
            raise reply
        if reply is None:
            msg = "The provider rejected the request (HTTP 400)."
            raise AiProviderError(msg)
        return AiCompletion(content=reply, model="test-model")

    async def list_models(self):
        return []

    async def test_connection(self) -> tuple[bool, str]:
        return (True, "Connected to test-model.") if self.connected else (False, "The provider rejected the API key.")

    async def aclose(self) -> None:
        self.closed = True


REPORT = json.dumps(
    {
        "action": "report",
        "peak_impact": "none",
        "current_impact": "none",
        "confidence": "low",
        "summary": "capability probe",
        "evidence": [],
    }
)
BASE_URL = "https://ai.example.test/v1"


def _vault() -> CredentialVault:
    return CredentialVault(
        Settings(
            environment="test",
            database_enabled=False,
            credential_encryption_key=SecretStr("test-encryption-key"),
        )
    )


def _provider_configuration(**overrides) -> ApplicationConfiguration:
    values = {
        "key": "global",
        "impact_ai_enabled": True,
        "impact_ai_base_url": BASE_URL,
        "impact_ai_model": "test-model",
        "encrypted_impact_ai_api_key": None,
        "impact_ai_api_key_last_four": None,
        "impact_ai_max_response_tokens": 1500,
        "impact_ai_automatic_summaries": False,
        "impact_ai_structured_output": None,
    }
    return ApplicationConfiguration.model_construct(**(values | overrides))


class _FakeRecorder:
    def __init__(self) -> None:
        self.audits: list[AiRequestRecord] = []

    async def record(self, record: AiRequestRecord) -> None:
        self.audits.append(record)


def _service(
    provider: _FakeProvider, configuration: ApplicationConfiguration, monkeypatch: pytest.MonkeyPatch
) -> ApplicationConfigurationService:
    service = ApplicationConfigurationService(
        _vault(),
        Settings(environment="test", database_enabled=False),
        provider_factory=lambda **_kwargs: provider,
    )
    monkeypatch.setattr(service, "_get_or_create", AsyncMock(return_value=configuration))
    monkeypatch.setattr(ApplicationConfiguration, "save", AsyncMock())
    return service


async def test_a_probe_that_validates_records_json_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = _FakeProvider(replies={"json_schema": REPORT})
    configuration = _provider_configuration()

    response = await _service(provider, configuration, monkeypatch).test_ai_connection()

    record = configuration.impact_ai_structured_output
    assert record is not None
    assert record.mode == "json_schema"
    assert record.schema_version == ACTION_SCHEMA_VERSION
    assert record.fingerprint == capability_fingerprint(base_url=BASE_URL, model="test-model")
    assert record.tested_at is not None
    assert [kind for kind, _ in provider.requests] == ["json_schema"]
    assert "json_schema" in response.detail
    assert provider.closed is True


async def test_the_schema_probe_asks_for_guardians_own_action_schema_without_strictness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Controller ruling R35: the root ``oneOf`` is outside strict mode, and content validation is the gate."""
    provider = _FakeProvider(replies={"json_schema": REPORT})

    await _service(provider, _provider_configuration(), monkeypatch).test_ai_connection()

    requested = provider.formats[0]
    assert isinstance(requested, JsonSchemaFormat)
    assert requested.schema == ACTION_SCHEMA
    # What that means on the wire is asserted in tests/test_ai_provider.py, over the real request body.
    assert requested.strict is False


async def test_a_server_that_ignores_the_schema_falls_back_to_a_json_object_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _FakeProvider(replies={"json_schema": "Sure! Here is the report.", "json_object": REPORT})
    configuration = _provider_configuration()

    await _service(provider, configuration, monkeypatch).test_ai_connection()

    record = configuration.impact_ai_structured_output
    assert record is not None
    assert record.mode == "json_object"
    assert [kind for kind, _ in provider.requests] == ["json_schema", "json_object"]
    schema_carried = [json.dumps([m.content for m in messages]) for _, messages in provider.requests]
    assert all("GuardianAction" in prompt for prompt in schema_carried)


@pytest.mark.parametrize(
    "replies",
    [
        {"json_schema": "no idea", "json_object": "{}"},
        {"json_schema": '{"action": "report"}', "json_object": '```json\n{"action":"call"}\n```'},
        {},
    ],
)
async def test_nothing_is_recorded_when_neither_probe_validates(
    replies: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    stale = StructuredOutputCapability(
        mode="json_schema",
        fingerprint=capability_fingerprint(base_url=BASE_URL, model="test-model"),
        schema_version=ACTION_SCHEMA_VERSION,
        tested_at=datetime(2026, 9, 1, tzinfo=UTC),
    )
    configuration = _provider_configuration(impact_ai_structured_output=stale)

    response = await _service(_FakeProvider(replies=replies), configuration, monkeypatch).test_ai_connection()

    assert configuration.impact_ai_structured_output is None
    assert "Structured output is unavailable" in response.detail
    assert response.ok is True


async def test_a_failed_connection_never_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = _FakeProvider(replies={"json_schema": REPORT}, connected=False)
    configuration = _provider_configuration()

    response = await _service(provider, configuration, monkeypatch).test_ai_connection()

    assert response.ok is False
    assert provider.requests == []
    assert configuration.impact_ai_structured_output is None


async def test_a_draft_probe_stores_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = _FakeProvider(replies={"json_schema": REPORT})
    configuration = _provider_configuration()

    await _service(provider, configuration, monkeypatch).test_ai_connection(
        draft=AiProviderDraft(base_url=BASE_URL, model="test-model")
    )

    assert configuration.impact_ai_structured_output is None
    assert configuration.impact_ai_last_test_at is None
    assert provider.requests == []


def test_the_fingerprint_covers_the_provider_model_and_schema_but_no_key_material() -> None:
    fingerprint = capability_fingerprint(base_url=BASE_URL, model="test-model")

    assert fingerprint == capability_fingerprint(base_url=f"{BASE_URL}/", model="test-model")
    assert fingerprint != capability_fingerprint(base_url="https://other.test/v1", model="test-model")
    assert fingerprint != capability_fingerprint(base_url=BASE_URL, model="other-model")
    other_version = f"{ACTION_SCHEMA_VERSION}-next"
    assert fingerprint != capability_fingerprint(base_url=BASE_URL, model="test-model", schema_version=other_version)
    assert "test-model" not in fingerprint


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({}, "json_schema"),
        ({"impact_ai_model": "other-model"}, None),
        ({"impact_ai_base_url": "https://other.test/v1"}, None),
    ],
)
def test_a_record_counts_only_while_it_matches_the_saved_provider(
    overrides: dict[str, object], expected: str | None
) -> None:
    record = StructuredOutputCapability(
        mode="json_schema",
        fingerprint=capability_fingerprint(base_url=BASE_URL, model="test-model"),
        schema_version=ACTION_SCHEMA_VERSION,
        tested_at=datetime(2026, 9, 1, tzinfo=UTC),
    )

    configuration = _provider_configuration(impact_ai_structured_output=record, **overrides)

    assert structured_output_mode(configuration) == expected


def test_an_outdated_schema_version_invalidates_a_stored_record() -> None:
    record = StructuredOutputCapability(
        mode="json_object",
        fingerprint=capability_fingerprint(base_url=BASE_URL, model="test-model", schema_version="0"),
        schema_version="0",
        tested_at=datetime(2026, 9, 1, tzinfo=UTC),
    )

    configuration = _provider_configuration(impact_ai_structured_output=record)

    assert structured_output_mode(configuration) is None


def test_the_runtime_configuration_carries_the_proved_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    record = StructuredOutputCapability(
        mode="json_object",
        fingerprint=capability_fingerprint(base_url=BASE_URL, model="test-model"),
        schema_version=ACTION_SCHEMA_VERSION,
        tested_at=datetime(2026, 9, 1, tzinfo=UTC),
    )
    configuration = _provider_configuration(impact_ai_structured_output=record)
    service = _service(_FakeProvider(replies={}), configuration, monkeypatch)

    runtime = service._runtime(configuration)  # noqa: SLF001 - the database read around it needs a live Beanie

    assert runtime.structured_output == "json_object"
    assert runtime.api_key == ""


async def test_every_outbound_request_of_a_test_gets_its_own_audit_row(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = _FakeProvider(replies={"json_schema": "Sure! Here is the report.", "json_object": REPORT})
    configuration = _provider_configuration()
    recorder = _FakeRecorder()

    await _service(provider, configuration, monkeypatch).test_ai_connection(recorder)

    assert [audit.purpose for audit in recorder.audits] == [
        "connection_test",
        "capability_probe",
        "capability_probe",
    ]
    assert [audit.succeeded for audit in recorder.audits] == [True, False, True]
    assert recorder.audits[1].error is not None
    assert recorder.audits[2].error is None
    assert all(audit.duration_ms >= 0 for audit in recorder.audits)
    assert all(audit.model == "test-model" for audit in recorder.audits)


async def test_a_failed_connection_audits_one_request(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = _FakeProvider(replies={"json_schema": REPORT}, connected=False)
    recorder = _FakeRecorder()

    await _service(provider, _provider_configuration(), monkeypatch).test_ai_connection(recorder)

    assert [audit.purpose for audit in recorder.audits] == ["connection_test"]
    assert recorder.audits[0].succeeded is False
    assert recorder.audits[0].error is not None


async def test_a_rejected_probe_request_is_audited_as_its_own_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    error = AiProviderError("The provider rejected the request (HTTP 400).")
    provider = _FakeProvider(replies={"json_schema": error, "json_object": REPORT})
    recorder = _FakeRecorder()

    await _service(provider, _provider_configuration(), monkeypatch).test_ai_connection(recorder)

    assert [audit.succeeded for audit in recorder.audits] == [True, False, True]
    assert "HTTP 400" in (recorder.audits[1].error or "")
