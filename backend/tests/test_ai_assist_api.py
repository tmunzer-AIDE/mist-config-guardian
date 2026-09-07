"""AI settings and secret-safe assistance API tests."""

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import httpx
import pytest
from beanie import PydanticObjectId
from pydantic import SecretStr
from pytest_httpx import HTTPXMock

from mist_config_guardian_backend.api.dependencies import (
    get_application_configuration_service,
    require_administrator,
    require_viewer,
)
from mist_config_guardian_backend.api.routes.ai import get_ai_audit_recorder
from mist_config_guardian_backend.api.routes.diff import get_version_repository
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.main import create_app
from mist_config_guardian_backend.models.application_configuration import ApplicationConfiguration
from mist_config_guardian_backend.models.snapshot import ObjectVersion, VersionEvent
from mist_config_guardian_backend.models.user import User, UserRole
from mist_config_guardian_backend.schemas.application_configuration import AiSettingsUpdate
from mist_config_guardian_backend.schemas.diff import (
    ConfigurationDiff,
    DiffChangeKind,
    DiffEntry,
)
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services import ai_assist
from mist_config_guardian_backend.services.ai_assist import (
    AiEvidenceError,
    build_summary_messages,
    parse_summary,
)
from mist_config_guardian_backend.services.application_configuration import (
    AiRequestRecord,
    AiRuntimeConfiguration,
    ApplicationConfigurationService,
)
from mist_config_guardian_backend.services.diff import diff_configurations

BASE_URL = "https://ai.example.test/v1"
COMPLETIONS_URL = f"{BASE_URL}/chat/completions"
MODELS_URL = f"{BASE_URL}/models"

ORGANIZATION_ID = PydanticObjectId()
BEFORE_ID = PydanticObjectId()
AFTER_ID = PydanticObjectId()

_BEFORE: dict[str, object] = {
    "band_5": {"power_max": 17},
    "radius": {"secret": {"$encrypted": "v1:before-ciphertext"}},
}
_AFTER: dict[str, object] = {
    "band_5": {"power_max": 11},
    "radius": {"secret": {"$encrypted": "v1:after-ciphertext"}},
}


@pytest.fixture(autouse=True)
def _clear_summary_cache() -> None:
    ai_assist._SUMMARY_CACHE.clear()  # noqa: SLF001 - process-local cache reset between tests


def _administrator() -> User:
    return User.model_construct(
        id=PydanticObjectId(),
        email="admin@example.com",
        display_name="Admin",
        password_hash="unused",
        role=UserRole.ADMINISTRATOR,
        is_active=True,
    )


def _viewer() -> User:
    return User.model_construct(
        id=PydanticObjectId(),
        email="viewer@example.com",
        display_name="Viewer",
        password_hash="unused",
        role=UserRole.VIEWER,
        is_active=True,
    )


def _version(version_id: PydanticObjectId, configuration: dict[str, object]) -> ObjectVersion:
    return ObjectVersion.model_construct(
        id=version_id,
        organization_id=ORGANIZATION_ID,
        logical_object_id=PydanticObjectId(),
        incarnation_id=PydanticObjectId(),
        version=1,
        event=VersionEvent.UPDATED,
        configuration=configuration,
        configuration_hash="hash",
        changed_fields=[],
        references=[],
        is_deleted=False,
        observed_at=datetime(2026, 9, 7, 9, 12, tzinfo=UTC),
        actor="j.mercer",
        audit_id=None,
    )


class _FakeVersionRepository:
    async def load(
        self,
        organization_id: PydanticObjectId,
        version_id: PydanticObjectId,
    ) -> ObjectVersion | None:
        if organization_id != ORGANIZATION_ID:
            return None
        if version_id == BEFORE_ID:
            return _version(BEFORE_ID, _BEFORE)
        if version_id == AFTER_ID:
            return _version(AFTER_ID, _AFTER)
        return None


class _FakeRecorder:
    def __init__(self) -> None:
        self.audits: list[AiRequestRecord] = []

    async def record(self, record: AiRequestRecord) -> None:
        self.audits.append(record)


class _FakeConfigurationService:
    def __init__(self, runtime: AiRuntimeConfiguration | None) -> None:
        self._runtime = runtime

    async def ai_runtime(self) -> AiRuntimeConfiguration | None:
        return self._runtime


def _runtime() -> AiRuntimeConfiguration:
    return AiRuntimeConfiguration(
        base_url=BASE_URL,
        model="test-model",
        api_key="provider-secret-key",
        max_response_tokens=800,
        automatic_summaries=False,
    )


def _assist_app(
    runtime: AiRuntimeConfiguration | None,
) -> tuple[object, _FakeRecorder]:
    app = create_app(Settings(environment="test", database_enabled=False))
    recorder = _FakeRecorder()
    app.dependency_overrides[get_application_configuration_service] = lambda: _FakeConfigurationService(runtime)
    app.dependency_overrides[get_ai_audit_recorder] = lambda: recorder
    app.dependency_overrides[get_version_repository] = _FakeVersionRepository
    app.dependency_overrides[require_viewer] = _viewer
    return app, recorder


def _summary_body() -> dict[str, object]:
    return {
        "organization_id": str(ORGANIZATION_ID),
        "from_version_id": str(BEFORE_ID),
        "to_version_id": str(AFTER_ID),
    }


# --- prompt construction ------------------------------------------------


def test_summary_prompt_contains_field_names_but_no_secret_material() -> None:
    diff = diff_configurations(_BEFORE, _AFTER)
    messages = build_summary_messages(diff)
    serialized = json.dumps([{"role": message.role, "content": message.content} for message in messages])

    assert "band_5.power_max" in serialized
    assert "radius.secret" in serialized
    assert "before-ciphertext" not in serialized
    assert "after-ciphertext" not in serialized
    assert "$encrypted" not in serialized
    assert "********" not in serialized


def test_evidence_guard_rejects_leaked_encrypted_material() -> None:
    diff = ConfigurationDiff(
        entries=[
            DiffEntry(
                field="radius.secret",
                kind=DiffChangeKind.MODIFIED,
                before='{"$encrypted": "v1:leak"}',
                after="x",
                note="leaked",
                section="radius",
            )
        ]
    )

    with pytest.raises(AiEvidenceError):
        build_summary_messages(diff)


def test_parse_summary_maps_intent_and_flags_to_cards() -> None:
    summary, cards = parse_summary(
        json.dumps(
            {
                "summary": "Narrows 5 GHz.",
                "intent": ["Reduce co-channel interference."],
                "flags": [{"level": "crit", "text": "Too few channels.", "ref": "band_5.channels"}],
            }
        )
    )

    assert summary == "Narrows 5 GHz."
    assert [card.kind for card in cards] == ["intent", "flag"]
    assert cards[1].level == "crit"
    assert cards[1].field == "band_5.channels"


def test_parse_summary_falls_back_to_plain_text() -> None:
    summary, cards = parse_summary("Not JSON at all.")

    assert summary == "Not JSON at all."
    assert cards == []


# --- assistance endpoints ------------------------------------------------


async def test_diff_summary_returns_cards_and_writes_an_audit(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        method="POST",
        url=COMPLETIONS_URL,
        json={
            "model": "test-model",
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "summary": "Transmit power is reduced and the RADIUS secret rotated.",
                                "intent": ["Shrink cell size."],
                                "flags": [{"level": "warn", "text": "Coverage may drop.", "ref": "band_5.power_max"}],
                            }
                        )
                    }
                }
            ],
            "usage": {"prompt_tokens": 210, "completion_tokens": 60},
        },
    )
    app, recorder = _assist_app(_runtime())

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/v1/ai/diff-summary", json=_summary_body())

    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"].startswith("Transmit power")
    assert payload["model"] == "test-model"
    assert payload["disclaimer"] == "Field names and values only — secrets are never sent."
    assert [card["kind"] for card in payload["cards"]] == ["intent", "flag"]
    assert payload["cached"] is False

    provider_request = httpx_mock.get_request()
    assert provider_request is not None
    assert "ciphertext" not in provider_request.read().decode()

    assert len(recorder.audits) == 1
    audit = recorder.audits[0]
    assert audit.purpose == "diff_summary"
    assert audit.succeeded is True
    assert audit.model == "test-model"
    assert audit.request_tokens == 210
    assert audit.response_tokens == 60
    assert audit.redaction_applied is True
    assert audit.organization_id == ORGANIZATION_ID
    assert audit.subject_id == f"{BEFORE_ID}->{AFTER_ID}"


async def test_diff_summary_audits_provider_failures(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="POST", url=COMPLETIONS_URL, status_code=401, json={"error": "no"})
    app, recorder = _assist_app(_runtime())

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/v1/ai/diff-summary", json=_summary_body())

    assert response.status_code == 502
    assert "API key" in response.json()["detail"]
    assert len(recorder.audits) == 1
    assert recorder.audits[0].succeeded is False
    assert recorder.audits[0].error is not None
    assert recorder.audits[0].redaction_applied is True


async def test_diff_summary_conflicts_when_ai_is_disabled() -> None:
    app, recorder = _assist_app(None)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/v1/ai/diff-summary", json=_summary_body())

    assert response.status_code == 409
    assert "disabled" in response.json()["detail"]
    assert recorder.audits == []


async def test_diff_summary_reuses_cache_until_regeneration(httpx_mock: HTTPXMock) -> None:
    for _ in range(2):
        httpx_mock.add_response(
            method="POST",
            url=COMPLETIONS_URL,
            json={"model": "test-model", "choices": [{"message": {"content": '{"summary":"Same."}'}}]},
        )
    app, recorder = _assist_app(_runtime())

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        first = await client.post("/api/v1/ai/diff-summary", json=_summary_body())
        cached = await client.post("/api/v1/ai/diff-summary", json=_summary_body())
        regenerated = await client.post(
            "/api/v1/ai/diff-summary",
            json={**_summary_body(), "regenerate": True},
        )

    assert first.json()["cached"] is False
    assert cached.json()["cached"] is True
    assert regenerated.json()["cached"] is False
    assert len(httpx_mock.get_requests()) == 2
    assert len(recorder.audits) == 2


async def test_diff_followup_answers_only_from_the_fixed_diff(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        method="POST",
        url=COMPLETIONS_URL,
        json={"model": "test-model", "choices": [{"message": {"content": "Transmit power dropped by 6 dBm."}}]},
    )
    app, recorder = _assist_app(_runtime())

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/ai/diff-followup",
            json={**_summary_body(), "question": "What changed on the 5 GHz radio?"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["answer"] == "Transmit power dropped by 6 dBm."
    assert payload["question"] == "What changed on the 5 GHz radio?"

    request = httpx_mock.get_request()
    assert request is not None
    body = request.read().decode()
    assert "What changed on the 5 GHz radio?" in body
    assert "ciphertext" not in body
    assert recorder.audits[0].purpose == "diff_followup"


async def test_diff_followup_rejects_overlong_questions() -> None:
    app, _recorder = _assist_app(_runtime())

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/ai/diff-followup",
            json={**_summary_body(), "question": "x" * 501},
        )

    assert response.status_code == 422


async def test_diff_followup_conflicts_when_ai_is_disabled() -> None:
    app, _recorder = _assist_app(None)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/ai/diff-followup",
            json={**_summary_body(), "question": "What changed?"},
        )

    assert response.status_code == 409


async def test_diff_summary_requires_authentication() -> None:
    app = create_app(Settings(environment="test", database_enabled=False))

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/v1/ai/diff-summary", json=_summary_body())

    assert response.status_code == 401


# --- settings endpoints --------------------------------------------------


def _vault() -> CredentialVault:
    return CredentialVault(
        Settings(
            environment="test",
            database_enabled=False,
            credential_encryption_key=SecretStr("test-encryption-key"),
        )
    )


def _stored_configuration() -> ApplicationConfiguration:
    return ApplicationConfiguration.model_construct(
        key="global",
        impact_ai_enabled=False,
        impact_ai_base_url="",
        impact_ai_model="",
        encrypted_impact_ai_api_key=None,
        impact_ai_api_key_last_four=None,
        impact_ai_max_response_tokens=1500,
        impact_ai_automatic_summaries=False,
        impact_ai_last_test_at=None,
        impact_ai_last_test_ok=None,
        impact_ai_last_test_detail=None,
    )


def _settings_app(service: object) -> object:
    app = create_app(Settings(environment="test", database_enabled=False))
    app.dependency_overrides[get_application_configuration_service] = lambda: service
    app.dependency_overrides[require_administrator] = _administrator
    return app


async def test_update_ai_settings_encrypts_the_key_and_never_returns_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault = _vault()
    service = ApplicationConfigurationService(vault, Settings(environment="test", database_enabled=False))
    configuration = _stored_configuration()
    monkeypatch.setattr(service, "_get_or_create", AsyncMock(return_value=configuration))
    monkeypatch.setattr(ApplicationConfiguration, "save", AsyncMock())
    app = _settings_app(service)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.put(
            "/api/v1/ai/settings",
            json={
                "enabled": True,
                "base_url": "https://ai.example.test/v1/",
                "model": "test-model",
                "api_key": "provider-secret-key",
                "max_response_tokens": 900,
                "automatic_summaries": True,
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["api_key_set"] is True
    assert payload["api_key_last_four"] == "-key"
    assert payload["max_response_tokens"] == 900
    assert payload["automatic_summaries"] is True
    assert "provider-secret-key" not in response.text
    assert configuration.encrypted_impact_ai_api_key is not None
    assert (
        vault.decrypt_for_context(configuration.encrypted_impact_ai_api_key, context="ai-provider-key")
        == "provider-secret-key"
    )


async def test_update_ai_settings_keeps_the_stored_key_when_blank(monkeypatch: pytest.MonkeyPatch) -> None:
    vault = _vault()
    service = ApplicationConfigurationService(vault, Settings(environment="test", database_enabled=False))
    configuration = _stored_configuration()
    configuration.encrypted_impact_ai_api_key = vault.encrypt_for_context("kept-key", context="ai-provider-key")
    configuration.impact_ai_api_key_last_four = "-key"
    monkeypatch.setattr(service, "_get_or_create", AsyncMock(return_value=configuration))
    monkeypatch.setattr(ApplicationConfiguration, "save", AsyncMock())

    result = await service.update_ai_settings(
        AiSettingsUpdate(
            enabled=True,
            base_url="https://ai.example.test/v1",
            model="test-model",
            api_key=SecretStr("   "),
        )
    )

    assert result.api_key_set is True
    assert (
        vault.decrypt_for_context(
            configuration.encrypted_impact_ai_api_key or "",
            context="ai-provider-key",
        )
        == "kept-key"
    )


async def test_ai_settings_test_persists_the_outcome_and_audits(
    monkeypatch: pytest.MonkeyPatch,
    httpx_mock: HTTPXMock,
) -> None:
    httpx_mock.add_response(method="POST", url=COMPLETIONS_URL, status_code=401, json={"error": "no"})
    vault = _vault()
    service = ApplicationConfigurationService(vault, Settings(environment="test", database_enabled=False))
    configuration = _stored_configuration()
    configuration.impact_ai_base_url = BASE_URL
    configuration.impact_ai_model = "test-model"
    configuration.encrypted_impact_ai_api_key = vault.encrypt_for_context("bad-key", context="ai-provider-key")
    monkeypatch.setattr(service, "_get_or_create", AsyncMock(return_value=configuration))
    monkeypatch.setattr(ApplicationConfiguration, "save", AsyncMock())
    recorder = _FakeRecorder()
    app = _settings_app(service)
    app.dependency_overrides[get_ai_audit_recorder] = lambda: recorder

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/v1/ai/settings/test")

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is False
    assert "API key" in payload["detail"]
    assert configuration.impact_ai_last_test_ok is False
    assert configuration.impact_ai_last_test_at is not None
    assert recorder.audits[0].purpose == "connection_test"
    assert recorder.audits[0].succeeded is False


async def test_ai_settings_test_conflicts_when_unconfigured(monkeypatch: pytest.MonkeyPatch) -> None:
    service = ApplicationConfigurationService(_vault(), Settings(environment="test", database_enabled=False))
    monkeypatch.setattr(service, "_get_or_create", AsyncMock(return_value=_stored_configuration()))
    app = _settings_app(service)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/v1/ai/settings/test")

    assert response.status_code == 409
    assert "base URL" in response.json()["detail"]


async def test_list_ai_models_returns_discovered_identifiers(
    monkeypatch: pytest.MonkeyPatch,
    httpx_mock: HTTPXMock,
) -> None:
    httpx_mock.add_response(
        method="GET",
        url=MODELS_URL,
        json={"data": [{"id": "gpt-4o"}, {"id": "gpt-4o-mini"}]},
    )
    vault = _vault()
    service = ApplicationConfigurationService(vault, Settings(environment="test", database_enabled=False))
    configuration = _stored_configuration()
    configuration.impact_ai_base_url = BASE_URL
    configuration.encrypted_impact_ai_api_key = vault.encrypt_for_context("k", context="ai-provider-key")
    monkeypatch.setattr(service, "_get_or_create", AsyncMock(return_value=configuration))
    app = _settings_app(service)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/ai/models")

    assert response.status_code == 200
    assert [item["id"] for item in response.json()["items"]] == ["gpt-4o", "gpt-4o-mini"]


async def test_list_ai_models_returns_bad_gateway_on_provider_failure(
    monkeypatch: pytest.MonkeyPatch,
    httpx_mock: HTTPXMock,
) -> None:
    httpx_mock.add_exception(httpx.ConnectError("refused"), method="GET", url=MODELS_URL)
    vault = _vault()
    service = ApplicationConfigurationService(vault, Settings(environment="test", database_enabled=False))
    configuration = _stored_configuration()
    configuration.impact_ai_base_url = BASE_URL
    configuration.encrypted_impact_ai_api_key = vault.encrypt_for_context("k", context="ai-provider-key")
    monkeypatch.setattr(service, "_get_or_create", AsyncMock(return_value=configuration))
    app = _settings_app(service)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/ai/models")

    assert response.status_code == 502
    assert "could not be reached" in response.json()["detail"]


async def test_ai_settings_require_administrator() -> None:
    app = create_app(Settings(environment="test", database_enabled=False))
    app.dependency_overrides[require_viewer] = _viewer

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/ai/settings")

    assert response.status_code == 401
