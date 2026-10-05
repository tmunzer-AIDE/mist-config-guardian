"""Settings and organization writes name their own fields, so a slow request cannot revert a concurrent change.

Beanie's ``save()`` writes every field of the instance it is given. An operation that reads a document, waits on a
provider or on Mist, then saves, carries its stale copy of every other field back over whatever another request
changed in the meantime. Each test lands that other request inside the window, against a real MongoDB.

Skipped unless ``MONGO_TEST_URL`` names a reachable MongoDB.
"""

import json
import os
from collections.abc import Awaitable, Callable

import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from pydantic import SecretStr
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.integrations.ai_provider import TEXT, AiCompletion, JsonSchemaFormat
from mist_config_guardian_backend.integrations.mist import (
    MistAccessMode,
    MistOrganizationAccess,
    MistVerificationError,
)
from mist_config_guardian_backend.models.application_configuration import ApplicationConfiguration
from mist_config_guardian_backend.models.organization import Organization, OrganizationStatus
from mist_config_guardian_backend.schemas.application_configuration import (
    AiSettingsUpdate,
    ImpactAiSettingsUpdate,
    SmtpSettingsUpdate,
)
from mist_config_guardian_backend.schemas.organization import OrganizationUpdateRequest
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.application_configuration import ApplicationConfigurationService
from mist_config_guardian_backend.services.organizations import OrganizationService

MONGO_URL = os.environ.get("MONGO_TEST_URL")
DATABASE = "settings_concurrent_writes"
BASE_URL = "https://ai.example.test/v1"
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

pytestmark = [
    pytest.mark.skipif(not MONGO_URL, reason="MONGO_TEST_URL is not set"),
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.usefixtures("database"),
]

Concurrent = Callable[[], Awaitable[object]]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def database() -> None:
    client = AsyncMongoClient(MONGO_URL, tz_aware=True)
    await client.drop_database(DATABASE)
    await init_beanie(database=client[DATABASE], document_models=[ApplicationConfiguration, Organization])
    yield
    await client.drop_database(DATABASE)
    await client.close()


def _vault() -> CredentialVault:
    return CredentialVault(
        Settings(environment="test", database_enabled=False, credential_encryption_key=SecretStr("test-encryption-key"))
    )


# -- application configuration ---------------------------------------------


class _Provider:
    """Answers the connection check and the probe; ``during`` runs once, while the first request is outstanding."""

    def __init__(self, during: Concurrent) -> None:
        self.during: Concurrent | None = during

    async def complete(self, messages, *, max_tokens=None, response_format=TEXT) -> AiCompletion:  # noqa: ARG002 - mirrors the provider protocol
        if self.during is not None:
            during, self.during = self.during, None
            await during()
        content = REPORT if isinstance(response_format, JsonSchemaFormat) else "OK"
        return AiCompletion(content=content, model="test-model")

    async def list_models(self):
        return []

    async def test_connection(self) -> tuple[bool, str]:
        await self.complete([], max_tokens=16)
        return True, "Connected to test-model."

    async def aclose(self) -> None:
        return None


def _configuration_service(provider: _Provider | None = None) -> ApplicationConfigurationService:
    settings = Settings(
        environment="test",
        database_enabled=False,
        credential_encryption_key=SecretStr("test-encryption-key"),
        cors_origins="https://app.example.test",
    )
    if provider is None:
        return ApplicationConfigurationService(_vault(), settings)
    return ApplicationConfigurationService(_vault(), settings, provider_factory=lambda **_kwargs: provider)


async def _stored_configuration() -> PydanticObjectId:
    await ApplicationConfiguration.get_pymongo_collection().delete_many({})
    configuration = ApplicationConfiguration(
        impact_ai_enabled=True,
        impact_ai_base_url=BASE_URL,
        impact_ai_model="test-model",
        smtp_host="old.example.test",
    )
    await configuration.insert()
    assert configuration.id is not None
    return configuration.id


def _change_smtp() -> Concurrent:
    """Another administrator saving new SMTP settings, through its own request."""
    return lambda: _configuration_service().update_smtp(
        SmtpSettingsUpdate(
            enabled=True,
            host="new.example.test",
            username="postmaster",
            password=SecretStr("new-password"),
            from_address="guardian@example.com",
        )
    )


def _read_then(
    monkeypatch: pytest.MonkeyPatch, service: ApplicationConfigurationService, concurrent: Concurrent
) -> None:
    """Let ``concurrent`` land after ``service`` has read the configuration and before it writes."""

    async def stale_read() -> ApplicationConfiguration:
        configuration = await ApplicationConfigurationService._get_or_create()  # noqa: SLF001 - the real read
        await concurrent()
        return configuration

    monkeypatch.setattr(service, "_get_or_create", stale_read)


async def test_an_ai_connection_test_keeps_an_smtp_change_made_while_the_provider_answered() -> None:
    configuration_id = await _stored_configuration()
    service = _configuration_service(_Provider(during=_change_smtp()))

    response = await service.test_ai_connection()

    stored = await ApplicationConfiguration.get(configuration_id)
    assert stored is not None
    assert stored.smtp_host == "new.example.test"
    assert stored.smtp_password_last_four == "word"
    assert response.ok is True
    assert stored.impact_ai_last_test_ok is True
    assert stored.impact_ai_last_test_at is not None
    assert stored.impact_ai_structured_output is not None
    assert stored.impact_ai_structured_output.mode == "json_schema"


@pytest.mark.parametrize(
    "save",
    [
        lambda service: service.update_ai_settings(
            AiSettingsUpdate(enabled=True, base_url=BASE_URL, model="next-model", automatic_summaries=True)
        ),
        lambda service: service.update_impact_ai(
            ImpactAiSettingsUpdate(enabled=False, base_url=BASE_URL, model="next-model")
        ),
    ],
    ids=["ai-settings", "impact-ai"],
)
async def test_saving_ai_settings_keeps_an_smtp_change_it_never_read(
    save: Callable[[ApplicationConfigurationService], Awaitable[object]], monkeypatch: pytest.MonkeyPatch
) -> None:
    configuration_id = await _stored_configuration()
    service = _configuration_service()
    _read_then(monkeypatch, service, _change_smtp())

    await save(service)

    stored = await ApplicationConfiguration.get(configuration_id)
    assert stored is not None
    assert stored.smtp_host == "new.example.test"
    assert stored.smtp_password_last_four == "word"
    assert stored.impact_ai_model == "next-model"


async def test_saving_ai_settings_without_a_key_keeps_a_key_rotated_meanwhile(monkeypatch: pytest.MonkeyPatch) -> None:
    configuration_id = await _stored_configuration()
    service = _configuration_service()

    async def rotate_key() -> None:
        await _configuration_service().update_ai_settings(
            AiSettingsUpdate(enabled=True, base_url=BASE_URL, model="test-model", api_key=SecretStr("rotated-key"))
        )

    _read_then(monkeypatch, service, rotate_key)

    await service.update_ai_settings(
        AiSettingsUpdate(enabled=True, base_url=BASE_URL, model="test-model", automatic_summaries=True)
    )

    stored = await ApplicationConfiguration.get(configuration_id)
    assert stored is not None
    assert stored.impact_ai_api_key_last_four == "-key"
    assert stored.impact_ai_automatic_summaries is True
    runtime = await _configuration_service().ai_runtime()
    assert runtime is not None
    assert runtime.api_key == "rotated-key"


# -- organizations ----------------------------------------------------------


class _Mist:
    """Stands in for Mist's ``/self``; ``during`` runs once, while the first verification is outstanding."""

    def __init__(self, *, during: Concurrent | None = None, rejected: frozenset[str] = frozenset()) -> None:
        self.during = during
        self.rejected = rejected

    async def verify_read_only_token(self, *, token: str, region: object) -> MistOrganizationAccess:  # noqa: ARG002 - mirrors the verification service
        if self.during is not None:
            during, self.during = self.during, None
            await during()
        if token in self.rejected:
            msg = "Mist rejected the credential"
            raise MistVerificationError(msg)
        return MistOrganizationAccess(
            org_id="org-1",
            org_name="Lab",
            privileges=("read", "org"),
            access_mode=MistAccessMode.READ_ONLY,
        )


def _organizations(mist: _Mist | None = None) -> OrganizationService:
    return OrganizationService(_vault(), mist or _Mist())


async def _stored_organization() -> PydanticObjectId:
    await Organization.get_pymongo_collection().delete_many({})
    organization = Organization(
        mist_org_id="org-1",
        name="Lab",
        status=OrganizationStatus.VERIFIED,
        encrypted_service_token=_vault().encrypt("token-a"),
        service_token_last_four="en-a",
    )
    await organization.insert()
    assert organization.id is not None
    return organization.id


async def _stored(organization_id: PydanticObjectId) -> Organization:
    organization = await Organization.get(organization_id)
    assert organization is not None
    return organization


def _webhook_secret(organization: Organization) -> str:
    assert organization.encrypted_webhook_secret is not None
    return _vault().decrypt_for_context(
        organization.encrypted_webhook_secret, context=f"webhook-signature:{organization.mist_org_id}"
    )


async def test_verifying_the_stored_token_keeps_a_webhook_secret_rotated_meanwhile() -> None:
    organization_id = await _stored_organization()
    rotated: list[str] = []

    async def rotate() -> None:
        _organization, secret = await _organizations().rotate_webhook_secret(organization_id)
        rotated.append(secret)

    await _organizations(_Mist(during=rotate)).verify_stored_token(organization_id)

    stored = await _stored(organization_id)
    assert _webhook_secret(stored) == rotated[0]
    assert stored.status is OrganizationStatus.VERIFIED
    assert stored.credential_verified_at is not None


async def test_replacing_the_token_keeps_a_webhook_secret_rotated_meanwhile() -> None:
    organization_id = await _stored_organization()
    rotated: list[str] = []

    async def rotate() -> None:
        _organization, secret = await _organizations().rotate_webhook_secret(organization_id)
        rotated.append(secret)

    await _organizations(_Mist(during=rotate)).replace_service_token(organization_id, "token-b")

    stored = await _stored(organization_id)
    assert _webhook_secret(stored) == rotated[0]
    assert _vault().decrypt(stored.encrypted_service_token) == "token-b"


async def test_a_failed_verification_of_the_old_token_keeps_a_replacement_made_meanwhile() -> None:
    organization_id = await _stored_organization()

    async def replace() -> None:
        await _organizations().replace_service_token(organization_id, "token-b")

    with pytest.raises(MistVerificationError):
        await _organizations(_Mist(during=replace, rejected=frozenset({"token-a"}))).verify_stored_token(
            organization_id
        )

    stored = await _stored(organization_id)
    assert _vault().decrypt(stored.encrypted_service_token) == "token-b"
    assert stored.service_token_last_four == "en-b"
    assert stored.status is OrganizationStatus.VERIFIED
    assert stored.credential_error is None


async def test_updating_settings_keeps_a_webhook_secret_rotated_meanwhile(monkeypatch: pytest.MonkeyPatch) -> None:
    organization_id = await _stored_organization()
    service = _organizations()
    rotated: list[str] = []
    read = service.get

    async def stale_get(identifier: PydanticObjectId) -> Organization:
        organization = await read(identifier)
        _organization, secret = await _organizations().rotate_webhook_secret(identifier)
        rotated.append(secret)
        return organization

    monkeypatch.setattr(service, "get", stale_get)

    await service.update(organization_id, OrganizationUpdateRequest(name="Renamed lab"))

    stored = await _stored(organization_id)
    assert stored.name == "Renamed lab"
    assert _webhook_secret(stored) == rotated[0]


async def test_rotating_the_webhook_secret_keeps_a_token_replaced_meanwhile(monkeypatch: pytest.MonkeyPatch) -> None:
    organization_id = await _stored_organization()
    service = _organizations()
    read = service.get

    async def stale_get(identifier: PydanticObjectId) -> Organization:
        organization = await read(identifier)
        await _organizations().replace_service_token(identifier, "token-b")
        return organization

    monkeypatch.setattr(service, "get", stale_get)

    _organization, secret = await service.rotate_webhook_secret(organization_id)

    stored = await _stored(organization_id)
    assert _vault().decrypt(stored.encrypted_service_token) == "token-b"
    assert _webhook_secret(stored) == secret
