"""Read-only Mist service credential access and legacy migration."""

from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.security.credentials import CredentialVault


async def service_token(
    organization: Organization,
    vault: CredentialVault,
) -> str:
    """Decrypt a service token and migrate legacy ciphertext atomically."""
    plaintext, replacement = vault.decrypt_with_migration(
        organization.encrypted_service_token,
    )
    if replacement is not None and organization.id is not None:
        previous = organization.encrypted_service_token
        await Organization.find_one(
            Organization.id == organization.id,
            Organization.encrypted_service_token == previous,
        ).update(
            {
                "$set": {
                    "encrypted_service_token": replacement,
                    "updated_at": utc_now(),
                }
            }
        )
        organization.encrypted_service_token = replacement
    return plaintext
