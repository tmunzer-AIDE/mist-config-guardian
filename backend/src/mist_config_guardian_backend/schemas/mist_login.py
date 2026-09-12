"""Mist password authentication input; never persisted."""

from pydantic import BaseModel, EmailStr, Field, SecretStr

from mist_config_guardian_backend.models.organization import MistCloudRegion


class MistLoginCredentials(BaseModel):
    email: EmailStr
    password: SecretStr = Field(min_length=1, max_length=1024)
    two_factor: SecretStr | None = Field(default=None, min_length=1, max_length=64)


class MistLoginRequest(MistLoginCredentials):
    region: MistCloudRegion
