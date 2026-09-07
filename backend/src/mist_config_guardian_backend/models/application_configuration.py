"""Application-wide configuration persistence."""

from typing import ClassVar, Literal

from beanie import Document
from pymongo import IndexModel

from mist_config_guardian_backend.models.base import TimestampedModel


class ApplicationConfiguration(TimestampedModel, Document):
    """Singleton configuration managed by local administrators."""

    key: Literal["global"] = "global"
    impact_ai_enabled: bool = False
    impact_ai_base_url: str = ""
    impact_ai_model: str = ""
    encrypted_impact_ai_api_key: str | None = None
    impact_ai_api_key_last_four: str | None = None

    class Settings:
        name = "application_configuration"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel([("key", 1)], unique=True, name="application_configuration_key_unique"),
        ]
