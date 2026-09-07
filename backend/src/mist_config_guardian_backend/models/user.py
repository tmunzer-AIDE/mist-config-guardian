"""Local user persistence."""

from enum import StrEnum
from typing import ClassVar

from beanie import Document
from pydantic import EmailStr
from pymongo import IndexModel

from mist_config_guardian_backend.models.base import TimestampedModel


class UserRole(StrEnum):
    """Application authorization role."""

    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMINISTRATOR = "administrator"


class User(TimestampedModel, Document):
    """A local application user."""

    email: EmailStr
    display_name: str
    password_hash: str
    role: UserRole = UserRole.VIEWER
    is_active: bool = True

    class Settings:
        name = "users"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel([("email", 1)], unique=True, name="user_email_unique"),
            IndexModel([("role", 1), ("is_active", 1)]),
        ]
