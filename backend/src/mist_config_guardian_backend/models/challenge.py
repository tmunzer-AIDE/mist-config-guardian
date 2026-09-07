"""Short-lived enrollment and ceremony state shared across API replicas.

Both documents hold state that only has to survive the seconds between two
requests, but the chart supports horizontal API scaling, so the second request
may land on a different replica than the first. Keeping them in MongoDB with a
TTL index makes enrollment and passkey ceremonies correct under any replica
count, and lets expiry be enforced by the database rather than by a sweep.
"""

from datetime import datetime
from typing import ClassVar, Literal

from beanie import Document, PydanticObjectId
from pymongo import IndexModel

from mist_config_guardian_backend.models.base import TimestampedModel


class PendingTotpEnrollment(TimestampedModel, Document):
    """An unconfirmed, encrypted TOTP secret between enroll and confirm."""

    user_id: PydanticObjectId
    encrypted_secret: str
    expires_at: datetime

    class Settings:
        name = "pending_totp_enrollments"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel([("user_id", 1)], unique=True, name="pending_totp_user_unique"),
            IndexModel([("expires_at", 1)], expireAfterSeconds=0, name="pending_totp_ttl"),
        ]


class WebAuthnChallenge(TimestampedModel, Document):
    """One issued WebAuthn challenge, held under an opaque handle.

    The challenge is consumed exactly once. A registration challenge is bound to
    the enrolling user; an authentication challenge has no user until the
    assertion identifies one.
    """

    handle: str
    challenge: str
    purpose: Literal["registration", "authentication"]
    user_id: str | None = None
    expires_at: datetime

    class Settings:
        name = "webauthn_challenges"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel([("handle", 1)], unique=True, name="webauthn_challenge_handle_unique"),
            IndexModel([("expires_at", 1)], expireAfterSeconds=0, name="webauthn_challenge_ttl"),
        ]
