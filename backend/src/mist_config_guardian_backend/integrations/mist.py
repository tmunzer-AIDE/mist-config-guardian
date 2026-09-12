"""Read-only Mist identity verification."""

from dataclasses import dataclass
from enum import StrEnum
from http import HTTPStatus
from typing import Any

import httpx

from mist_config_guardian_backend.integrations.mist_session import (
    MistMfaChallengeError,
    credential_headers,
    login_session,
    logout_session,
)
from mist_config_guardian_backend.models.organization import MistCloudRegion
from mist_config_guardian_backend.schemas.mist_login import MistLoginCredentials

REGION_HOSTS = {
    MistCloudRegion.GLOBAL_01: "https://api.mist.com",
    MistCloudRegion.GLOBAL_02: "https://api.gc1.mist.com",
    MistCloudRegion.GLOBAL_03: "https://api.ac2.mist.com",
    MistCloudRegion.GLOBAL_04: "https://api.gc2.mist.com",
    MistCloudRegion.GLOBAL_05: "https://api.gc4.mist.com",
    MistCloudRegion.EMEA_01: "https://api.eu.mist.com",
    MistCloudRegion.EMEA_02: "https://api.gc3.mist.com",
    MistCloudRegion.EMEA_03: "https://api.ac6.mist.com",
    MistCloudRegion.EMEA_04: "https://api.gc6.mist.com",
    MistCloudRegion.APAC_01: "https://api.ac5.mist.com",
    MistCloudRegion.APAC_02: "https://api.gc5.mist.com",
    MistCloudRegion.APAC_03: "https://api.gc7.mist.com",
}
_READ_ONLY_ROLES = {"read", "readonly", "read_only", "viewer"}
_WRITE_ROLES = {"admin", "super_admin", "write"}


def region_base_url(region: MistCloudRegion) -> str:
    """Return the Mist API base URL for one cloud region."""
    return REGION_HOSTS[region]


class MistAccessMode(StrEnum):
    """Detected access level for an organization privilege."""

    READ_ONLY = "read_only"
    WRITE = "write"
    UNKNOWN = "unknown"


class MistVerificationError(ValueError):
    """Raised when a Mist credential cannot satisfy onboarding requirements."""


class MistMfaRequiredError(MistVerificationError):
    """A Mist login needs a multi-factor code before it can continue."""


@dataclass(frozen=True)
class MistOrganizationAccess:
    """Verified organization identity and access metadata."""

    org_id: str
    org_name: str
    privileges: tuple[str, ...]
    access_mode: MistAccessMode
    actor: str | None = None


class MistVerificationService:
    """Verify a service token without issuing configuration writes."""

    async def login(
        self,
        credentials: MistLoginCredentials,
        region: MistCloudRegion,
        *,
        retain_session: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        payload = {"email": str(credentials.email), "password": credentials.password.get_secret_value()}
        if credentials.two_factor is not None:
            payload["two_factor"] = credentials.two_factor.get_secret_value()
        async with httpx.AsyncClient(base_url=REGION_HOSTS[region], timeout=30) as client:
            retained = False
            try:
                result = await login_session(client, payload)
            except MistMfaChallengeError as exc:
                raise MistMfaRequiredError(str(exc)) from exc
            except (httpx.HTTPError, ValueError) as exc:
                msg = str(exc) if isinstance(exc, ValueError) else "Mist authentication is unavailable; try again"
                raise MistVerificationError(msg) from exc
            else:
                retained = retain_session
                return result
            finally:
                if not retained and client.cookies:
                    await logout_session(client)

    async def verify_read_only_token(
        self,
        *,
        token: str,
        region: MistCloudRegion,
    ) -> MistOrganizationAccess:
        """Verify an organization-scoped token and discover its organization."""
        identity = await self._fetch_identity(token, region)
        privilege = self._sole_org_privilege(identity)

        access_mode = self._access_mode(privilege)
        if access_mode is MistAccessMode.WRITE:
            msg = "The stored service token must be read-only"
            raise MistVerificationError(msg)
        if access_mode is MistAccessMode.UNKNOWN:
            msg = "Mist did not provide enough privilege metadata to prove the token is read-only"
            raise MistVerificationError(msg)

        roles = tuple(str(privilege[key]) for key in ("role", "scope") if privilege.get(key) is not None)
        return MistOrganizationAccess(
            org_id=str(privilege["org_id"]),
            org_name=str(privilege.get("org_name") or privilege.get("name") or privilege["org_id"]),
            privileges=roles,
            access_mode=access_mode,
            actor=str(identity.get("email") or identity.get("name") or "") or None,
        )

    async def verify_write_token(
        self,
        *,
        token: str,
        org_id: str,
        region: MistCloudRegion,
    ) -> MistOrganizationAccess:
        """Verify a freshly supplied Mist administrator credential."""
        identity = await self._fetch_identity(token, region)
        privilege = self._find_org_privilege(identity, org_id)
        if privilege is None:
            msg = "The Mist administrator does not have access to the requested organization"
            raise MistVerificationError(msg)
        access_mode = self._access_mode(privilege)
        if access_mode is not MistAccessMode.WRITE:
            msg = "A Mist administrator credential with write access is required"
            raise MistVerificationError(msg)
        roles = tuple(str(privilege[key]) for key in ("role", "scope") if privilege.get(key) is not None)
        return MistOrganizationAccess(
            org_id=org_id,
            org_name=str(privilege.get("org_name") or privilege.get("name") or org_id),
            privileges=roles,
            access_mode=access_mode,
            actor=str(identity.get("email") or identity.get("name") or "") or None,
        )

    @staticmethod
    async def _fetch_identity(
        token: str,
        region: MistCloudRegion,
    ) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(
                base_url=REGION_HOSTS[region],
                headers=credential_headers(token),
                timeout=30,
            ) as client:
                response = await client.get("/api/v1/self")
        except httpx.HTTPError as exc:
            msg = "Mist identity verification is unavailable; try again"
            raise MistVerificationError(msg) from exc
        try:
            identity = response.json()
        except ValueError as exc:
            msg = "Mist returned an invalid identity response"
            raise MistVerificationError(msg) from exc
        if response.status_code != HTTPStatus.OK or not isinstance(identity, dict):
            msg = "Mist rejected the credential"
            raise MistVerificationError(msg)
        return identity

    @staticmethod
    def _find_org_privilege(identity: dict[str, Any], org_id: str) -> dict[str, Any] | None:
        privileges = identity.get("privileges")
        if not isinstance(privileges, list):
            return None
        for privilege in privileges:
            if isinstance(privilege, dict) and privilege.get("org_id") == org_id and privilege.get("scope") == "org":
                return privilege
        return None

    @staticmethod
    def _sole_org_privilege(identity: dict[str, Any]) -> dict[str, Any]:
        privileges = identity.get("privileges")
        if not isinstance(privileges, list):
            msg = "Mist did not return organization privileges for this token"
            raise MistVerificationError(msg)
        org_privileges = [
            privilege
            for privilege in privileges
            if isinstance(privilege, dict)
            and privilege.get("scope") == "org"
            and isinstance(privilege.get("org_id"), str)
        ]
        org_ids = {str(privilege["org_id"]) for privilege in org_privileges}
        if len(org_ids) != 1:
            msg = "An organization API token with access to exactly one organization is required"
            raise MistVerificationError(msg)
        return org_privileges[0]

    @staticmethod
    def _access_mode(privilege: dict[str, Any]) -> MistAccessMode:
        role = str(privilege.get("role") or "").lower()
        if role in _READ_ONLY_ROLES:
            return MistAccessMode.READ_ONLY
        if role in _WRITE_ROLES:
            return MistAccessMode.WRITE
        return MistAccessMode.UNKNOWN
