"""Mist login, partial authentication, delegated sessions and account boundaries."""

import json
from unittest.mock import AsyncMock

import pytest
from beanie import PydanticObjectId
from fastapi import HTTPException, Request, Response
from pydantic import ValidationError

from mist_config_guardian_backend.api.routes.auth import mist_login
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.integrations.mist import MistVerificationError, MistVerificationService
from mist_config_guardian_backend.integrations.mist_mutation import MistMutationClient
from mist_config_guardian_backend.integrations.mist_session import credential_headers
from mist_config_guardian_backend.models.organization import MistCloudRegion
from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.schemas.mist_login import MistLoginCredentials, MistLoginRequest
from mist_config_guardian_backend.schemas.restore import RestoreExecuteRequest

EMAIL = "admin@example.com"
BASE = "https://api.eu.mist.com"


def credentials():
    return MistLoginCredentials(email=EMAIL, password="secret password", two_factor="123456")


def responses(httpx_mock, identity=None, *, logout=True):
    httpx_mock.add_response(
        url=BASE + "/api/v1/login",
        json={},
        headers=[
            ("set-cookie", "csrftoken.eu=csrf; Path=/; Secure"),
            ("set-cookie", "sessionid.eu=session; Path=/; Secure"),
        ],
    )
    httpx_mock.add_response(
        url=BASE + "/api/v1/self",
        json=identity
        or {
            "email": EMAIL,
            "two_factor_required": True,
            "two_factor_passed": True,
        },
    )
    if logout:
        httpx_mock.add_response(url=BASE + "/api/v1/logout", status_code=200)


async def test_login_uses_region_mfa_and_logs_out_without_retaining_password(httpx_mock):
    responses(httpx_mock)
    credential, identity = await MistVerificationService().login(credentials(), MistCloudRegion.EMEA_01)
    requests = httpx_mock.get_requests()
    assert json.loads(requests[0].content)["two_factor"] == "123456"
    assert requests[1].headers["X-CSRFToken"] == "csrf"
    assert "sessionid.eu=session" in requests[1].headers["cookie"]
    assert requests[2].url.path == "/api/v1/logout"
    assert "secret password" not in credential
    assert "123456" not in credential
    assert identity["email"] == EMAIL


@pytest.mark.parametrize(
    "identity",
    [
        {"email": EMAIL, "two_factor_required": True, "two_factor_passed": False},
        {"email": EMAIL, "two_factor_required": True},
        {"email": "someone-else@example.com"},
        {"privileges": []},
    ],
)
async def test_login_rejects_partial_or_mismatched_identity_and_closes_session(httpx_mock, identity):
    responses(httpx_mock, identity)
    with pytest.raises(MistVerificationError):
        await MistVerificationService().login(credentials(), MistCloudRegion.EMEA_01, retain_session=True)
    assert httpx_mock.get_requests()[-1].url.path == "/api/v1/logout"


async def test_rejected_login_does_not_create_session(httpx_mock):
    httpx_mock.add_response(url=BASE + "/api/v1/login", status_code=401)
    with pytest.raises(MistVerificationError, match="rejected"):
        await MistVerificationService().login(credentials(), MistCloudRegion.EMEA_01)


async def test_restore_session_survives_handoff_and_worker_logs_out(httpx_mock):
    responses(httpx_mock, logout=False)
    credential, _ = await MistVerificationService().login(credentials(), MistCloudRegion.EMEA_01, retain_session=True)
    assert len(httpx_mock.get_requests()) == 2
    assert "Authorization" not in credential_headers(credential)
    httpx_mock.add_response(url=BASE + "/api/v1/logout", status_code=200)
    async with MistMutationClient(token=credential, region=MistCloudRegion.EMEA_01):
        pass
    request = httpx_mock.get_requests()[-1]
    assert request.headers["X-CSRFToken"] == "csrf"
    assert "sessionid.eu=session" in request.headers["cookie"]


async def test_site_admin_cannot_authorize_whole_org(httpx_mock):
    httpx_mock.add_response(
        url=BASE + "/api/v1/self",
        json={
            "privileges": [
                {"org_id": "org-1", "scope": "site", "role": "admin"},
            ]
        },
    )
    with pytest.raises(MistVerificationError, match="does not have access"):
        await MistVerificationService().verify_write_token(
            token="token", org_id="org-1", region=MistCloudRegion.EMEA_01
        )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"administrator_token": "token", "mist_login": {"email": EMAIL, "password": "p"}},
        {"administrator_token": "mist-session:{}"},
    ],
)
def test_restore_rejects_ambiguous_or_internal_credentials(payload):
    with pytest.raises(ValidationError):
        RestoreExecuteRequest.model_validate(payload)


def test_restore_login_does_not_require_region_and_preserves_password():
    request = RestoreExecuteRequest.model_validate({"mist_login": {"email": EMAIL, "password": "  password  "}})
    assert request.mist_login.password.get_secret_value() == "  password  "
    assert "password  " not in repr(request)


@pytest.mark.parametrize("local_mfa", [False, True])
async def test_mist_signin_keeps_local_mfa_and_never_autoprovisions(monkeypatch, local_mfa):
    from mist_config_guardian_backend.api.routes import auth  # noqa: PLC0415

    user = User.model_construct(id=PydanticObjectId(), email=EMAIL, totp=object() if local_mfa else None)
    lookup = AsyncMock(return_value=user)
    monkeypatch.setattr(User, "find_one", lookup)
    complete = AsyncMock(return_value="completed")
    monkeypatch.setattr(auth, "_complete_sign_in", complete)
    throttle = AsyncMock()
    throttle.account = lambda email: email
    throttle.address = lambda _request: "address"
    monkeypatch.setattr(auth, "reserve_or_raise", AsyncMock())
    mist = AsyncMock()
    mist.login.return_value = ("session", {"email": EMAIL})
    mfa = AsyncMock()
    mfa.issue_login_challenge.return_value = "challenge"
    args = dict(  # noqa: C408 - named route arguments
        payload=MistLoginRequest(**credentials().model_dump(), region=MistCloudRegion.EMEA_01),
        request=Request({"type": "http", "headers": []}),
        response=Response(),
        users=AsyncMock(),
        sessions=AsyncMock(),
        mfa=mfa,
        passkeys=AsyncMock(),
        settings=Settings(environment="test"),
        throttle=throttle,
        mist=mist,
    )
    result = await mist_login(**args)
    if local_mfa:
        assert result.mfa_required
        complete.assert_not_called()
    else:
        assert result == "completed"
        assert complete.call_args.kwargs["mfa_verified"] is False
    assert lookup.call_args.args[0] == {"email": EMAIL, "is_active": True, "status": "active"}
    lookup.return_value = None
    with pytest.raises(HTTPException) as exc:
        await mist_login(**args)
    assert exc.value.status_code == 401


async def test_pending_login_response_cannot_become_a_full_session(httpx_mock):
    httpx_mock.add_response(
        url=BASE + "/api/v1/login",
        json={"two_factor_required": True},
        headers=[
            ("set-cookie", "csrftoken.eu=csrf; Path=/"),
            ("set-cookie", "sessionid.eu=session; Path=/"),
        ],
    )
    httpx_mock.add_response(url=BASE + "/api/v1/logout", status_code=200)
    with pytest.raises(MistVerificationError, match="multi-factor"):
        await MistVerificationService().login(credentials(), MistCloudRegion.EMEA_01, retain_session=True)


async def test_restore_authorization_uses_saved_region_and_encrypts_only_session(monkeypatch):
    from types import SimpleNamespace  # noqa: PLC0415
    from unittest.mock import MagicMock  # noqa: PLC0415

    from beanie.odm.fields import ExpressionField  # noqa: PLC0415

    from mist_config_guardian_backend.models.organization import Organization  # noqa: PLC0415
    from mist_config_guardian_backend.models.restore import RestoreOperation, RestoreStatus  # noqa: PLC0415
    from mist_config_guardian_backend.services import restore_authorization as module  # noqa: PLC0415

    organization_id, operation_id = PydanticObjectId(), PydanticObjectId()
    organization = SimpleNamespace(mist_org_id="org-1", cloud_region=MistCloudRegion.EMEA_01)
    operation = SimpleNamespace(id=operation_id, status=RestoreStatus.PLANNED, preflight_errors=[], actions=[])
    for field in ("id", "organization_id", "status"):
        monkeypatch.setattr(RestoreOperation, field, ExpressionField(field), raising=False)
    monkeypatch.setattr(Organization, "get", AsyncMock(return_value=organization))
    monkeypatch.setattr(RestoreOperation, "get", AsyncMock(return_value=operation))
    query = SimpleNamespace(update=AsyncMock(return_value=SimpleNamespace(modified_count=1)))

    async def load():
        return operation

    monkeypatch.setattr(RestoreOperation, "find_one", MagicMock(side_effect=[load(), query]))
    throttle = AsyncMock()
    throttle.account = lambda email: email
    monkeypatch.setattr(module, "get_throttle_service", lambda _settings: throttle)
    monkeypatch.setattr(module, "reserve_or_raise", AsyncMock())
    mist, vault = AsyncMock(), MagicMock()
    mist.login.return_value = ("mist-session:opaque", {"email": EMAIL})
    mist.verify_write_token.return_value = SimpleNamespace(actor=EMAIL)
    vault.encrypt_for_context.return_value = "encrypted-session"
    service = module.RestoreAuthorizationService(Settings(environment="test"), vault, mist)
    supplied = credentials()
    await service.authorize(organization_id, operation_id, supplied, "task")
    mist.login.assert_awaited_once_with(supplied, MistCloudRegion.EMEA_01, retain_session=True)
    mist.verify_write_token.assert_awaited_once_with(
        token="mist-session:opaque", org_id="org-1", region=MistCloudRegion.EMEA_01
    )
    vault.encrypt_for_context.assert_called_once_with("mist-session:opaque", context=f"restore:{operation_id}")
    saved = query.update.call_args.args[0]["$set"]
    assert saved["encrypted_delegated_credential"] == "encrypted-session"
    assert saved["credential_actor"] == EMAIL
