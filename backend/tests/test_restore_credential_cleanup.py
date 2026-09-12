"""Unused delegated sessions are revoked without touching another task's credential."""

import asyncio
import copy
import json
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from beanie import PydanticObjectId
from pymongo import ReturnDocument

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.integrations.mist import MistVerificationService
from mist_config_guardian_backend.integrations.mist_session import SESSION_PREFIX
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.organization import MistCloudRegion, Organization
from mist_config_guardian_backend.models.restore import RestoreOperation, RestoreStatus
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.restore_authorization import RestoreAuthorizationService

BASE = "https://api.eu.mist.com"
SESSION = SESSION_PREFIX + json.dumps({"cookie": "sessionid.eu=session", "csrf": "csrf", "origin": BASE})


class Collection:
    """Atomic preimage update stand-in; no await between match and mutation."""

    def __init__(self):
        self.documents = []

    async def find_one_and_update(self, criteria, update, *, return_document, projection):
        assert return_document == ReturnDocument.BEFORE
        assert projection == {"encrypted_delegated_credential": 1, "organization_id": 1}
        for document in self.documents:
            if not all(
                document.get(key) is not None and document[key] <= value["$lte"]
                if isinstance(value, dict)
                else document.get(key) == value
                for key, value in criteria.items()
            ):
                continue
            before = copy.deepcopy(document)
            document.update(update["$set"])
            for key, value in update.get("$push", {}).items():
                document.setdefault(key, []).append(value)
            return before
        return None


@pytest.fixture
def cleanup(monkeypatch):
    settings = Settings(environment="test")
    vault = CredentialVault(settings)
    service = RestoreAuthorizationService(settings, vault, MistVerificationService())
    collection = Collection()
    monkeypatch.setattr(RestoreOperation, "get_pymongo_collection", lambda: collection)
    monkeypatch.setattr(
        Organization, "get", AsyncMock(return_value=SimpleNamespace(cloud_region=MistCloudRegion.EMEA_01))
    )
    return service, vault, collection


def queued(vault, credential=SESSION, *, status=RestoreStatus.QUEUED, expired=True):
    operation_id = PydanticObjectId()
    return {
        "_id": operation_id,
        "organization_id": PydanticObjectId(),
        "status": status,
        "task_id": "task-1",
        "encrypted_delegated_credential": vault.encrypt_for_context(credential, context=f"restore:{operation_id}"),
        "delegated_credential_expires_at": utc_now() + timedelta(minutes=-1 if expired else 10),
    }


async def test_delivery_failure_revokes_once_with_regional_session_and_csrf(cleanup, httpx_mock):
    service, vault, collection = cleanup
    operation = queued(vault, expired=False)
    collection.documents.append(operation)

    def logout(request):
        # The old task has been atomically released before the network await.
        assert operation["status"] == RestoreStatus.PLANNED
        assert operation["encrypted_delegated_credential"] is None
        assert request.headers["cookie"] == "sessionid.eu=session"
        assert request.headers["X-CSRFToken"] == "csrf"
        assert "authorization" not in request.headers
        return httpx.Response(200)

    httpx_mock.add_callback(logout, url=BASE + "/api/v1/logout", method="POST")
    await asyncio.gather(service.release(operation["_id"], "task-1"), service.release(operation["_id"], "task-1"))
    assert operation["task_id"] is None
    assert operation["delegated_credential_expires_at"] is None
    assert len(httpx_mock.get_requests()) == 1


@pytest.mark.parametrize("running", [False, True])
async def test_release_does_not_revoke_another_task_or_running_operation(cleanup, running):
    service, vault, collection = cleanup
    operation = queued(vault, status=RestoreStatus.RUNNING if running else RestoreStatus.QUEUED)
    collection.documents.append(operation)
    before = copy.deepcopy(operation)
    await service.release(operation["_id"], "task-1" if running else "old-task")
    assert operation == before


@pytest.mark.parametrize("method", ["release", "expiry"])
async def test_logout_timeout_does_not_prevent_local_cleanup(cleanup, httpx_mock, method):
    service, vault, collection = cleanup
    operation = queued(vault)
    collection.documents.append(operation)
    httpx_mock.add_exception(httpx.ReadTimeout("Mist unavailable"), url=BASE + "/api/v1/logout")
    if method == "release":
        await service.release(operation["_id"], "task-1")
        assert operation["status"] == RestoreStatus.PLANNED
    else:
        assert await service.expire_stale_credentials() == 1
        assert operation["status"] == RestoreStatus.FAILED
    assert operation["encrypted_delegated_credential"] is None
    assert operation["delegated_credential_expires_at"] is None


async def test_expiry_cleans_each_expired_credential_and_skips_live_work(cleanup, httpx_mock):
    service, vault, collection = cleanup
    session, token, corrupt = queued(vault), queued(vault, "api-token"), queued(vault)
    corrupt["encrypted_delegated_credential"] = "broken"
    fresh, running = queued(vault, expired=False), queued(vault, status=RestoreStatus.RUNNING)
    untouched = copy.deepcopy([fresh, running])
    collection.documents.extend([session, token, corrupt, fresh, running])
    httpx_mock.add_response(url=BASE + "/api/v1/logout", status_code=200)
    assert await service.expire_stale_credentials() == 3
    assert await service.expire_stale_credentials() == 0
    for operation in [session, token, corrupt]:
        assert operation["status"] == RestoreStatus.FAILED
        assert operation["encrypted_delegated_credential"] is None
        assert operation["delegated_credential_expires_at"] is None
        assert operation["completed_at"] is not None
        assert len(operation["preflight_errors"]) == 1
    assert [fresh, running] == untouched
    assert len(httpx_mock.get_requests()) == 1


async def test_release_of_api_token_does_not_attempt_logout(cleanup):
    service, vault, collection = cleanup
    operation = queued(vault, "api-token")
    collection.documents.append(operation)
    await service.release(operation["_id"], "task-1")
    assert operation["status"] == RestoreStatus.PLANNED
    assert operation["encrypted_delegated_credential"] is None
