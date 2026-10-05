"""Database-backed checks that one approval request takes exactly one decision.

Two administrators can open the same pending request at once. Whatever each
read, the first decision stored is the decision: a later one must be refused,
not written over it.

Skipped unless ``MONGO_TEST_URL`` names a reachable MongoDB.
"""

import os
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.models.approval import ApprovalStatus, RestoreApproval
from mist_config_guardian_backend.models.organization import MistCloudRegion, Organization, OrganizationStatus
from mist_config_guardian_backend.models.restore import (
    RestoreAction,
    RestoreActionType,
    RestoreMode,
    RestoreOperation,
    RestoreStatus,
)
from mist_config_guardian_backend.models.user import User, UserRole
from mist_config_guardian_backend.services.approvals import (
    ApprovalError,
    ApprovalService,
    BeanieApprovalStore,
    SelfApprovalError,
)

MONGO_URL = os.environ.get("MONGO_TEST_URL")
DATABASE = "approval_decisions"

pytestmark = [
    pytest.mark.skipif(not MONGO_URL, reason="MONGO_TEST_URL is not set"),
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.usefixtures("database"),
]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def database() -> None:
    client = AsyncMongoClient(MONGO_URL, tz_aware=True)
    await client.drop_database(DATABASE)
    await init_beanie(database=client[DATABASE], document_models=[RestoreApproval, RestoreOperation])
    yield
    await client.drop_database(DATABASE)
    await client.close()


class _Notifications:
    async def notify_approval_requested(self, **_fields: object) -> None:
        return None


class _ReadBefore(BeanieApprovalStore):
    """The store as seen by an administrator whose first read predates another writer; later reads are current."""

    def __init__(self, stale: RestoreApproval) -> None:
        self._stale: RestoreApproval | None = stale

    async def find_by_id(self, organization_id, approval_id):
        stale, self._stale = self._stale, None
        return stale if stale is not None else await super().find_by_id(organization_id, approval_id)


def _user(role: UserRole, email: str) -> User:
    return User.model_construct(
        id=PydanticObjectId(),
        email=email,
        display_name=email,
        password_hash="unused",
        role=role,
        is_active=True,
        totp=None,
    )


async def _pending_request() -> tuple[RestoreApproval, User]:
    organization_id = PydanticObjectId()
    operation = RestoreOperation(
        organization_id=organization_id,
        requested_by=PydanticObjectId(),
        mode=RestoreMode.NON_DESTRUCTIVE,
        target_at=datetime(2026, 1, 1, tzinfo=UTC),
        status=RestoreStatus.PLANNED,
        actions=[
            RestoreAction(
                logical_object_id=PydanticObjectId(),
                source_version_id=PydanticObjectId(),
                order=0,
                action=RestoreActionType.UPDATE,
                scope="org",
                object_type="wlans",
                object_name="Corp",
                current_mist_id="mist-0",
                protected_configuration={"ssid": "Corp"},
            )
        ],
    )
    await operation.insert()
    organization = Organization.model_construct(
        id=organization_id,
        mist_org_id="org-1",
        name="Lab",
        cloud_region=MistCloudRegion.GLOBAL_01,
        status=OrganizationStatus.VERIFIED,
    )
    requester = _user(UserRole.OPERATOR, "operator@example.com")
    approval = await ApprovalService(BeanieApprovalStore(), _Notifications()).request(
        organization, operation, requester
    )
    return approval, requester


@pytest.mark.parametrize("first", [True, False])
async def test_a_decision_made_on_a_stale_read_does_not_overwrite_the_first(first: bool) -> None:  # noqa: FBT001
    approval, _requester = await _pending_request()
    assert approval.id is not None
    stale = await RestoreApproval.get(approval.id)
    assert stale is not None
    alice = _user(UserRole.ADMINISTRATOR, "alice@example.com")
    bob = _user(UserRole.ADMINISTRATOR, "bob@example.com")

    await ApprovalService(BeanieApprovalStore(), _Notifications()).decide(
        approval.organization_id, approval.id, alice, approved=first
    )
    with pytest.raises(ApprovalError, match=f"already {'approved' if first else 'rejected'}"):
        await ApprovalService(_ReadBefore(stale), _Notifications()).decide(
            approval.organization_id, approval.id, bob, approved=not first
        )

    stored = await RestoreApproval.get(approval.id)
    assert stored is not None
    assert stored.status is (ApprovalStatus.APPROVED if first else ApprovalStatus.REJECTED)
    assert stored.decided_by == alice.id
    assert stored.decided_by_email == "alice@example.com"


async def test_a_request_reopened_by_the_decider_since_their_read_is_not_theirs_to_decide() -> None:
    approval, _requester = await _pending_request()
    assert approval.id is not None
    stale = await RestoreApproval.get(approval.id)
    assert stale is not None
    alice = _user(UserRole.ADMINISTRATOR, "alice@example.com")
    # Since Alice opened it, the request expired and she asked for approval again herself.
    await RestoreApproval.find_one(RestoreApproval.id == approval.id).update(
        {"$set": {"requested_by": alice.id, "requested_by_email": alice.email}}
    )

    with pytest.raises(SelfApprovalError):
        await ApprovalService(_ReadBefore(stale), _Notifications()).decide(
            approval.organization_id, approval.id, alice, approved=True
        )

    stored = await RestoreApproval.get(approval.id)
    assert stored is not None
    assert stored.status is ApprovalStatus.PENDING
    assert stored.decided_by is None
