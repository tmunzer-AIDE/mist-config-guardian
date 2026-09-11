"""Safety snapshots, compensating plans, and their credential requirements."""

from datetime import UTC, datetime

import httpx
import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.api.dependencies import get_current_user, require_organization
from mist_config_guardian_backend.api.routes.approvals import get_approval_service
from mist_config_guardian_backend.api.routes.restores import (
    get_plan_state_store,
    get_restore_compensation_service,
    get_restore_plans,
)
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.integrations.mist_mutation import MistMutationError
from mist_config_guardian_backend.main import create_app
from mist_config_guardian_backend.models.organization import (
    MistCloudRegion,
    Organization,
    OrganizationStatus,
)
from mist_config_guardian_backend.models.restore import (
    RestoreAction,
    RestoreActionStatus,
    RestoreActionType,
    RestoreMode,
    RestoreOperation,
    RestoreStatus,
)
from mist_config_guardian_backend.models.snapshot import ObjectVersion, VersionEvent
from mist_config_guardian_backend.models.user import User, UserRole
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.approvals import ApprovalService, compute_plan_hash
from mist_config_guardian_backend.services.mfa import require_fresh_mfa
from mist_config_guardian_backend.services.restore_compensation import (
    RestoreCompensationError,
    RestoreCompensationService,
    capture_safety_snapshot,
)
from mist_config_guardian_backend.services.restore_planner import (
    RestoreOperationState,
    SafetySnapshotEntry,
)
from mist_config_guardian_backend.snapshots.canonical import (
    configuration_hash,
    legacy_configuration_hash,
)
from mist_config_guardian_backend.snapshots.registry import get_definition
from mist_config_guardian_backend.snapshots.secrets import (
    find_unavailable_secrets,
    is_protected,
    protect_configuration,
    reveal_configuration,
)

ORGANIZATION_ID = PydanticObjectId()
OPERATION_ID = PydanticObjectId()
COMPENSATION_ID = PydanticObjectId()
ADMINISTRATOR_ID = PydanticObjectId()

CORP_WLAN = {"name": "Corp", "psk": "super-secret", "enabled": True}
IGNORED = frozenset({"created_time", "modified_time", "last_seen"})
GUEST_WLAN = {"name": "Guest", "enabled": False}


def _vault() -> CredentialVault:
    return CredentialVault(Settings(environment="test", credential_encryption_key="test-key"))


def _organization() -> Organization:
    return Organization.model_construct(
        id=ORGANIZATION_ID,
        mist_org_id="org-1",
        name="Lab",
        cloud_region=MistCloudRegion.GLOBAL_01,
        status=OrganizationStatus.VERIFIED,
        encrypted_service_token="v1:encrypted-value",
        service_token_last_four="alue",
    )


def _action(
    order: int,
    action: RestoreActionType,
    *,
    expected_current_hash: str | None = None,
    resulting_mist_id: str | None = None,
    status: RestoreActionStatus = RestoreActionStatus.PENDING,
) -> RestoreAction:
    return RestoreAction(
        logical_object_id=PydanticObjectId(),
        source_version_id=PydanticObjectId(),
        order=order,
        action=action,
        scope="site",
        object_type="wlans",
        object_name=f"wlan-{order}",
        current_mist_id=f"mist-{order}",
        site_mist_id="site-a",
        protected_configuration={"name": f"wlan-{order}"},
        expected_current_hash=expected_current_hash,
        status=status,
        resulting_mist_id=resulting_mist_id,
    )


def _operation(
    actions: list[RestoreAction],
    *,
    status: RestoreStatus = RestoreStatus.COMPENSATION_AVAILABLE,
    identifier: PydanticObjectId = OPERATION_ID,
) -> RestoreOperation:
    return RestoreOperation.model_construct(
        id=identifier,
        organization_id=ORGANIZATION_ID,
        requested_by=ADMINISTRATOR_ID,
        mode=RestoreMode.NON_DESTRUCTIVE,
        include_dependencies=True,
        target_at=datetime(2026, 1, 1, tzinfo=UTC),
        status=status,
        actions=actions,
        warnings=[],
        preflight_errors=[],
        credential_actor="admin@example.com",
        started_at=None,
        completed_at=None,
        failure_action_order=None,
        task_id=None,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        updated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


class _FakeMistClient:
    """Returns canned live state for every plan target."""

    def __init__(self, live: dict[str, dict[str, object] | None]) -> None:
        self.live = live
        self.reads: list[str] = []

    async def get_current(self, definition, object_id, *, org_id, site_id):  # noqa: ARG002
        self.reads.append(object_id)
        return self.live.get(object_id)


class _MemoryStateStore:
    """In-memory plan-lifecycle state keyed the same way MongoDB keys it."""

    def __init__(self) -> None:
        self.items: dict[tuple[PydanticObjectId, PydanticObjectId], RestoreOperationState] = {}

    async def load(self, organization_id, operation_id):
        return self.items.get((organization_id, operation_id))

    async def save(self, state):
        self.items[(state.organization_id, state.operation_id)] = state

    async def find_compensation_of(self, organization_id, operation_id):
        return next(
            (
                state
                for state in self.items.values()
                if state.organization_id == organization_id and state.compensates_operation_id == operation_id
            ),
            None,
        )


@pytest.fixture
def offline_documents(monkeypatch: pytest.MonkeyPatch) -> None:
    """Let restore documents be built and inserted without a live MongoDB."""
    monkeypatch.setattr(RestoreOperation, "get_pymongo_collection", classmethod(lambda cls: None))  # noqa: ARG005

    async def _insert(self, *_args, **_kwargs):
        self.id = COMPENSATION_ID
        return self

    monkeypatch.setattr(RestoreOperation, "insert", _insert)

    async def _version(_document_id, *_args, **_kwargs):
        return None

    monkeypatch.setattr(ObjectVersion, "get", _version)


# ------------------------------------------------------------- safety snapshot


async def test_safety_snapshot_records_the_pre_restore_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version",
        _no_stored_version,
    )
    corp_hash = configuration_hash(CORP_WLAN, ignored_fields=IGNORED)
    operation = _operation(
        [
            _action(0, RestoreActionType.CREATE),
            _action(1, RestoreActionType.UPDATE, expected_current_hash=corp_hash),
        ]
    )
    client = _FakeMistClient({"mist-1": dict(CORP_WLAN)})

    entries = await capture_safety_snapshot(client, _organization(), operation, _vault())

    assert [entry.existed for entry in entries] == [False, True]
    assert entries[0].configuration == {}
    assert entries[1].configuration["name"] == "Corp"
    assert is_protected(entries[1].configuration["psk"])
    assert "super-secret" not in str(entries[1].configuration)
    assert entries[1].configuration_hash == corp_hash


async def test_a_changed_live_object_aborts_before_any_write(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version",
        _no_stored_version,
    )
    operation = _operation([_action(0, RestoreActionType.UPDATE, expected_current_hash="stale-hash")])
    client = _FakeMistClient({"mist-0": dict(CORP_WLAN)})

    with pytest.raises(MistMutationError, match="changed after this plan was reviewed"):
        await capture_safety_snapshot(client, _organization(), operation, _vault())


async def test_a_deleted_live_object_aborts_before_any_write(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version",
        _no_stored_version,
    )
    operation = _operation([_action(0, RestoreActionType.UPDATE, expected_current_hash="any")])

    with pytest.raises(MistMutationError, match="no longer exists"):
        await capture_safety_snapshot(_FakeMistClient({}), _organization(), operation, _vault())


async def test_relaxed_capture_accepts_the_state_a_restore_already_replaced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version",
        _no_stored_version,
    )
    operation = _operation([_action(0, RestoreActionType.UPDATE, expected_current_hash=None)])
    client = _FakeMistClient({"mist-0": dict(GUEST_WLAN)})

    entries = await capture_safety_snapshot(client, _organization(), operation, _vault(), relaxed=True)

    assert entries[0].existed is True


def _stored_version(configuration: dict[str, object], digest: str) -> ObjectVersion:
    return ObjectVersion.model_construct(
        id=PydanticObjectId(),
        organization_id=ORGANIZATION_ID,
        logical_object_id=PydanticObjectId(),
        incarnation_id=PydanticObjectId(),
        version=1,
        event=VersionEvent.UPDATED,
        configuration=dict(configuration),
        configuration_hash=digest,
        is_deleted=False,
    )


async def test_a_plan_whose_expected_hash_predates_the_key_still_validates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A restore reviewed before the hash was keyed is not made unrunnable by it."""
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version",
        _no_stored_version,
    )
    legacy = legacy_configuration_hash(CORP_WLAN, ignored_fields=IGNORED)
    operation = _operation([_action(0, RestoreActionType.UPDATE, expected_current_hash=legacy)])
    client = _FakeMistClient({"mist-0": dict(CORP_WLAN)})

    entries = await capture_safety_snapshot(client, _organization(), operation, _vault())

    assert [entry.existed for entry in entries] == [True]


async def test_a_plan_whose_expected_hash_predates_the_key_still_detects_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version",
        _no_stored_version,
    )
    legacy = legacy_configuration_hash(CORP_WLAN, ignored_fields=IGNORED)
    operation = _operation([_action(0, RestoreActionType.UPDATE, expected_current_hash=legacy)])
    client = _FakeMistClient({"mist-0": {**CORP_WLAN, "enabled": False}})

    with pytest.raises(MistMutationError, match="changed after this plan was reviewed"):
        await capture_safety_snapshot(client, _organization(), operation, _vault())


async def test_compensation_finds_the_stored_secrets_after_the_digest_is_migrated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The keyed hash migrates in the background, including between a restore
    failing and its reversal being built.

    Comparing the snapshot's digest with the one now stored beside the version
    reads a migration as a changed configuration. The reversal then falls back
    to the live read, and what a live read holds for a secret is the mask Mist
    returns — so undoing a failed restore would set the secret to `********`.
    """
    vault = _vault()
    definition = get_definition("site", "wlans")
    assert definition is not None
    stored = _stored_version(
        protect_configuration(CORP_WLAN, vault, sensitive_fields=definition.sensitive_fields),
        # Already rewritten by the backfill.
        configuration_hash(CORP_WLAN, ignored_fields=IGNORED),
    )
    entry = SafetySnapshotEntry(
        logical_object_id=stored.logical_object_id,
        order=0,
        action=RestoreActionType.UPDATE,
        scope="site",
        object_type="wlans",
        object_name="wlan-0",
        mist_object_id="mist-0",
        existed=True,
        configuration=protect_configuration(CORP_WLAN, vault, sensitive_fields=definition.sensitive_fields),
        # Captured before the backfill reached that version.
        configuration_hash=legacy_configuration_hash(CORP_WLAN, ignored_fields=IGNORED),
        pre_version_id=stored.id,
    )

    async def _stored_by_id(_version_id: object) -> ObjectVersion:
        return stored

    monkeypatch.setattr(ObjectVersion, "get", _stored_by_id)
    service = RestoreCompensationService(_MemoryStateStore(), vault)

    inverse = await service._invert(_action(0, RestoreActionType.UPDATE), entry, 0)  # noqa: SLF001

    # Both hold the same plaintext but were encrypted separately, so the
    # ciphertext says which one the reversal will actually write.
    assert inverse.protected_configuration == stored.configuration
    assert inverse.protected_configuration != entry.configuration


async def _inverse_of(entry: SafetySnapshotEntry, stored: ObjectVersion, monkeypatch, vault) -> RestoreAction:
    async def _stored_by_id(_version_id: object) -> ObjectVersion:
        return stored

    monkeypatch.setattr(ObjectVersion, "get", _stored_by_id)
    service = RestoreCompensationService(_MemoryStateStore(), vault)
    return await service._invert(_action(0, RestoreActionType.UPDATE), entry, 0)  # noqa: SLF001


def _entry(configuration: dict[str, object], stored: ObjectVersion, vault: CredentialVault) -> SafetySnapshotEntry:
    definition = get_definition("site", "wlans")
    assert definition is not None
    return SafetySnapshotEntry(
        logical_object_id=stored.logical_object_id,
        order=0,
        action=RestoreActionType.UPDATE,
        scope="site",
        object_type="wlans",
        object_name="wlan-0",
        mist_object_id="mist-0",
        existed=True,
        configuration=protect_configuration(configuration, vault, sensitive_fields=definition.sensitive_fields),
        configuration_hash=configuration_hash(configuration, ignored_fields=IGNORED),
        pre_version_id=stored.id,
    )


async def test_compensation_recovers_a_secret_mist_would_only_return_masked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The one case the stored version exists for is the one that has to work.

    Mist returns some secrets as `********`, so the snapshot holds a mask where
    the stored version holds the real value. Comparing the two as wholes never
    matches there, and compensation carried the mask forward — into a plan
    authorization then refused for requiring a secret it did not have.
    """
    vault = _vault()
    definition = get_definition("site", "wlans")
    assert definition is not None
    stored = _stored_version(
        protect_configuration(CORP_WLAN, vault, sensitive_fields=definition.sensitive_fields),
        configuration_hash(CORP_WLAN, ignored_fields=IGNORED),
    )
    # What the live read actually returned when the snapshot was taken.
    entry = _entry({**CORP_WLAN, "psk": "********"}, stored, vault)

    inverse = await _inverse_of(entry, stored, monkeypatch, vault)

    assert reveal_configuration(inverse.protected_configuration, vault)["psk"] == "super-secret"


async def test_compensation_keeps_a_secret_mist_did_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A secret that came back real and differs is a real difference.

    Leaving every sensitive field out of the comparison would have made this
    look like the same object and put the older secret back.
    """
    vault = _vault()
    definition = get_definition("site", "wlans")
    assert definition is not None
    stored = _stored_version(
        protect_configuration(CORP_WLAN, vault, sensitive_fields=definition.sensitive_fields),
        configuration_hash(CORP_WLAN, ignored_fields=IGNORED),
    )
    entry = _entry({**CORP_WLAN, "psk": "rotated-since"}, stored, vault)

    inverse = await _inverse_of(entry, stored, monkeypatch, vault)

    assert reveal_configuration(inverse.protected_configuration, vault)["psk"] == "rotated-since"


# An object can carry the same secret field in more than one place.
NESTED_WLAN: dict[str, object] = {
    "name": "Corp",
    "enabled": True,
    "auth_servers": [
        {"host": "radius-1.example", "secret": "primary-shared-secret"},
        {"host": "radius-2.example", "secret": "backup-shared-secret"},
    ],
}


def _nested(masked_primary: str, backup: str) -> dict[str, object]:
    """The same object as a live read returned it."""
    return {
        "name": "Corp",
        "enabled": True,
        "auth_servers": [
            {"host": "radius-1.example", "secret": masked_primary},
            {"host": "radius-2.example", "secret": backup},
        ],
    }


def _nested_pair(
    live: dict[str, object],
    vault: CredentialVault,
) -> tuple[SafetySnapshotEntry, ObjectVersion]:
    definition = get_definition("site", "wlans")
    assert definition is not None
    stored = _stored_version(
        protect_configuration(NESTED_WLAN, vault, sensitive_fields=definition.sensitive_fields),
        configuration_hash(NESTED_WLAN, ignored_fields=IGNORED),
    )
    entry = SafetySnapshotEntry(
        logical_object_id=stored.logical_object_id,
        order=0,
        action=RestoreActionType.UPDATE,
        scope="site",
        object_type="wlans",
        object_name="wlan-0",
        mist_object_id="mist-0",
        existed=True,
        configuration=protect_configuration(live, vault, sensitive_fields=definition.sensitive_fields),
        configuration_hash=configuration_hash(live, ignored_fields=IGNORED),
        pre_version_id=stored.id,
    )
    return entry, stored


async def test_a_mask_on_one_secret_does_not_excuse_another_that_changed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Masked locations are left out one at a time, not by field name.

    Excluding the name meant a mask over the first shared secret suppressed the
    comparison of the second. The stored version was accepted over a backup
    credential rotated since, and compensation put the old one back — no mask,
    so nothing for authorization to catch, and a working credential overwritten
    with a stale one.
    """
    vault = _vault()
    # Mist masked the first server's secret and returned the second, which has
    # been rotated since the stored version was taken.
    entry, stored = _nested_pair(_nested("********", "rotated-backup-secret"), vault)

    inverse = await _inverse_of(entry, stored, monkeypatch, vault)

    revealed = reveal_configuration(inverse.protected_configuration, vault)
    servers = revealed["auth_servers"]
    assert isinstance(servers, list)
    assert servers[1]["secret"] == "rotated-backup-secret"


async def test_a_mask_on_one_secret_still_recovers_it_when_the_rest_agrees(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Being exact about locations must not stop the recovery from happening."""
    vault = _vault()
    entry, stored = _nested_pair(_nested("********", "backup-shared-secret"), vault)

    inverse = await _inverse_of(entry, stored, monkeypatch, vault)

    revealed = reveal_configuration(inverse.protected_configuration, vault)
    servers = revealed["auth_servers"]
    assert isinstance(servers, list)
    # The masked one comes from the stored version; the other is unchanged.
    assert servers[0]["secret"] == "primary-shared-secret"
    assert servers[1]["secret"] == "backup-shared-secret"


async def test_a_stored_version_without_the_masked_secret_is_not_a_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A version that never held the secret cannot supply it.

    Dropping the masked location from both sides made "the stored version has
    this secret" and "the stored version has no such field" look alike. The
    second was then preferred, and the object went back through a replacement
    write without the field at all — nothing masked, so nothing for
    authorization to refuse, and the credential silently gone.
    """
    vault = _vault()
    definition = get_definition("site", "wlans")
    assert definition is not None
    without_psk: dict[str, object] = {"name": "Corp", "enabled": True}
    stored = _stored_version(
        protect_configuration(without_psk, vault, sensitive_fields=definition.sensitive_fields),
        configuration_hash(without_psk, ignored_fields=IGNORED),
    )
    entry = _entry({**without_psk, "psk": "********"}, stored, vault)

    inverse = await _inverse_of(entry, stored, monkeypatch, vault)

    revealed = reveal_configuration(inverse.protected_configuration, vault)
    # The live snapshot is kept, mask and all, which is what makes the plan
    # fail closed instead of writing the object back without its key.
    assert revealed["psk"] == "********"
    assert find_unavailable_secrets(revealed, definition.sensitive_fields) == {("psk",)}


async def test_a_stored_version_whose_secret_is_itself_masked_is_not_a_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A snapshot taken while Mist was masking holds no more than the live read."""
    vault = _vault()
    definition = get_definition("site", "wlans")
    assert definition is not None
    masked: dict[str, object] = {"name": "Corp", "enabled": True, "psk": "********"}
    stored = _stored_version(
        protect_configuration(masked, vault, sensitive_fields=definition.sensitive_fields),
        configuration_hash(masked, ignored_fields=IGNORED),
    )
    entry = _entry(dict(masked), stored, vault)

    inverse = await _inverse_of(entry, stored, monkeypatch, vault)

    assert find_unavailable_secrets(
        reveal_configuration(inverse.protected_configuration, vault),
        definition.sensitive_fields,
    ) == {("psk",)}


async def test_a_key_containing_a_dot_is_not_mistaken_for_another_location(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two distinct locations must not share an identity.

    A key may itself contain a dot, so `{"a.b": {"secret": ...}}` and
    `{"a": {"b": {"secret": ...}}}` both spell `a.b.secret`. While locations
    were named that way, a mask on the first suppressed the second and stood in
    as its source, and compensation replaced a returned, rotated secret with
    stale plaintext.
    """
    vault = _vault()
    definition = get_definition("site", "wlans")
    assert definition is not None
    live: dict[str, object] = {
        "name": "Corp",
        "a.b": {"secret": "********"},
        "a": {"b": {"secret": "rotated-returned-secret"}},
    }
    stored_configuration: dict[str, object] = {
        "name": "Corp",
        "a.b": {"secret": "primary-real-secret"},
        "a": {"b": {"secret": "stale-returned-secret"}},
    }
    stored = _stored_version(
        protect_configuration(stored_configuration, vault, sensitive_fields=definition.sensitive_fields),
        configuration_hash(stored_configuration, ignored_fields=IGNORED),
    )
    entry = _entry(live, stored, vault)

    inverse = await _inverse_of(entry, stored, monkeypatch, vault)

    revealed = reveal_configuration(inverse.protected_configuration, vault)
    nested = revealed["a"]
    assert isinstance(nested, dict)
    assert nested["b"]["secret"] == "rotated-returned-secret"


async def test_a_stored_version_that_has_drifted_is_not_paired_with(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only a digest that describes the live read is worth copying forward."""
    stale = legacy_configuration_hash({**CORP_WLAN, "enabled": False}, ignored_fields=IGNORED)

    async def _drifted_stored(_logical_id):
        return _stored_version({**CORP_WLAN, "enabled": False}, stale)

    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version",
        _drifted_stored,
    )
    live = configuration_hash(CORP_WLAN, ignored_fields=IGNORED)
    operation = _operation([_action(0, RestoreActionType.UPDATE, expected_current_hash=live)])
    client = _FakeMistClient({"mist-0": dict(CORP_WLAN)})

    entries = await capture_safety_snapshot(client, _organization(), operation, _vault())

    assert entries[0].configuration_hash == live


async def _no_stored_version(_logical_id):
    return None


# --------------------------------------------------------------- compensation


def _snapshot_state(entries) -> RestoreOperationState:
    return RestoreOperationState(
        organization_id=ORGANIZATION_ID,
        operation_id=OPERATION_ID,
        plan_hash="plan-hash",
        safety_snapshot=entries,
    )


async def _applied_plan(monkeypatch: pytest.MonkeyPatch) -> tuple[RestoreOperation, _MemoryStateStore]:
    monkeypatch.setattr(
        "mist_config_guardian_backend.services.restore_compensation.latest_version",
        _no_stored_version,
    )
    actions = [
        _action(0, RestoreActionType.CREATE, status=RestoreActionStatus.COMPLETED, resulting_mist_id="new-uuid"),
        _action(1, RestoreActionType.UPDATE, status=RestoreActionStatus.COMPLETED, resulting_mist_id="mist-1"),
        _action(2, RestoreActionType.DELETE, status=RestoreActionStatus.COMPLETED, resulting_mist_id=None),
        _action(3, RestoreActionType.UPDATE, status=RestoreActionStatus.PENDING),
    ]
    operation = _operation(actions)
    client = _FakeMistClient({"mist-1": dict(CORP_WLAN), "mist-2": dict(GUEST_WLAN), "mist-3": dict(GUEST_WLAN)})
    for action in actions:
        if action.action is not RestoreActionType.CREATE:
            action.expected_current_hash = None
    entries = await capture_safety_snapshot(client, _organization(), operation, _vault(), relaxed=True)
    store = _MemoryStateStore()
    await store.save(_snapshot_state(entries))
    return operation, store


@pytest.mark.usefixtures("offline_documents")
async def test_compensation_inverts_applied_actions_in_reverse_order(monkeypatch: pytest.MonkeyPatch) -> None:
    operation, store = await _applied_plan(monkeypatch)

    plan = await RestoreCompensationService(store).create_compensation_plan(
        operation=operation,
        requested_by=ADMINISTRATOR_ID,
    )

    assert [action.order for action in plan.actions] == [0, 1, 2]
    assert [action.object_name for action in plan.actions] == ["wlan-2", "wlan-1", "wlan-0"]
    assert [action.action for action in plan.actions] == [
        RestoreActionType.CREATE,
        RestoreActionType.UPDATE,
        RestoreActionType.DELETE,
    ]
    assert plan.actions[0].current_mist_id == "mist-2"
    assert plan.actions[2].current_mist_id == "new-uuid"
    assert plan.status is RestoreStatus.PLANNED


@pytest.mark.usefixtures("offline_documents")
async def test_compensation_replays_the_captured_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    operation, store = await _applied_plan(monkeypatch)

    plan = await RestoreCompensationService(store).create_compensation_plan(
        operation=operation,
        requested_by=ADMINISTRATOR_ID,
    )
    recreate = plan.actions[0]
    revert = plan.actions[1]

    assert recreate.protected_configuration["name"] == "Guest"
    assert revert.protected_configuration["name"] == "Corp"
    assert is_protected(revert.protected_configuration["psk"])
    assert plan.actions[2].protected_configuration == {}


@pytest.mark.usefixtures("offline_documents")
async def test_compensation_links_both_directions(monkeypatch: pytest.MonkeyPatch) -> None:
    operation, store = await _applied_plan(monkeypatch)
    service = RestoreCompensationService(store)

    plan = await service.create_compensation_plan(operation=operation, requested_by=ADMINISTRATOR_ID)

    linked = await store.find_compensation_of(ORGANIZATION_ID, OPERATION_ID)
    assert linked is not None
    assert linked.operation_id == COMPENSATION_ID
    assert linked.plan_hash == compute_plan_hash(plan.actions)
    source = await store.load(ORGANIZATION_ID, OPERATION_ID)
    assert source is not None
    assert source.compensation_operation_id == COMPENSATION_ID


async def test_compensation_refuses_a_restore_that_did_not_fail_midway() -> None:
    operation = _operation([_action(0, RestoreActionType.UPDATE)], status=RestoreStatus.COMPLETED)

    with pytest.raises(RestoreCompensationError, match="nothing to compensate"):
        await RestoreCompensationService(_MemoryStateStore()).create_compensation_plan(
            operation=operation,
            requested_by=ADMINISTRATOR_ID,
        )


async def test_compensation_refuses_a_restore_without_a_safety_snapshot() -> None:
    operation = _operation(
        [_action(0, RestoreActionType.UPDATE, status=RestoreActionStatus.COMPLETED)],
    )

    with pytest.raises(RestoreCompensationError, match="No safety snapshot"):
        await RestoreCompensationService(_MemoryStateStore()).create_compensation_plan(
            operation=operation,
            requested_by=ADMINISTRATOR_ID,
        )


# ------------------------------------------------------------------------ api


class _RecordingAuthorization:
    """Captures the delegated credential the route hands to authorization."""

    def __init__(self) -> None:
        self.credentials: list[str] = []
        self.operations: list[PydanticObjectId] = []

    async def authorize(self, organization_id, operation_id, credential, task_id):  # noqa: ARG002
        self.credentials.append(credential)
        self.operations.append(operation_id)
        return _operation([], status=RestoreStatus.QUEUED, identifier=operation_id)

    async def release(self, operation_id, task_id) -> None:  # noqa: ARG002
        return


class _StubCompensation:
    """Returns a fixed compensating plan for the failed restore."""

    def __init__(self, plan: RestoreOperation | None) -> None:
        self.plan = plan

    async def compensation_for(self, operation):  # noqa: ARG002
        return self.plan


def _administrator() -> User:
    return User.model_construct(
        id=ADMINISTRATOR_ID,
        email="admin@example.com",
        display_name="Admin",
        password_hash="unused",
        role=UserRole.ADMINISTRATOR,
        is_active=True,
        totp=None,
    )


def _app(compensation: _StubCompensation, authorization: _RecordingAuthorization):
    from mist_config_guardian_backend.api.dependencies import (  # noqa: PLC0415
        get_restore_authorization_service,
    )

    app = create_app(Settings(environment="test", database_enabled=False))
    app.dependency_overrides[get_current_user] = _administrator
    app.dependency_overrides[require_organization] = _organization
    app.dependency_overrides[get_restore_compensation_service] = lambda: compensation
    app.dependency_overrides[get_restore_authorization_service] = lambda: authorization
    app.dependency_overrides[get_plan_state_store] = _MemoryStateStore
    app.dependency_overrides[get_restore_plans] = lambda: _MemoryPlans(
        [_operation([_action(0, RestoreActionType.UPDATE, status=RestoreActionStatus.COMPLETED)])]
    )
    app.dependency_overrides[get_approval_service] = lambda: ApprovalService(_NoApprovals())
    return app


class _NoApprovals:
    """An approval store with nothing in it."""

    async def find_by_id(self, organization_id, approval_id):  # noqa: ARG002
        return None

    async def find_by_operation(self, organization_id, restore_operation_id):  # noqa: ARG002
        return None

    async def insert(self, draft):
        raise NotImplementedError

    async def save(self, approval) -> None:  # noqa: ARG002
        return

    async def page(self, organization_id, status, *, skip, limit):  # noqa: ARG002
        return [], 0

    async def load_operation(self, organization_id, restore_operation_id):  # noqa: ARG002
        return None


class _MemoryPlans:
    """Restore plans keyed by identifier, scoped by organization."""

    def __init__(self, plans: list[RestoreOperation]) -> None:
        self.plans = plans

    async def load(self, organization_id, operation_id):
        return next(
            (plan for plan in self.plans if plan.id == operation_id and plan.organization_id == organization_id),
            None,
        )

    async def page(self, organization_id, *, skip, limit):
        matched = [plan for plan in self.plans if plan.organization_id == organization_id]
        return matched[skip : skip + limit], len(matched)


@pytest.fixture(name="routed")
def _routed(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace task dispatch for restore route tests."""
    dispatched: list[str] = []
    monkeypatch.setattr(
        "mist_config_guardian_backend.api.routes.restores.celery_app.send_task",
        lambda *args, **kwargs: dispatched.append(kwargs.get("task_id", "")),  # noqa: ARG005
    )
    return dispatched


@pytest.mark.usefixtures("routed")
async def test_compensation_execution_requires_a_fresh_step_up() -> None:
    plan = _operation([], status=RestoreStatus.PLANNED, identifier=COMPENSATION_ID)
    authorization = _RecordingAuthorization()
    app = _app(_StubCompensation(plan), authorization)

    def _deny() -> User:
        from fastapi import HTTPException, status  # noqa: PLC0415

        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Confirm your authenticator code")

    app.dependency_overrides[require_fresh_mfa] = _deny
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            f"/api/v1/organizations/{ORGANIZATION_ID}/restores/{OPERATION_ID}/compensation/execute",
            json={"administrator_token": "fresh-admin-token"},
        )

    assert response.status_code == 403
    assert authorization.credentials == []


async def test_compensation_execution_uses_the_delegated_administrator_credential(routed: list[str]) -> None:
    plan = _operation([], status=RestoreStatus.PLANNED, identifier=COMPENSATION_ID)
    authorization = _RecordingAuthorization()
    transport = httpx.ASGITransport(app=_app(_StubCompensation(plan), authorization))

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            f"/api/v1/organizations/{ORGANIZATION_ID}/restores/{OPERATION_ID}/compensation/execute",
            json={"administrator_token": "fresh-admin-token"},
        )

    assert response.status_code == 202
    assert authorization.credentials == ["fresh-admin-token"]
    assert authorization.operations == [COMPENSATION_ID]
    assert len(routed) == 1
    assert "fresh-admin-token" not in response.text


@pytest.mark.usefixtures("routed")
async def test_compensation_execution_refuses_a_plan_that_was_never_created() -> None:
    authorization = _RecordingAuthorization()
    transport = httpx.ASGITransport(app=_app(_StubCompensation(None), authorization))

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            f"/api/v1/organizations/{ORGANIZATION_ID}/restores/{OPERATION_ID}/compensation/execute",
            json={"administrator_token": "fresh-admin-token"},
        )

    assert response.status_code == 409
    assert authorization.credentials == []
