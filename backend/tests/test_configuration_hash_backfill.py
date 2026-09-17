"""Tests for the migration of stored configuration digests to the keyed hash."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.snapshot import ObjectVersion
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services import snapshots as snapshot_service
from mist_config_guardian_backend.services.snapshots import CaptureContext, SnapshotService, _upgrade_stored_hash
from mist_config_guardian_backend.snapshots.canonical import (
    configuration_hash,
    is_legacy_hash,
    legacy_configuration_hash,
)
from mist_config_guardian_backend.snapshots.registry import DEFAULT_IGNORED_FIELDS, get_definition
from mist_config_guardian_backend.tasks import hashes as hash_tasks
from mist_config_guardian_backend.tasks.hashes import upgraded_hash

WLAN = {"name": "NW-Corp", "psk": "super-secret", "vlan": 12, "modified_time": 1757000000}
IGNORED = frozenset({"modified_time"})


def test_a_legacy_digest_is_replaced_by_the_keyed_one() -> None:
    stored = legacy_configuration_hash(WLAN, ignored_fields=IGNORED)

    replacement = upgraded_hash(WLAN, stored, ignored_fields=IGNORED)

    assert replacement == configuration_hash(WLAN, ignored_fields=IGNORED)
    assert not is_legacy_hash(replacement or "")


def test_a_digest_that_does_not_describe_its_configuration_is_left_alone() -> None:
    """A migration that cannot reproduce a digest is not migrating, it is inventing.

    A row whose stored digest no longer matches its stored configuration under
    any known policy would otherwise be stamped with a keyed digest asserting
    something nobody checked.
    """
    stored = legacy_configuration_hash(WLAN, ignored_fields=IGNORED)

    assert upgraded_hash(WLAN, stored) is None
    assert upgraded_hash({**WLAN, "vlan": 13}, stored, ignored_fields=IGNORED) is None


def test_a_legacy_digest_using_the_previous_field_policy_migrates_to_the_current_policy() -> None:
    previous_fields = frozenset({"modified_time"})
    current_fields = previous_fields | {"portal_template_url"}
    configuration = {**WLAN, "portal_template_url": "https://generated.example/portal"}
    stored = legacy_configuration_hash(configuration, ignored_fields=previous_fields)

    replacement = upgraded_hash(
        configuration,
        stored,
        ignored_fields=current_fields,
        compatible_ignored_fields=(previous_fields,),
    )

    assert replacement == configuration_hash(configuration, ignored_fields=current_fields)


async def test_backfill_task_supplies_the_previous_default_field_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """The production task must wire compatibility into each row migration."""
    definition = get_definition("site", "maps")
    assert definition is not None
    configuration = {"id": "map-1", "name": "Office", "url": "https://generated.example/map"}
    version = ObjectVersion.model_construct(
        id=PydanticObjectId(),
        logical_object_id=PydanticObjectId(),
        configuration=configuration,
        configuration_hash=legacy_configuration_hash(
            configuration,
            ignored_fields=DEFAULT_IGNORED_FIELDS,
        ),
    )

    class _PendingVersions:
        def limit(self, size: int) -> "_PendingVersions":
            assert size == hash_tasks.BACKFILL_BATCH_SIZE
            return self

        async def to_list(self) -> list[ObjectVersion]:
            return [version]

    database = SimpleNamespace(connect=AsyncMock(), close=AsyncMock())
    update = AsyncMock(return_value=SimpleNamespace(modified_count=1))
    expression = object()
    monkeypatch.setattr(hash_tasks, "get_settings", lambda: Settings(environment="test"))
    monkeypatch.setattr(hash_tasks, "DatabaseManager", lambda _settings: database)
    monkeypatch.setattr(
        hash_tasks,
        "ObjectVersion",
        SimpleNamespace(
            id=expression,
            configuration_hash=expression,
            find=lambda _selector: _PendingVersions(),
            find_one=lambda *_args: SimpleNamespace(update=update),
        ),
    )
    monkeypatch.setattr(hash_tasks, "_ignored_fields", AsyncMock(return_value=definition.ignored_fields))

    migrated = await hash_tasks._backfill_configuration_hashes()  # noqa: SLF001

    assert migrated == 1
    update.assert_awaited_once_with(
        {
            "$set": {
                "configuration_hash": configuration_hash(
                    configuration,
                    ignored_fields=definition.ignored_fields,
                )
            }
        }
    )
    database.connect.assert_awaited_once_with()
    database.close.assert_awaited_once_with()


def test_an_already_migrated_digest_is_left_alone() -> None:
    assert upgraded_hash(WLAN, configuration_hash(WLAN, ignored_fields=IGNORED), ignored_fields=IGNORED) is None


async def test_an_unchanged_object_with_a_current_digest_is_not_rewritten(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every snapshot revisits every unchanged object; only the old ones cost a write."""

    def _explode(*_args: object, **_kwargs: object) -> None:
        msg = "A digest that is already current must not be rewritten"
        raise AssertionError(msg)

    monkeypatch.setattr(ObjectVersion, "find_one", _explode)
    current = configuration_hash(WLAN, ignored_fields=IGNORED)
    version = ObjectVersion.model_construct(id=PydanticObjectId(), configuration_hash=current)

    await _upgrade_stored_hash(version, current)

    assert version.configuration_hash == current


async def test_an_unchanged_object_with_an_old_field_policy_is_rehashed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    update = AsyncMock()
    monkeypatch.setattr(
        snapshot_service,
        "ObjectVersion",
        SimpleNamespace(
            id=object(),
            configuration_hash=object(),
            find_one=lambda *_args: SimpleNamespace(update=update),
        ),
    )
    configuration = {**WLAN, "portal_template_url": "https://generated.example/portal"}
    previous = configuration_hash(configuration, ignored_fields=IGNORED)
    current = configuration_hash(configuration, ignored_fields=IGNORED | {"portal_template_url"})
    version = ObjectVersion.model_construct(id=PydanticObjectId(), configuration_hash=previous)

    await _upgrade_stored_hash(version, current)

    update.assert_awaited_once()
    assert version.configuration_hash == current


async def test_a_captured_update_lists_functional_changed_fields_without_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    definition = get_definition("org", "networktemplates")
    assert definition is not None
    stored = {"id": "template-1", "name": "DNT-NTR", "dns_servers": ["10.0.0.1"], "modified_time": 1}
    current = {**stored, "dns_servers": ["10.0.0.2"], "modified_time": 2}
    latest = ObjectVersion.model_construct(
        id=PydanticObjectId(),
        version=1,
        configuration=stored,
        configuration_hash=configuration_hash(stored, ignored_fields=definition.ignored_fields),
    )
    inserted: list[dict[str, object]] = []

    class _Versions:
        def sort(self, *_args: object) -> "_Versions":
            return self

        async def first_or_none(self) -> ObjectVersion:
            return latest

    class _SortExpression:
        def __neg__(self) -> "_SortExpression":
            return self

    class _Version(SimpleNamespace):
        organization_id = logical_object_id = object()
        version = _SortExpression()

        @staticmethod
        def find(*_args: object) -> _Versions:
            return _Versions()

        async def insert(self) -> None:
            inserted.append(vars(self))

    expression = object()
    logical = SimpleNamespace(id=PydanticObjectId(), touch=lambda: None, save=AsyncMock())
    monkeypatch.setattr(
        snapshot_service,
        "LogicalObject",
        SimpleNamespace(
            organization_id=expression,
            scope=expression,
            object_type=expression,
            source_key=expression,
            find_one=AsyncMock(return_value=logical),
        ),
    )
    monkeypatch.setattr(
        snapshot_service,
        "ObjectIncarnation",
        SimpleNamespace(
            logical_object_id=expression,
            mist_object_id=expression,
            find_one=AsyncMock(return_value=SimpleNamespace(id=PydanticObjectId())),
        ),
    )
    monkeypatch.setattr(snapshot_service, "ObjectVersion", _Version)
    service = SnapshotService(CredentialVault(Settings(environment="test", credential_encryption_key="test-key")))

    created = await service.capture_configuration(
        PydanticObjectId(), definition, current, CaptureContext(snapshot_id=None, site_id=None)
    )

    assert created
    assert [version["changed_fields"] for version in inserted] == [["dns_servers"]]


async def test_a_new_field_policy_does_not_create_a_phantom_version(monkeypatch: pytest.MonkeyPatch) -> None:
    definition = get_definition("site", "maps")
    assert definition is not None
    stored = {"id": "map-1", "name": "Office", "url": "https://generated.example/old"}
    current = {**stored, "url": "https://generated.example/new"}
    latest = ObjectVersion.model_construct(
        id=PydanticObjectId(),
        version=1,
        configuration=stored,
        configuration_hash=configuration_hash(stored, ignored_fields=IGNORED),
    )

    class _Versions:
        def sort(self, *_args: object) -> "_Versions":
            return self

        async def first_or_none(self) -> ObjectVersion:
            return latest

    class _SortExpression:
        def __neg__(self) -> "_SortExpression":
            return self

    expression = object()
    sort_expression = _SortExpression()
    monkeypatch.setattr(
        snapshot_service,
        "LogicalObject",
        SimpleNamespace(
            organization_id=expression,
            scope=expression,
            object_type=expression,
            source_key=expression,
            find_one=AsyncMock(return_value=SimpleNamespace(id=PydanticObjectId())),
        ),
    )
    monkeypatch.setattr(
        snapshot_service,
        "ObjectIncarnation",
        SimpleNamespace(
            logical_object_id=expression,
            mist_object_id=expression,
            find_one=AsyncMock(return_value=SimpleNamespace(id=PydanticObjectId())),
        ),
    )
    monkeypatch.setattr(
        snapshot_service,
        "ObjectVersion",
        SimpleNamespace(
            organization_id=expression,
            logical_object_id=expression,
            version=sort_expression,
            find=lambda *_args: _Versions(),
        ),
    )
    refresh_hash = AsyncMock()
    monkeypatch.setattr(snapshot_service, "_upgrade_stored_hash", refresh_hash)
    service = SnapshotService(CredentialVault(Settings(environment="test", credential_encryption_key="test-key")))

    created = await service.capture_configuration(
        PydanticObjectId(),
        definition,
        current,
        CaptureContext(snapshot_id=None, site_id="site-1"),
    )

    assert not created
    refresh_hash.assert_awaited_once_with(
        latest,
        configuration_hash(current, ignored_fields=definition.ignored_fields),
    )
