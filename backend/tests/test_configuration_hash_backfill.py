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
from mist_config_guardian_backend.snapshots.registry import get_definition
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
