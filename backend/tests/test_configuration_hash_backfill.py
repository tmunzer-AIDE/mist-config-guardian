"""Tests for the migration of stored configuration digests to the keyed hash."""

import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.models.snapshot import ObjectVersion
from mist_config_guardian_backend.services.snapshots import _upgrade_stored_hash
from mist_config_guardian_backend.snapshots.canonical import (
    configuration_hash,
    is_legacy_hash,
    legacy_configuration_hash,
)
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

    A row whose stored digest no longer matches its stored configuration — a
    definition that changed which fields it ignores, say — would otherwise be
    stamped with a keyed digest asserting something nobody checked.
    """
    stored = legacy_configuration_hash(WLAN, ignored_fields=IGNORED)

    assert upgraded_hash(WLAN, stored) is None
    assert upgraded_hash({**WLAN, "vlan": 13}, stored, ignored_fields=IGNORED) is None


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
