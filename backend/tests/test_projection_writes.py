"""The conditional projection write: what it stores, and what it matches on."""

from datetime import UTC, datetime
from typing import Any

import pytest
from beanie import PydanticObjectId
from beanie.odm.fields import ExpressionField
from beanie.odm.utils.pydantic import get_model_fields
from bson import ObjectId
from bson import encode as bson_encode

from mist_config_guardian_backend.models.monitoring import ImpactSeverity
from mist_config_guardian_backend.models.webhook import (
    AuditChangeGroup,
    ChangedObjectRef,
    RecoveryState,
    WebhookProcessingStatus,
    WebhookReceipt,
)
from mist_config_guardian_backend.services.change_groups import (
    BeanieChangeGroupStore,
    revision_predicate,
)
from mist_config_guardian_backend.services.webhook_processing import WebhookProcessingService

NOW = datetime(2026, 9, 7, 14, 22, tzinfo=UTC)


def _bind_query_fields(model: type) -> None:
    """Attach the query expression fields Beanie normally installs at init."""
    for name, field in get_model_fields(model).items():
        setattr(model, name, ExpressionField(field.alias or name))


_bind_query_fields(AuditChangeGroup)


class _RecordingCollection:
    """Captures the update a write issues, and reports what it matched."""

    def __init__(self, *, matched: int = 1) -> None:
        self.filter: dict[str, Any] | None = None
        self.update: dict[str, Any] | None = None
        self._matched = matched

    async def update_one(self, criteria: dict[str, Any], update: dict[str, Any]) -> Any:
        self.filter = criteria
        self.update = update
        return type("Result", (), {"matched_count": self._matched})()


def _group(**overrides: object) -> AuditChangeGroup:
    fields: dict[str, object] = {
        "id": PydanticObjectId(),
        "organization_id": PydanticObjectId(),
        "audit_id": "9F2A-C41",
        "actor": "j.mercer",
        "occurred_at": NOW,
        "receipt_ids": [PydanticObjectId()],
        "monitoring_session_ids": [PydanticObjectId()],
        "affected_site_ids": ["site-1"],
        "affected_object_ids": [],
        "changed_objects": [
            ChangedObjectRef(
                logical_object_id=PydanticObjectId(),
                object_type="wlans",
                object_name="NW-Corp",
                scope="org",
                event="updated",
            )
        ],
        "affected_devices": [],
        "impact_severity": ImpactSeverity.CRITICAL,
        "recovery_state": RecoveryState.UNRECOVERED,
        "degraded_metrics": ["capacity"],
        "evidence": [],
        "projection_revision": 0,
        "created_at": NOW,
        "updated_at": NOW,
    }
    fields.update(overrides)
    return AuditChangeGroup.model_construct(**fields)


async def _save(group: AuditChangeGroup, collection: _RecordingCollection, monkeypatch: pytest.MonkeyPatch) -> bool:
    monkeypatch.setattr(AuditChangeGroup, "get_pymongo_collection", lambda: collection)
    return await BeanieChangeGroupStore().save(group)


async def test_the_write_stores_identifiers_and_instants_as_mongo_types(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A JSON dump would store them as strings.

    The document would then be unreachable by every typed query that finds it
    — by organization, by session, by window — and would not collide on the
    compound index that keeps one group per audit.
    """
    collection = _RecordingCollection()
    group = _group()

    assert await _save(group, collection, monkeypatch) is True

    assert collection.update is not None
    document = collection.update["$set"]
    assert isinstance(document["organization_id"], ObjectId)
    assert isinstance(document["occurred_at"], datetime)
    assert isinstance(document["created_at"], datetime)
    assert all(isinstance(item, ObjectId) for item in document["receipt_ids"])
    assert all(isinstance(item, ObjectId) for item in document["monitoring_session_ids"])
    assert isinstance(document["changed_objects"][0]["logical_object_id"], ObjectId)
    # And the whole thing is what the driver will actually put on the wire.
    assert bson_encode(document)


async def test_the_write_leaves_the_identifier_and_revision_to_mongo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collection = _RecordingCollection()

    await _save(_group(), collection, monkeypatch)

    assert collection.update is not None
    assert "id" not in collection.update["$set"]
    assert "_id" not in collection.update["$set"]
    assert "projection_revision" not in collection.update["$set"]
    assert collection.update["$inc"] == {"projection_revision": 1}


async def test_a_won_write_advances_the_revision_it_holds(monkeypatch: pytest.MonkeyPatch) -> None:
    group = _group(projection_revision=4)

    assert await _save(group, _RecordingCollection(matched=1), monkeypatch) is True
    assert group.projection_revision == 5


async def test_a_lost_write_leaves_the_revision_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    group = _group(projection_revision=4)

    assert await _save(group, _RecordingCollection(matched=0), monkeypatch) is False
    assert group.projection_revision == 4


# --------------------------------------------------------------- the predicate


def test_a_group_written_before_the_field_existed_is_still_writable() -> None:
    """Such a document has no `projection_revision` at all.

    A query for zero does not match a missing field, so every rebuild of one
    would believe it had lost a race that never happened and, after its
    retries, give up on that group permanently.
    """
    predicate = revision_predicate(0)

    assert predicate == {"$or": [{"projection_revision": 0}, {"projection_revision": {"$exists": False}}]}


def test_a_later_revision_is_matched_exactly() -> None:
    assert revision_predicate(7) == {"projection_revision": 7}


async def test_the_write_asks_for_the_revision_it_read(monkeypatch: pytest.MonkeyPatch) -> None:
    collection = _RecordingCollection()
    group = _group(projection_revision=2)

    await _save(group, collection, monkeypatch)

    assert collection.filter == {"_id": group.id, "projection_revision": 2}


# ------------------------------------------------------- receipt aggregation


class _PipelineCollection:
    def __init__(self) -> None:
        self.filter: dict[str, Any] | None = None
        self.pipeline: list[dict[str, Any]] | None = None

    async def update_one(self, criteria: dict[str, Any], update: list[dict[str, Any]]) -> Any:
        self.filter = criteria
        self.pipeline = update
        return type("Result", (), {"matched_count": 1})()


async def test_receipt_metadata_merges_without_touching_the_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A read-modify-save here would overwrite a concurrent rebuild's work.

    The merge names only the fields a receipt carries, and increments the
    revision so a rebuild already in flight loses its conditional write and
    recomputes from these instead of replacing them with its older copy.
    """
    group = _group(actor=None, message=None)
    collection = _PipelineCollection()

    async def find_one(*_args: object, **_kwargs: object) -> AuditChangeGroup:
        return group

    monkeypatch.setattr(AuditChangeGroup, "find_one", find_one)
    monkeypatch.setattr(AuditChangeGroup, "get_pymongo_collection", lambda: collection)
    receipt = WebhookReceipt.model_construct(
        id=PydanticObjectId(),
        organization_id=group.organization_id,
        topic="audits",
        event_id="event-1",
        audit_id=group.audit_id,
        payload_hash="hash",
        encrypted_payload="v1:cipher",
        signature_version="v2",
        signature_valid=True,
        status=WebhookProcessingStatus.PROCESSING,
        processing_attempts=1,
        created_at=NOW,
        updated_at=NOW,
    )

    await WebhookProcessingService._add_to_change_group(  # noqa: SLF001
        receipt,
        {"admin_name": "a.osei", "site_id": "site-2"},
    )

    assert collection.pipeline is not None
    merged = collection.pipeline[0]["$set"]
    # Nothing the projector owns is named here.
    assert not {
        "impact_severity",
        "recovery_state",
        "changed_objects",
        "affected_devices",
        "monitoring_session_ids",
        "evidence",
        "summary",
    } & set(merged)
    # The revision moves, so a rebuild in flight recomputes rather than
    # overwriting this receipt's metadata with the copy it read.
    assert merged["projection_revision"] == {"$add": [{"$ifNull": ["$projection_revision", 0]}, 1]}
    # Known values are kept; blanks are filled.
    assert merged["actor"] == {"$ifNull": ["$actor", "a.osei"]}
    assert merged["receipt_ids"] == {"$setUnion": [{"$ifNull": ["$receipt_ids", []]}, [receipt.id]]}
    assert merged["affected_site_ids"] == {"$setUnion": [{"$ifNull": ["$affected_site_ids", []]}, ["site-2"]]}
