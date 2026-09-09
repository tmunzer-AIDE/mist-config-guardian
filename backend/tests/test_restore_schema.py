"""The restore operation response carries what a client needs to rebuild the plan."""

from datetime import UTC, datetime

from beanie import PydanticObjectId

from mist_config_guardian_backend.models.restore import RestoreMode, RestoreOperation, RestoreStatus
from mist_config_guardian_backend.schemas.restore import RestoreOperationResponse

WHEN = datetime(2026, 9, 1, tzinfo=UTC)


def _operation(**overrides: object) -> RestoreOperation:
    fields: dict[str, object] = {
        "id": PydanticObjectId(),
        "organization_id": PydanticObjectId(),
        "requested_by": PydanticObjectId(),
        "mode": RestoreMode.EXACT,
        "include_dependencies": True,
        "target_at": WHEN,
        "status": RestoreStatus.PLANNED,
        "actions": [],
        "warnings": [],
        "preflight_errors": [],
        "credential_actor": None,
        "started_at": None,
        "completed_at": None,
        "task_id": None,
        "created_at": WHEN,
        "updated_at": WHEN,
    }
    fields.update(overrides)
    return RestoreOperation.model_construct(**fields)


def test_the_response_carries_the_requested_versions_as_requested() -> None:
    """The action list is derived and lossy; rebuilding needs the inputs themselves."""
    chosen = [PydanticObjectId(), PydanticObjectId()]

    response = RestoreOperationResponse.from_document(_operation(requested_version_ids=chosen))

    assert response.requested_version_ids == [str(version_id) for version_id in chosen]


def test_an_operation_planned_before_inputs_were_recorded_reports_none() -> None:
    """A client must treat such a plan as not rebuildable rather than guess from its actions."""
    response = RestoreOperationResponse.from_document(_operation())

    assert response.requested_version_ids == []
