"""Tests for purging change groups that never described a configuration change."""

from beanie import PydanticObjectId

from mist_config_guardian_backend.models.snapshot import VersionEvent
from mist_config_guardian_backend.models.webhook import AuditChangeGroup, ChangedObjectRef
from mist_config_guardian_backend.services.audit_cleanup import is_operational_noise

PCAP = {"id": "audit-1", "site_id": "site-1", "message": "Packet Capture started"}
MXCLUSTER = {
    "id": "audit-2",
    "mxcluster_id": "72df7314-b11b-49d8-8570-c7b39ab7c0c0",
    "message": 'Update MxCluster "campus_cluster"',
}


def _group(**overrides: object) -> AuditChangeGroup:
    fields: dict[str, object] = {
        "id": PydanticObjectId(),
        "organization_id": PydanticObjectId(),
        "audit_id": "audit-1",
        "message": None,
        "changed_objects": [],
        "affected_devices": [],
    }
    fields.update(overrides)
    return AuditChangeGroup.model_construct(**fields)


def test_a_group_whose_every_audit_is_operational_is_purged() -> None:
    assert is_operational_noise(_group(message="Packet Capture started"), [PCAP])


def test_a_group_carrying_a_configuration_audit_is_kept() -> None:
    assert not is_operational_noise(_group(message='Update MxCluster "campus_cluster"'), [PCAP, MXCLUSTER])


def test_a_group_that_recorded_changed_objects_is_never_purged() -> None:
    """Objects were versioned from this action, so it changed configuration.

    Whatever the payload says, deleting the group would orphan that history.
    """
    group = _group(
        message="Packet Capture started",
        changed_objects=[
            ChangedObjectRef.model_construct(
                logical_object_id=PydanticObjectId(),
                object_type="wlans",
                scope="site",
                name="Corporate",
                event=VersionEvent.UPDATED,
                version=2,
            )
        ],
    )

    assert not is_operational_noise(group, [PCAP])


def test_a_group_whose_receipts_are_gone_is_judged_by_its_message() -> None:
    assert is_operational_noise(_group(message='Accessed Org "TM-LAB"'), [])
    assert not is_operational_noise(_group(message='Delete MxEdge "teleworker-x1"'), [])
