"""Change-group projection, presentation, and read-model tests."""

import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta

import httpx
from beanie import PydanticObjectId

from mist_config_guardian_backend.api.dependencies import get_current_user, require_organization
from mist_config_guardian_backend.api.routes.change_groups import get_change_group_service
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.main import create_app
from mist_config_guardian_backend.models.monitoring import (
    DeviceType,
    ImpactSeverity,
    MonitoringIncident,
    MonitoringSession,
    MonitoringStatus,
    SleObservation,
)
from mist_config_guardian_backend.models.notification import NotificationSeverity
from mist_config_guardian_backend.models.organization import (
    MistCloudRegion,
    Organization,
    OrganizationStatus,
)
from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectVersion, VersionEvent
from mist_config_guardian_backend.models.user import User, UserRole
from mist_config_guardian_backend.models.webhook import (
    AffectedDevice,
    AuditChangeGroup,
    BaselineConfidence,
    ChangedObjectRef,
    ChangeSource,
    RecoveryState,
    WebhookProcessingStatus,
    WebhookReceipt,
)
from mist_config_guardian_backend.services.change_groups import (
    MINUS_SIGN,
    ChangeGroupFilters,
    ChangeGroupProjector,
    ChangeGroupService,
    actor_matches,
    build_devices_label,
    build_impact_label,
    build_title,
    measure_movements,
    object_type_label,
    resolve_baseline_confidence,
    resolve_recovery_state,
)
from mist_config_guardian_backend.services.webhook_processing import WebhookProcessingService

ORGANIZATION_ID = PydanticObjectId()
OTHER_ORGANIZATION_ID = PydanticObjectId()
NOW = datetime(2026, 9, 7, 14, 0, tzinfo=UTC)
SEATTLE = "site-seattle"
PORTLAND = "site-portland"


# ------------------------------------------------------------------- fixtures


def _group(
    *,
    audit_id: str = "audit-1",
    organization_id: PydanticObjectId = ORGANIZATION_ID,
    actor: str | None = "j.mercer",
    occurred_at: datetime = NOW,
    sites: Sequence[str] = (SEATTLE,),
    **overrides: object,
) -> AuditChangeGroup:
    defaults: dict[str, object] = {
        "id": PydanticObjectId(),
        "organization_id": organization_id,
        "audit_id": audit_id,
        "actor": actor,
        "method": "PUT",
        "message": "modify wlan",
        "source": ChangeSource.WEBHOOK,
        "occurred_at": occurred_at,
        "receipt_ids": [],
        "affected_site_ids": list(sites),
        "affected_object_ids": [],
        "changed_objects": [],
        "affected_devices": [],
        "monitoring_session_ids": [],
        "impact_severity": ImpactSeverity.NONE,
        "recovery_state": RecoveryState.NOT_APPLICABLE,
        "baseline_confidence": BaselineConfidence.NONE,
        "deterministic_assessment": None,
        "evidence": [],
        "degraded_metrics": [],
        "summary": None,
        "projection_updated_at": None,
        "created_at": occurred_at,
        "updated_at": occurred_at,
    }
    return AuditChangeGroup.model_construct(**(defaults | overrides))


def _logical(  # noqa: PLR0913 - a fixture builder mirrors the document's fields
    *,
    name: str,
    object_type: str,
    organization_id: PydanticObjectId = ORGANIZATION_ID,
    site: str | None = None,
    scope: str = "org",
    version: int = 2,
    is_deleted: bool = False,
    mist_id: str = "",
) -> LogicalObject:
    return LogicalObject.model_construct(
        id=PydanticObjectId(),
        organization_id=organization_id,
        scope=scope,
        object_type=object_type,
        source_key=name,
        current_mist_id=mist_id or f"mist-{name}",
        site_mist_id=site,
        name=name,
        is_deleted=is_deleted,
        current_version=version,
        created_at=NOW,
        updated_at=NOW,
    )


def _version(  # noqa: PLR0913 - a fixture builder mirrors the document's fields
    logical: LogicalObject,
    *,
    version: int,
    audit_id: str | None = "audit-1",
    changed_fields: Sequence[str] = (),
    event: VersionEvent = VersionEvent.UPDATED,
    is_deleted: bool = False,
    observed_at: datetime = NOW,
) -> ObjectVersion:
    return ObjectVersion.model_construct(
        id=PydanticObjectId(),
        organization_id=logical.organization_id,
        logical_object_id=logical.id,
        incarnation_id=PydanticObjectId(),
        snapshot_id=None,
        version=version,
        event=event,
        configuration={},
        configuration_hash=f"hash-{version}",
        changed_fields=list(changed_fields),
        references=[],
        is_deleted=is_deleted,
        observed_at=observed_at,
        actor="j.mercer",
        audit_id=audit_id,
    )


def _session(  # noqa: PLR0913 - a fixture builder mirrors the document's fields
    *,
    mac: str,
    audit_ids: Sequence[str] = ("audit-1",),
    site: str = SEATTLE,
    device_type: DeviceType = DeviceType.AP,
    status: MonitoringStatus = MonitoringStatus.COMPLETED,
    baseline: Mapping[str, float] | None = None,
    latest: Mapping[str, float] | None = None,
    samples: int = 52,
    severity: ImpactSeverity = ImpactSeverity.NONE,
    degraded: Sequence[str] = (),
    incidents: Sequence[MonitoringIncident] = (),
    organization_id: PydanticObjectId = ORGANIZATION_ID,
) -> MonitoringSession:
    observations: list[SleObservation] = []
    if latest is not None:
        observations = [
            SleObservation(captured_at=NOW - timedelta(minutes=index), values=dict(latest)) for index in range(samples)
        ]
    return MonitoringSession.model_construct(
        id=PydanticObjectId(),
        organization_id=organization_id,
        audit_ids=list(audit_ids),
        receipt_ids=[],
        site_id=site,
        device_mac=mac,
        device_name=mac.upper(),
        device_type=device_type,
        status=status,
        active=status in {MonitoringStatus.AWAITING_CONFIG, MonitoringStatus.MONITORING},
        baseline=SleObservation(captured_at=NOW, values=dict(baseline)) if baseline is not None else None,
        observations=observations,
        incidents=list(incidents),
        config_applied_at=NOW,
        monitoring_started_at=NOW,
        monitoring_ends_at=NOW + timedelta(hours=5, minutes=10),
        next_poll_at=None,
        impact_severity=severity,
        deterministic_summary=None,
        degraded_metrics=list(degraded),
        ai_assessment=None,
        ai_assessment_error=None,
        completed_at=NOW + timedelta(hours=5, minutes=10),
        warnings=[],
        created_at=NOW,
        updated_at=NOW,
    )


class _MemoryChangeGroupStore:
    """In-memory stand-in honouring the criteria documents the service builds."""

    def __init__(self) -> None:
        self.groups: list[AuditChangeGroup] = []
        self.versions: list[ObjectVersion] = []
        self.logicals: list[LogicalObject] = []
        self.sessions: list[MonitoringSession] = []
        self.saves = 0
        self.calls: list[str] = []

    async def group_by_audit(
        self,
        organization_id: PydanticObjectId,
        audit_id: str,
    ) -> AuditChangeGroup | None:
        self.calls.append("group_by_audit")
        return next(
            (group for group in self.groups if group.organization_id == organization_id and group.audit_id == audit_id),
            None,
        )

    async def group_by_id(
        self,
        organization_id: PydanticObjectId,
        group_id: PydanticObjectId,
    ) -> AuditChangeGroup | None:
        self.calls.append("group_by_id")
        return next(
            (group for group in self.groups if group.organization_id == organization_id and group.id == group_id),
            None,
        )

    async def save(self, group: AuditChangeGroup) -> None:
        self.calls.append("save")
        self.saves += 1
        if group not in self.groups:
            self.groups.append(group)

    async def count(self, criteria: Mapping[str, object]) -> int:
        self.calls.append("count")
        return len(self._match(criteria))

    async def page(
        self,
        criteria: Mapping[str, object],
        *,
        skip: int,
        limit: int,
    ) -> list[AuditChangeGroup]:
        self.calls.append("page")
        ordered = sorted(
            self._match(criteria),
            key=lambda group: group.occurred_at or group.created_at,
            reverse=True,
        )
        return ordered[skip : skip + limit]

    async def versions_for_audit(
        self,
        organization_id: PydanticObjectId,
        audit_id: str,
    ) -> list[ObjectVersion]:
        self.calls.append("versions_for_audit")
        return [
            version
            for version in self.versions
            if version.organization_id == organization_id and version.audit_id == audit_id
        ]

    async def versions_at(
        self,
        organization_id: PydanticObjectId,
        pairs: Sequence[tuple[PydanticObjectId, int]],
    ) -> list[ObjectVersion]:
        self.calls.append("versions_at")
        wanted = set(pairs)
        return [
            version
            for version in self.versions
            if version.organization_id == organization_id and (version.logical_object_id, version.version) in wanted
        ]

    async def logical_objects(
        self,
        organization_id: PydanticObjectId,
        object_ids: Sequence[PydanticObjectId],
    ) -> list[LogicalObject]:
        self.calls.append("logical_objects")
        wanted = set(object_ids)
        return [
            logical for logical in self.logicals if logical.organization_id == organization_id and logical.id in wanted
        ]

    async def sessions_for_audit(
        self,
        organization_id: PydanticObjectId,
        audit_id: str,
    ) -> list[MonitoringSession]:
        self.calls.append("sessions_for_audit")
        return [
            session
            for session in self.sessions
            if session.organization_id == organization_id and audit_id in session.audit_ids
        ]

    async def sessions_by_id(
        self,
        organization_id: PydanticObjectId,
        session_ids: Sequence[PydanticObjectId],
    ) -> list[MonitoringSession]:
        self.calls.append("sessions_by_id")
        wanted = set(session_ids)
        return [
            session for session in self.sessions if session.organization_id == organization_id and session.id in wanted
        ]

    async def groups_touching_sites(
        self,
        organization_id: PydanticObjectId,
        site_ids: Sequence[str],
        *,
        start: datetime,
        end: datetime,
        exclude_audit_id: str,
    ) -> list[AuditChangeGroup]:
        self.calls.append("groups_touching_sites")
        wanted = set(site_ids)
        return [
            group
            for group in self.groups
            if group.organization_id == organization_id
            and group.audit_id != exclude_audit_id
            and wanted & set(group.affected_site_ids)
            and group.occurred_at is not None
            and start <= group.occurred_at <= end
        ]

    async def site_names(
        self,
        organization_id: PydanticObjectId,
        site_ids: Sequence[str],
    ) -> dict[str, str]:
        self.calls.append("site_names")
        wanted = set(site_ids)
        return {
            logical.current_mist_id: logical.name
            for logical in self.logicals
            if logical.organization_id == organization_id
            and logical.object_type == "sites"
            and logical.current_mist_id in wanted
        }

    def _match(self, criteria: Mapping[str, object]) -> list[AuditChangeGroup]:
        return [group for group in self.groups if _matches(group, criteria)]


def _matches(group: AuditChangeGroup, criteria: Mapping[str, object]) -> bool:
    for key, expected in criteria.items():
        if key == "$or":
            clauses = expected if isinstance(expected, list) else []
            if not any(_matches(group, clause) for clause in clauses):
                return False
            continue
        if not _field_matches(group, key, expected):
            return False
    return True


def _field_matches(group: AuditChangeGroup, key: str, expected: object) -> bool:
    if key == "changed_objects.object_name":
        values: list[object] = [ref.object_name for ref in group.changed_objects]
    else:
        values = [getattr(group, key, None)]
    return any(_value_matches(value, expected) for value in values)


def _value_matches(value: object, expected: object) -> bool:  # noqa: PLR0911 - one branch per operator
    if isinstance(expected, dict):
        for operator, operand in expected.items():
            if operator == "$gte" and not (value is not None and value >= operand):
                return False
            if operator == "$lte" and not (value is not None and value <= operand):
                return False
            if operator == "$in" and value not in operand:
                return False
            if operator == "$ne" and value == operand:
                return False
            if operator == "$regex" and (
                not isinstance(value, str) or re.search(str(operand), value, re.IGNORECASE) is None
            ):
                return False
        return True
    if isinstance(value, ImpactSeverity | RecoveryState | ChangeSource):
        return expected in {value.value, value}
    return value == expected


class _RecordingNotifier:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def notify_impact_detected(
        self,
        *,
        organization_id: PydanticObjectId,
        change_group_id: str,
        summary: str,
        severity: NotificationSeverity = NotificationSeverity.CRITICAL,
    ) -> object:
        del organization_id, severity
        self.calls.append((change_group_id, summary))
        return None


def _viewer(email: str = "j.mercer@northwind.example") -> User:
    return User.model_construct(
        id=PydanticObjectId(),
        email=email,
        display_name="Viewer",
        password_hash="unused",
        role=UserRole.VIEWER,
        is_active=True,
    )


def _organization(organization_id: PydanticObjectId = ORGANIZATION_ID) -> Organization:
    return Organization.model_construct(
        id=organization_id,
        mist_org_id="org-1",
        name="Northwind Retail",
        cloud_region=MistCloudRegion.GLOBAL_01,
        status=OrganizationStatus.VERIFIED,
        encrypted_service_token="v1:encrypted-value",
        service_token_last_four="4f21",
    )


def _critical_fixture() -> _MemoryChangeGroupStore:
    """The design's flagship change group: 2 objects, 6 APs, capacity down 29."""
    store = _MemoryChangeGroupStore()
    store.groups.append(_group())
    site = _logical(name="Seattle-DC", object_type="sites", mist_id=SEATTLE)
    wlan = _logical(name="NW-Corp", object_type="wlans")
    rf = _logical(name="Indoor-Dense-6G", object_type="rftemplates")
    store.logicals.extend([site, wlan, rf])
    store.versions.extend(
        [
            _version(wlan, version=14, audit_id=None),
            _version(wlan, version=15, changed_fields=["rf_template_id", "band_steer", "max_clients"]),
            _version(rf, version=3, audit_id=None),
            _version(rf, version=4, changed_fields=["band_5.channels", "band_5.power_max"]),
        ]
    )
    store.sessions.extend(
        _session(
            mac=f"5c5b350{index}",
            baseline={"capacity": 41.0, "time-to-connect": 91.0},
            latest={"capacity": 12.0, "time-to-connect": 84.0},
            severity=ImpactSeverity.CRITICAL,
            degraded=["capacity"],
        )
        for index in range(6)
    )
    return store


# ------------------------------------------------------------------- helpers


def test_object_type_label_keeps_acronyms_and_singularizes() -> None:
    assert object_type_label("rftemplates") == "RF template"
    assert object_type_label("gatewaytemplates") == "Gateway template"
    assert object_type_label("wlans") == "Organization WLAN"
    assert object_type_label("wlans", "site") == "Site WLAN"
    assert object_type_label("sitegroups") == "Site group"
    assert object_type_label("mystery_type") == "Mystery type"


def test_actor_matches_email_and_its_local_part() -> None:
    assert actor_matches("j.mercer", "j.mercer@northwind.example")
    assert actor_matches("J.Mercer@Northwind.example", "j.mercer@northwind.example")
    assert not actor_matches("a.osei", "j.mercer@northwind.example")
    assert not actor_matches(None, "j.mercer@northwind.example")


def test_devices_label_uses_the_designs_terse_forms() -> None:
    devices = [
        AffectedDevice(device_mac=f"5c5b350{index}", device_type="ap", site_mist_id=SEATTLE) for index in range(6)
    ]
    assert build_devices_label(devices, {SEATTLE: "Seattle-DC"}) == "6 APs · Seattle-DC"
    assert build_devices_label([], {}) == "org-wide"
    assert build_devices_label(devices[:1], {}) == f"1 AP · {SEATTLE}"


def test_devices_label_counts_sites_when_a_change_spans_several() -> None:
    devices = [
        AffectedDevice(device_mac=f"mac{index}", device_type="gateway", site_mist_id=f"site-{index % 3}")
        for index in range(4)
    ]
    assert build_devices_label(devices, {}) == "4 gateways · 3 sites"


def test_impact_label_matches_the_designs_badge_strings() -> None:
    movements = measure_movements(
        [
            _session(
                mac="a",
                baseline={"capacity": 41.0},
                latest={"capacity": 12.0},
            )
        ]
    )
    assert (
        build_impact_label(ImpactSeverity.CRITICAL, RecoveryState.UNRECOVERED, movements) == f"CRITICAL {MINUS_SIGN}29"
    )
    warning = measure_movements([_session(mac="b", baseline={"roaming": 88.0}, latest={"roaming": 79.0})])
    assert build_impact_label(ImpactSeverity.WARNING, RecoveryState.MONITORING, warning) == f"WARNING {MINUS_SIGN}9"
    assert build_impact_label(ImpactSeverity.NONE, RecoveryState.COMPLETED, ()) == "NO IMPACT"
    assert build_impact_label(ImpactSeverity.CRITICAL, RecoveryState.RECOVERED, movements) == "RECOVERED"
    assert build_impact_label(ImpactSeverity.INFO, RecoveryState.COMPLETED, ()) == "NO DATA"


def test_title_templates_from_object_type_event_and_count() -> None:
    single = ChangedObjectRef(
        logical_object_id=PydanticObjectId(),
        object_type="gatewaytemplates",
        object_name="NW-Edge-Standard",
        scope="org",
        event="updated",
    )
    assert build_title([single], None) == "Gateway template updated · NW-Edge-Standard"
    second = single.model_copy(update={"object_type": "rftemplates", "object_name": "Indoor-Dense-6G"})
    assert build_title([single, second], None) == "Gateway template updated on NW-Edge-Standard · 2 objects"
    assert build_title([], "modify wlan") == "modify wlan"
    assert build_title([], None) == "Configuration change"


def test_recovery_state_and_confidence_are_derived_from_sessions() -> None:
    assert resolve_recovery_state([], ()) is RecoveryState.NOT_APPLICABLE
    open_session = _session(mac="a", status=MonitoringStatus.MONITORING)
    assert resolve_recovery_state([open_session], ()) is RecoveryState.MONITORING
    clean = _session(mac="b", baseline={"capacity": 90.0}, latest={"capacity": 91.0})
    assert resolve_recovery_state([clean], measure_movements([clean])) is RecoveryState.COMPLETED
    dipped = _session(
        mac="c",
        baseline={"time-to-connect": 91.0},
        latest={"time-to-connect": 91.0},
        degraded=["time-to-connect"],
    )
    assert resolve_recovery_state([dipped], measure_movements([dipped])) is RecoveryState.RECOVERED
    down = _session(
        mac="d",
        baseline={"capacity": 41.0},
        latest={"capacity": 12.0},
        degraded=["capacity"],
    )
    assert resolve_recovery_state([down], measure_movements([down])) is RecoveryState.UNRECOVERED

    assert resolve_baseline_confidence([]) is BaselineConfidence.NONE
    assert resolve_baseline_confidence([_session(mac="e")]) is BaselineConfidence.NONE
    assert resolve_baseline_confidence([down]) is BaselineConfidence.HIGH
    thin = _session(mac="f", baseline={"capacity": 41.0}, latest={"capacity": 40.0}, samples=2)
    assert resolve_baseline_confidence([thin]) is BaselineConfidence.MEDIUM
    assert resolve_baseline_confidence([down, _session(mac="g")]) is BaselineConfidence.LOW


# ---------------------------------------------------------------- projection


async def test_rebuild_projects_objects_devices_and_measured_impact() -> None:
    store = _critical_fixture()
    notifier = _RecordingNotifier()

    group = await ChangeGroupProjector(store, notifier).rebuild(ORGANIZATION_ID, "audit-1")

    assert group is not None
    assert [(ref.object_name, ref.before_version, ref.after_version) for ref in group.changed_objects] == [
        ("NW-Corp", 14, 15),
        ("Indoor-Dense-6G", 3, 4),
    ]
    assert group.changed_objects[0].changed_fields == ["band_steer", "max_clients", "rf_template_id"]
    assert len(group.affected_devices) == 6
    assert len(group.monitoring_session_ids) == 6
    assert group.impact_severity is ImpactSeverity.CRITICAL
    assert group.recovery_state is RecoveryState.UNRECOVERED
    assert group.baseline_confidence is BaselineConfidence.HIGH
    assert group.degraded_metrics == ["capacity"]
    assert group.projection_updated_at is not None
    assert notifier.calls
    assert notifier.calls[0][0] == str(group.id)


async def test_rebuild_writes_the_designs_evidence_lines() -> None:
    store = _critical_fixture()

    group = await ChangeGroupProjector(store).rebuild(ORGANIZATION_ID, "audit-1")

    assert group is not None
    labels = [item.label for item in group.evidence]
    assert labels[0] == "Degraded metrics: capacity"
    assert labels[1] == "Infrastructure incidents in window: none"
    assert labels[2] == "Competing changes at this site: none"
    assert labels[3].startswith("Baseline confidence: high · ")
    assert group.deterministic_assessment is not None
    assert "Capacity fell 29 points across 6 of 6 monitored APs" in group.deterministic_assessment
    assert "no other change group touched Seattle-DC" in group.deterministic_assessment
    assert group.summary is not None
    assert group.summary.startswith("j.mercer updated 2 objects at Seattle-DC.")
    assert "6 APs entered monitoring." in group.summary


async def test_rebuild_names_competing_change_groups_at_the_same_site() -> None:
    store = _critical_fixture()
    store.groups.append(_group(audit_id="audit-2", actor="a.osei", occurred_at=NOW + timedelta(hours=1)))

    group = await ChangeGroupProjector(store).rebuild(ORGANIZATION_ID, "audit-1")

    assert group is not None
    assert group.deterministic_assessment is not None
    assert "1 other change group touched Seattle-DC" in group.deterministic_assessment
    assert group.evidence[2].label == "Competing changes at this site: 1"


async def test_rebuild_is_idempotent_under_duplicate_and_out_of_order_events() -> None:
    store = _critical_fixture()
    notifier = _RecordingNotifier()
    projector = ChangeGroupProjector(store, notifier)

    first = await projector.rebuild(ORGANIZATION_ID, "audit-1")
    assert first is not None
    snapshot = first.model_dump(exclude={"projection_updated_at", "updated_at"})

    # A duplicate delivery of the same audit event: the same version rows arrive
    # again, out of order, and one device event replays.
    store.versions.reverse()
    store.versions.append(store.versions[0])
    store.sessions.append(store.sessions[0])

    second = await projector.rebuild(ORGANIZATION_ID, "audit-1")
    third = await projector.rebuild(ORGANIZATION_ID, "audit-1")

    assert second is not None
    assert third is not None
    assert second.model_dump(exclude={"projection_updated_at", "updated_at"}) == snapshot
    assert third.model_dump(exclude={"projection_updated_at", "updated_at"}) == snapshot
    assert len(second.changed_objects) == 2
    assert len(second.affected_devices) == 6
    # The notification service deduplicates, but the projector must not stop
    # asking: every rebuild that still sees critical impact reports it.
    assert {call[0] for call in notifier.calls} == {str(first.id)}


async def test_rebuild_prefers_the_newest_version_an_audit_produced() -> None:
    store = _MemoryChangeGroupStore()
    store.groups.append(_group())
    wlan = _logical(name="NW-Corp", object_type="wlans")
    store.logicals.append(wlan)
    store.versions.extend(
        [
            _version(wlan, version=15, changed_fields=["a"]),
            _version(wlan, version=16, changed_fields=["a", "b"]),
            _version(wlan, version=14, audit_id=None),
        ]
    )

    group = await ChangeGroupProjector(store).rebuild(ORGANIZATION_ID, "audit-1")

    assert group is not None
    assert len(group.changed_objects) == 1
    assert group.changed_objects[0].after_version == 16
    assert group.changed_objects[0].before_version == 15


async def test_rebuild_marks_a_deleted_object_with_no_after_version() -> None:
    store = _MemoryChangeGroupStore()
    store.groups.append(_group())
    wlan = _logical(name="NW-Guest", object_type="wlans", is_deleted=True)
    store.logicals.append(wlan)
    store.versions.extend(
        [
            _version(wlan, version=8, audit_id=None),
            _version(wlan, version=9, event=VersionEvent.DELETED, is_deleted=True),
        ]
    )

    group = await ChangeGroupProjector(store).rebuild(ORGANIZATION_ID, "audit-1")

    assert group is not None
    assert group.changed_objects[0].event == "deleted"
    assert group.changed_objects[0].after_version is None
    assert group.changed_objects[0].before_version == 8


async def test_rebuild_returns_none_for_an_unknown_audit_and_never_writes() -> None:
    store = _critical_fixture()

    assert await ChangeGroupProjector(store).rebuild(ORGANIZATION_ID, "audit-missing") is None
    assert await ChangeGroupProjector(store).rebuild(OTHER_ORGANIZATION_ID, "audit-1") is None
    assert store.saves == 0


async def test_rebuild_stays_quiet_below_critical() -> None:
    store = _MemoryChangeGroupStore()
    store.groups.append(_group())
    store.sessions.append(
        _session(
            mac="aa",
            baseline={"roaming": 88.0},
            latest={"roaming": 79.0},
            severity=ImpactSeverity.WARNING,
            degraded=["roaming"],
        )
    )
    notifier = _RecordingNotifier()

    group = await ChangeGroupProjector(store, notifier).rebuild(ORGANIZATION_ID, "audit-1")

    assert group is not None
    assert group.impact_severity is ImpactSeverity.WARNING
    assert notifier.calls == []


# ---------------------------------------------------------------- read model


async def test_summary_renders_the_designs_metric_tiles() -> None:
    store = _critical_fixture()
    await ChangeGroupProjector(store).rebuild(ORGANIZATION_ID, "audit-1")

    items, total = await ChangeGroupService(store).list_groups(
        ORGANIZATION_ID,
        ChangeGroupFilters(),
        viewer_email="j.mercer@northwind.example",
    )

    assert total == 1
    card = items[0]
    # The fixture's WLAN changes rf_template_id, so the headline names the
    # change the way the design does rather than saying "WLAN updated".
    assert card.title == "RF template reassigned on NW-Corp WLAN · 2 objects"
    assert card.devices_label == "6 APs · Seattle-DC"
    assert card.impact_label == f"CRITICAL {MINUS_SIGN}29"
    assert card.object_count == 2
    assert card.device_count == 6
    assert card.is_mine is True
    tiles = [(tile.label, tile.value, tile.from_, tile.severity.value) for tile in card.metrics]
    assert tiles[0] == ("CAPACITY", "12%", "from 41%", "critical")
    assert tiles[1] == ("TIME TO CONNECT", "84%", "from 91%", "warning")
    assert tiles[2][0] == "SAMPLES"
    assert tiles[3] == ("INCIDENTS", "None", "", "none")


async def test_summary_has_no_tiles_when_nothing_moved() -> None:
    store = _MemoryChangeGroupStore()
    store.groups.append(_group())
    store.sessions.append(_session(mac="aa", baseline={"capacity": 90.0}, latest={"capacity": 91.0}))
    await ChangeGroupProjector(store).rebuild(ORGANIZATION_ID, "audit-1")

    items, _ = await ChangeGroupService(store).list_groups(
        ORGANIZATION_ID,
        ChangeGroupFilters(),
        viewer_email="nobody@example.com",
    )

    assert items[0].metrics == []
    assert items[0].impact_label == "NO IMPACT"
    assert items[0].is_mine is False


async def test_list_filters_by_severity() -> None:
    store = _MemoryChangeGroupStore()
    store.groups.extend(
        [
            _group(audit_id="c", impact_severity=ImpactSeverity.CRITICAL),
            _group(audit_id="w", impact_severity=ImpactSeverity.WARNING),
            _group(audit_id="n", impact_severity=ImpactSeverity.NONE),
            _group(audit_id="i", impact_severity=ImpactSeverity.INFO),
        ]
    )
    service = ChangeGroupService(store)

    async def audits(severity: str) -> list[str]:
        items, _ = await service.list_groups(
            ORGANIZATION_ID,
            ChangeGroupFilters(severity=severity),
            viewer_email="x@example.com",
        )
        return sorted(item.audit_id for item in items)

    assert await audits("any") == ["c", "i", "n", "w"]
    assert await audits("critical") == ["c"]
    assert await audits("warning") == ["w"]
    assert await audits("none") == ["i", "n"]


async def test_list_filters_by_actor_and_free_text() -> None:
    store = _MemoryChangeGroupStore()
    store.groups.extend(
        [
            _group(audit_id="9F2AC41", actor="j.mercer", summary="capacity fell"),
            _group(audit_id="4C810AE", actor="a.osei", summary="roaming settled"),
            _group(audit_id="B0C91D3", actor="terraform-svc", summary="no impact"),
        ]
    )
    service = ChangeGroupService(store)

    by_actor, _ = await service.list_groups(
        ORGANIZATION_ID,
        ChangeGroupFilters(actor="osei"),
        viewer_email="x@example.com",
    )
    assert [item.audit_id for item in by_actor] == ["4C810AE"]

    by_audit, _ = await service.list_groups(
        ORGANIZATION_ID,
        ChangeGroupFilters(query="9f2a"),
        viewer_email="x@example.com",
    )
    assert [item.audit_id for item in by_audit] == ["9F2AC41"]

    by_summary, _ = await service.list_groups(
        ORGANIZATION_ID,
        ChangeGroupFilters(query="roaming"),
        viewer_email="x@example.com",
    )
    assert [item.audit_id for item in by_summary] == ["4C810AE"]


async def test_free_text_treats_regex_metacharacters_literally() -> None:
    store = _MemoryChangeGroupStore()
    store.groups.extend(
        [
            _group(audit_id="plain", summary="capacity fell"),
            _group(audit_id="dotted", summary="a.b matched"),
        ]
    )

    items, _ = await ChangeGroupService(store).list_groups(
        ORGANIZATION_ID,
        ChangeGroupFilters(query="a.b"),
        viewer_email="x@example.com",
    )

    assert [item.audit_id for item in items] == ["dotted"]


async def test_list_spans_days_newest_first_and_honours_the_range() -> None:
    store = _MemoryChangeGroupStore()
    now = datetime.now(tz=UTC)
    store.groups.extend(
        [
            _group(audit_id="today", occurred_at=now - timedelta(hours=2)),
            _group(audit_id="yesterday", occurred_at=now - timedelta(hours=20)),
            _group(audit_id="last-week", occurred_at=now - timedelta(days=6)),
            _group(audit_id="last-month", occurred_at=now - timedelta(days=29)),
        ]
    )
    service = ChangeGroupService(store)

    day, day_total = await service.list_groups(
        ORGANIZATION_ID,
        ChangeGroupFilters(range_key="24h"),
        viewer_email="x@example.com",
    )
    assert [item.audit_id for item in day] == ["today", "yesterday"]
    assert day_total == 2

    week, _ = await service.list_groups(
        ORGANIZATION_ID,
        ChangeGroupFilters(range_key="7d"),
        viewer_email="x@example.com",
    )
    assert [item.audit_id for item in week] == ["today", "yesterday", "last-week"]

    month, _ = await service.list_groups(
        ORGANIZATION_ID,
        ChangeGroupFilters(range_key="30d"),
        viewer_email="x@example.com",
    )
    assert len(month) == 4


async def test_as_of_excludes_groups_that_happened_after_it() -> None:
    store = _MemoryChangeGroupStore()
    now = datetime.now(tz=UTC)
    store.groups.extend(
        [
            _group(audit_id="before", occurred_at=now - timedelta(hours=6)),
            _group(audit_id="after", occurred_at=now - timedelta(hours=1)),
        ]
    )

    items, total = await ChangeGroupService(store).list_groups(
        ORGANIZATION_ID,
        ChangeGroupFilters(as_of=now - timedelta(hours=3)),
        viewer_email="x@example.com",
    )

    assert [item.audit_id for item in items] == ["before"]
    assert total == 1


async def test_list_paginates_without_losing_the_total() -> None:
    store = _MemoryChangeGroupStore()
    now = datetime.now(tz=UTC)
    store.groups.extend(
        _group(audit_id=f"audit-{index}", occurred_at=now - timedelta(minutes=index)) for index in range(5)
    )

    items, total = await ChangeGroupService(store).list_groups(
        ORGANIZATION_ID,
        ChangeGroupFilters(skip=1, limit=2),
        viewer_email="x@example.com",
    )

    assert [item.audit_id for item in items] == ["audit-1", "audit-2"]
    assert total == 5


async def test_detail_carries_objects_devices_evidence_and_competitors() -> None:
    store = _critical_fixture()
    competitor = _group(audit_id="audit-2", actor="a.osei", occurred_at=NOW + timedelta(hours=1))
    store.groups.append(competitor)
    group = await ChangeGroupProjector(store).rebuild(ORGANIZATION_ID, "audit-1")
    assert group is not None
    assert group.id is not None

    detail = await ChangeGroupService(store).get_group(
        ORGANIZATION_ID,
        group.id,
        viewer_email="j.mercer@northwind.example",
    )

    assert detail is not None
    assert detail.message == "modify wlan"
    assert detail.method == "PUT"
    assert detail.baseline_confidence is BaselineConfidence.HIGH
    assert [item.object_name for item in detail.changed_objects] == ["NW-Corp", "Indoor-Dense-6G"]
    assert len(detail.affected_devices) == 6
    assert detail.evidence[0].label == "Degraded metrics: capacity"
    assert detail.competing_change_group_ids == [str(competitor.id)]
    assert detail.impact_label == f"CRITICAL {MINUS_SIGN}29"


async def test_detail_is_scoped_to_its_organization() -> None:
    store = _critical_fixture()
    group = store.groups[0]
    assert group.id is not None

    assert (
        await ChangeGroupService(store).get_group(
            OTHER_ORGANIZATION_ID,
            group.id,
            viewer_email="x@example.com",
        )
        is None
    )


async def test_list_never_crosses_organizations() -> None:
    store = _MemoryChangeGroupStore()
    store.groups.extend(
        [
            _group(audit_id="mine"),
            _group(audit_id="theirs", organization_id=OTHER_ORGANIZATION_ID),
        ]
    )

    items, total = await ChangeGroupService(store).list_groups(
        ORGANIZATION_ID,
        ChangeGroupFilters(),
        viewer_email="x@example.com",
    )

    assert [item.audit_id for item in items] == ["mine"]
    assert total == 1


# ----------------------------------------------------------------------- api


def _app(service: ChangeGroupService, *, organization_id: PydanticObjectId = ORGANIZATION_ID) -> object:
    app = create_app(Settings(environment="test", database_enabled=False))
    app.dependency_overrides[get_current_user] = _viewer
    app.dependency_overrides[require_organization] = lambda: _organization(organization_id)
    app.dependency_overrides[get_change_group_service] = lambda: service
    return app


async def test_list_endpoint_returns_the_page_and_total() -> None:
    store = _critical_fixture()
    await ChangeGroupProjector(store).rebuild(ORGANIZATION_ID, "audit-1")
    app = _app(ChangeGroupService(store))

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(
            f"/api/v1/organizations/{ORGANIZATION_ID}/change-groups",
            params={"range": "24h", "severity": "any"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["impact_label"] == f"CRITICAL {MINUS_SIGN}29"
    assert item["devices_label"] == "6 APs · Seattle-DC"
    assert item["metrics"][0]["from"] == "from 41%"
    assert item["is_mine"] is True


async def test_detail_endpoint_returns_404_for_another_organizations_group() -> None:
    store = _critical_fixture()
    group = await ChangeGroupProjector(store).rebuild(ORGANIZATION_ID, "audit-1")
    assert group is not None
    app = _app(ChangeGroupService(store), organization_id=OTHER_ORGANIZATION_ID)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(
            f"/api/v1/organizations/{OTHER_ORGANIZATION_ID}/change-groups/{group.id}",
        )

    assert response.status_code == 404


async def test_detail_endpoint_serializes_the_full_contract() -> None:
    store = _critical_fixture()
    group = await ChangeGroupProjector(store).rebuild(ORGANIZATION_ID, "audit-1")
    assert group is not None
    app = _app(ChangeGroupService(store))

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(
            f"/api/v1/organizations/{ORGANIZATION_ID}/change-groups/{group.id}",
        )

    assert response.status_code == 200
    body = response.json()
    assert set(body) >= {
        "id",
        "audit_id",
        "actor",
        "source",
        "occurred_at",
        "title",
        "summary",
        "object_count",
        "device_count",
        "affected_site_ids",
        "devices_label",
        "impact_severity",
        "recovery_state",
        "impact_label",
        "degraded_metrics",
        "metrics",
        "monitoring_session_ids",
        "is_mine",
        "message",
        "method",
        "baseline_confidence",
        "deterministic_assessment",
        "evidence",
        "changed_objects",
        "affected_devices",
        "competing_change_group_ids",
    }
    assert body["changed_objects"][0]["changed_fields"] == [
        "band_steer",
        "max_clients",
        "rf_template_id",
    ]


# ------------------------------------------------------- webhook projection


class _RecordingProjector:
    def __init__(self) -> None:
        self.rebuilt: list[tuple[PydanticObjectId, str]] = []

    async def rebuild(self, organization_id: PydanticObjectId, audit_id: str) -> None:
        self.rebuilt.append((organization_id, audit_id))


def _receipt(*, audit_id: str | None, topic: str = "audits") -> WebhookReceipt:
    return WebhookReceipt.model_construct(
        id=PydanticObjectId(),
        organization_id=ORGANIZATION_ID,
        topic=topic,
        event_id="event-1",
        audit_id=audit_id,
        payload_hash="hash",
        encrypted_payload="v1:cipher",
        signature_version="v2",
        signature_valid=True,
        status=WebhookProcessingStatus.PROCESSING,
        processing_attempts=1,
        created_at=NOW,
        updated_at=NOW,
    )


def test_webhook_event_time_reads_seconds_and_milliseconds() -> None:
    seconds = WebhookProcessingService._event_time({"timestamp": 1_757_253_600})  # noqa: SLF001
    millis = WebhookProcessingService._event_time({"when": 1_757_253_600_000})  # noqa: SLF001

    assert seconds == datetime(2025, 9, 7, 14, 0, tzinfo=UTC)
    assert millis == seconds
    assert WebhookProcessingService._event_time({}) is None  # noqa: SLF001
    assert WebhookProcessingService._event_time({"timestamp": True}) is None  # noqa: SLF001


async def test_webhook_processing_rebuilds_the_projection_for_its_audit() -> None:
    projector = _RecordingProjector()
    # Projection never touches the vault; only decryption does.
    service = WebhookProcessingService(vault=None, projector=projector)

    await service.project(_receipt(audit_id="audit-1"), {})

    assert projector.rebuilt == [(ORGANIZATION_ID, "audit-1")]


async def test_webhook_processing_skips_receipts_with_nothing_to_project() -> None:
    projector = _RecordingProjector()
    # Projection never touches the vault; only decryption does.
    service = WebhookProcessingService(vault=None, projector=projector)

    await service.project(_receipt(audit_id=None, topic="device-events"), {})

    assert projector.rebuilt == []


async def test_rebuild_describes_a_dip_that_returned_to_baseline() -> None:
    store = _MemoryChangeGroupStore()
    store.groups.append(_group())
    store.logicals.append(_logical(name="Seattle-DC", object_type="sites", mist_id=SEATTLE))
    store.sessions.append(
        _session(
            mac="aa",
            baseline={"time-to-connect": 91.0},
            latest={"time-to-connect": 89.0},
            degraded=["time-to-connect"],
        )
    )

    group = await ChangeGroupProjector(store).rebuild(ORGANIZATION_ID, "audit-1")
    items, _ = await ChangeGroupService(store).list_groups(
        ORGANIZATION_ID,
        ChangeGroupFilters(),
        viewer_email="x@example.com",
    )

    assert group is not None
    assert group.recovery_state is RecoveryState.RECOVERED
    assert group.summary is not None
    assert group.summary.endswith("Time to connect SLE dipped and returned to baseline.")
    assert group.deterministic_assessment is not None
    assert "has since returned to baseline" in group.deterministic_assessment
    assert items[0].impact_label == "RECOVERED"
    tiles = [(tile.label, tile.value, tile.from_) for tile in items[0].metrics]
    assert tiles[0] == ("TIME TO CONNECT", "89%", "back to baseline")
    assert [tile[0] for tile in tiles] == ["TIME TO CONNECT", "SAMPLES"]


async def test_rebuild_describes_a_change_that_is_still_settling() -> None:
    store = _MemoryChangeGroupStore()
    store.groups.append(_group(sites=[PORTLAND]))
    store.logicals.append(_logical(name="Portland-2", object_type="sites", mist_id=PORTLAND))
    store.sessions.append(
        _session(
            mac="bb",
            site=PORTLAND,
            status=MonitoringStatus.MONITORING,
            baseline={"roaming": 88.0},
            latest={"roaming": 79.0},
            severity=ImpactSeverity.WARNING,
            degraded=["roaming"],
        )
    )

    group = await ChangeGroupProjector(store).rebuild(ORGANIZATION_ID, "audit-1")
    items, _ = await ChangeGroupService(store).list_groups(
        ORGANIZATION_ID,
        ChangeGroupFilters(),
        viewer_email="x@example.com",
    )

    assert group is not None
    assert group.recovery_state is RecoveryState.MONITORING
    assert group.summary is not None
    assert group.summary.endswith("Roaming SLE moved 88% → 79% and is still settling.")
    assert group.deterministic_assessment is not None
    assert "is still being monitored" in group.deterministic_assessment
    assert items[0].impact_label == f"WARNING {MINUS_SIGN}9"


async def test_rebuild_counts_incidents_and_spans_several_sites() -> None:
    store = _MemoryChangeGroupStore()
    store.groups.append(_group(sites=[]))
    store.logicals.extend(
        [
            _logical(name="Seattle-DC", object_type="sites", mist_id=SEATTLE),
            _logical(name="Portland-2", object_type="sites", mist_id=PORTLAND),
        ]
    )
    store.sessions.extend(
        [
            _session(
                mac="cc",
                site=SEATTLE,
                baseline={"capacity": 41.0},
                latest={"capacity": 12.0},
                severity=ImpactSeverity.CRITICAL,
                degraded=["capacity"],
                incidents=[MonitoringIncident(event_type="AP_RECONFIGURED", severity=ImpactSeverity.WARNING)],
            ),
            _session(
                mac="dd",
                site=PORTLAND,
                baseline={"capacity": 41.0},
                latest={"capacity": 12.0},
                severity=ImpactSeverity.CRITICAL,
                degraded=["capacity"],
            ),
        ]
    )

    group = await ChangeGroupProjector(store).rebuild(ORGANIZATION_ID, "audit-1")
    items, _ = await ChangeGroupService(store).list_groups(
        ORGANIZATION_ID,
        ChangeGroupFilters(),
        viewer_email="x@example.com",
    )

    assert group is not None
    assert group.affected_site_ids == sorted([PORTLAND, SEATTLE])
    assert group.summary is not None
    assert "across 2 sites" in group.summary
    assert group.deterministic_assessment is not None
    assert "1 infrastructure incident overlaps this window" in group.deterministic_assessment
    assert "these 2 sites" in group.deterministic_assessment
    assert group.evidence[1].label == "Infrastructure incidents in window: 1"
    assert items[0].devices_label == "2 APs · 2 sites"
    assert [tile.label for tile in items[0].metrics] == ["CAPACITY", "SAMPLES", "INCIDENTS"]
    assert items[0].metrics[-1].value == "1"


async def test_summary_reports_an_organization_wide_change_with_no_devices() -> None:
    store = _MemoryChangeGroupStore()
    store.groups.append(_group(sites=[]))

    group = await ChangeGroupProjector(store).rebuild(ORGANIZATION_ID, "audit-1")
    items, _ = await ChangeGroupService(store).list_groups(
        ORGANIZATION_ID,
        ChangeGroupFilters(),
        viewer_email="x@example.com",
    )

    assert group is not None
    assert group.summary == (
        "j.mercer changed 0 objects organization-wide. No device monitoring was correlated with this change."
    )
    assert group.deterministic_assessment == (
        "No device monitoring was correlated with this change group, so no impact could be measured."
    )
    assert items[0].devices_label == "org-wide"
    assert items[0].impact_label == "NO IMPACT"


def _changed(object_type: str, name: str, fields: list[str], event: str = "updated") -> ChangedObjectRef:
    return ChangedObjectRef(
        logical_object_id=PydanticObjectId(),
        object_type=object_type,
        object_name=name,
        scope="org",
        event=event,
        changed_fields=fields,
    )


def test_a_known_field_gives_the_headline_the_design_shows() -> None:
    """The design names the change itself, not just "<type> updated"."""
    title = build_title([_changed("wlans", "NW-Corp", ["rf_template_id", "band_steer"])], None)

    assert title == "RF template reassigned on NW-Corp WLAN"


def test_the_headline_stays_scope_free() -> None:
    """The scope prefix belongs in the table column, not in a sentence."""
    assert "Organization" not in build_title([_changed("wlans", "NW-Guest", ["psk"])], None)
    assert build_title([_changed("wlans", "NW-Guest", ["psk"])], None) == "NW-Guest PSK rotated"


def test_several_objects_keep_the_phrase_and_count_the_rest() -> None:
    """A group covering more than one object still leads with what happened."""
    title = build_title(
        [
            _changed("wlans", "NW-Corp", ["rf_template_id"]),
            _changed("rftemplates", "Indoor-Dense-6G", ["band_5.channels"]),
        ],
        None,
    )

    assert title == "RF template reassigned on NW-Corp WLAN · 2 objects"


def test_an_unknown_field_falls_back_to_the_generic_form() -> None:
    """Prose cannot be invented for arbitrary Mist fields."""
    title = build_title([_changed("gatewaytemplates", "NW-Edge-Standard", ["port_config"])], None)

    assert title == "Gateway template updated · NW-Edge-Standard"


def test_a_creation_is_never_described_as_a_field_change() -> None:
    """Saying a field changed on an object that did not exist would be wrong."""
    title = build_title([_changed("wlans", "New-WLAN", ["rf_template_id"], event="created")], None)

    assert title == "Organization WLAN created · New-WLAN"
