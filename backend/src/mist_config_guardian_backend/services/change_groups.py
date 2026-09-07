"""Change-group projection, presentation, and read model.

One Mist administrator action is one change group (``organization_id +
audit_id``). :class:`ChangeGroupProjector` folds everything that action produced
- object versions, monitoring sessions, devices, and measured SLE movement -
into the stored projection on :class:`AuditChangeGroup`. The projection is
recomputed from its sources every time, never mutated incrementally, so
duplicate and out-of-order webhook deliveries converge on the same result.

Every label in this module is a template filled from measured values. No text
here comes from an AI provider.
"""

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from beanie import PydanticObjectId

from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.monitoring import (
    DeviceType,
    ImpactSeverity,
    MonitoringSession,
    MonitoringStatus,
)
from mist_config_guardian_backend.models.notification import NotificationSeverity
from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectVersion, VersionEvent
from mist_config_guardian_backend.models.webhook import (
    AffectedDevice,
    AuditChangeGroup,
    BaselineConfidence,
    ChangedObjectRef,
    ChangeEvidence,
    RecoveryState,
)
from mist_config_guardian_backend.schemas.change_group import (
    AffectedDeviceResponse,
    ChangedObjectResponse,
    ChangeEvidenceResponse,
    ChangeGroupDetailResponse,
    ChangeGroupSummaryResponse,
    ChangeMetricResponse,
)
from mist_config_guardian_backend.snapshots.registry import ORG_OBJECTS, SITE_OBJECTS

# The design prints impact deltas with a typographic minus, not a hyphen. The
# glyph is deliberate: it is what the approved badge design uses.
MINUS_SIGN = "−"  # noqa: RUF001

# Movement bands, in SLE percentage points, applied to (latest - baseline).
# ``TILE_BAND`` decides whether a metric is worth a tile at all; the other two
# decide the tile's colour. They are display bands: the authoritative
# ``degraded_metrics`` list is whatever the monitoring pipeline recorded.
TILE_BAND = -5.0
WARNING_BAND = -10.0
CRITICAL_BAND = -25.0

# Polls a session needs before its baseline counts as strong evidence.
HIGH_CONFIDENCE_SAMPLES = 6

_RANGE_WINDOWS: Mapping[str, timedelta] = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}
_DEFAULT_RANGE = "24h"

_IMPACTING = (ImpactSeverity.WARNING, ImpactSeverity.CRITICAL)
_SEVERITY_RANK: Mapping[ImpactSeverity, int] = {
    ImpactSeverity.NONE: 0,
    ImpactSeverity.INFO: 1,
    ImpactSeverity.WARNING: 2,
    ImpactSeverity.CRITICAL: 3,
}
_OPEN_STATUSES = (MonitoringStatus.AWAITING_CONFIG, MonitoringStatus.MONITORING)

_EVENT_VERB: Mapping[VersionEvent, str] = {
    VersionEvent.INITIAL: "captured",
    VersionEvent.CREATED: "created",
    VersionEvent.UPDATED: "updated",
    VersionEvent.DELETED: "deleted",
    VersionEvent.RESTORED: "restored",
}
# Phrasing for the handful of fields whose change is worth naming outright. The
# design's headlines read as prose ("RF template reassigned on NW-Corp WLAN")
# rather than as "<type> updated", but prose cannot be invented for arbitrary
# Mist fields, so only these well-understood ones get a phrase and everything
# else falls back to the generic form.
_FIELD_PHRASES: Mapping[str, str] = {
    "rf_template_id": "RF template reassigned on {name} {label}",
    "rftemplate_id": "RF template reassigned on {name} {label}",
    "sitegroup_ids": "Site group reassigned · {name}",
    "site_ids": "Site group reassigned · {name}",
    "psk": "{name} PSK rotated",
    "auth_servers_timeout": "Authentication server timeout changed · {name}",
    "vlan_id": "VLAN reassigned on {name}",
    "gatewaytemplate_id": "Gateway template reassigned on {name}",
    "networktemplate_id": "Switch template reassigned on {name}",
}
_DEVICE_NOUNS: Mapping[DeviceType, tuple[str, str]] = {
    DeviceType.AP: ("AP", "APs"),
    DeviceType.SWITCH: ("switch", "switches"),
    DeviceType.GATEWAY: ("gateway", "gateways"),
}
# A few keys - "wlans", "webhooks" - exist at both scopes with different
# labels, so the two registries stay in separate tables.
_OBJECT_LABELS: Mapping[str, Mapping[str, str]] = {
    "org": {definition.key: definition.label for definition in ORG_OBJECTS},
    "site": {definition.key: definition.label for definition in SITE_OBJECTS},
}


def as_utc(value: datetime) -> datetime:
    """Attach UTC to a naive timestamp so stored and generated times compare."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def resolve_window(range_key: str, as_of: datetime | None = None) -> tuple[datetime, datetime]:
    """Resolve a UI range key and optional as-of instant into an absolute window."""
    end = as_utc(as_of) if as_of is not None else utc_now()
    return end - _RANGE_WINDOWS.get(range_key, _RANGE_WINDOWS[_DEFAULT_RANGE]), end


def actor_matches(actor: str | None, email: str) -> bool:
    """Report whether a change group's actor is the given user.

    Mist records an administrator name that is often the mailbox local part
    rather than the full address, so both forms count as a match.
    """
    if not actor:
        return False
    candidate = actor.strip().lower()
    address = email.strip().lower()
    return candidate in {address, address.partition("@")[0]}


def worst_severity(values: Iterable[ImpactSeverity]) -> ImpactSeverity:
    """Return the highest severity in the collection, or none when it is empty."""
    return max(values, key=lambda item: _SEVERITY_RANK[item], default=ImpactSeverity.NONE)


def object_type_label(object_type: str, scope: str = "org") -> str:
    """Render a registry object type as the sentence-case noun a title uses.

    ``rftemplates`` becomes ``RF template`` and an organization ``wlans``
    becomes ``Organization WLAN``: the leading word keeps its casing so acronyms
    survive, and every following word is lowered unless it is itself an acronym.
    """
    preferred = "site" if scope == "site" else "org"
    label = _OBJECT_LABELS[preferred].get(object_type) or _OBJECT_LABELS["org" if preferred == "site" else "site"].get(
        object_type
    )
    if label is None:
        return object_type.replace("_", " ").capitalize()
    words = [_singular(word) for word in label.split()]
    return " ".join(word if index == 0 or word.isupper() else word.lower() for index, word in enumerate(words))


def format_duration(delta: timedelta) -> str:
    """Render an elapsed interval the way the design writes it (``5h 10m``)."""
    minutes = max(0, int(delta.total_seconds() // 60))
    days, minutes = divmod(minutes, 24 * 60)
    hours, minutes = divmod(minutes, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _singular(word: str) -> str:
    return word[:-1] if len(word) > 1 and word.endswith("s") and not word.endswith("ss") else word


def _metric_label(metric: str) -> str:
    return metric.replace("-", " ").replace("_", " ").upper()


def _metric_phrase(metric: str) -> str:
    return metric.replace("-", " ").replace("_", " ")


@dataclass(frozen=True, slots=True)
class MetricMovement:
    """One SLE metric's measured movement across a change group's sessions."""

    metric: str
    baseline: float
    latest: float
    sessions: int
    degraded_sessions: int

    @property
    def delta(self) -> float:
        """Signed movement from baseline to the latest observation."""
        return round(self.latest - self.baseline, 2)

    @property
    def severity(self) -> ImpactSeverity:
        """Display severity for this metric's tile."""
        if self.delta <= CRITICAL_BAND:
            return ImpactSeverity.CRITICAL
        if self.delta <= TILE_BAND:
            return ImpactSeverity.WARNING
        return ImpactSeverity.NONE


@dataclass(frozen=True, slots=True)
class GroupEvidenceInput:
    """Everything measured about one change group, before it is templated."""

    movements: tuple[MetricMovement, ...]
    session_count: int
    device_count: int
    device_noun: str
    sample_count: int
    incident_count: int
    unresolved_incidents: int
    competing_group_ids: tuple[str, ...]
    site_labels: tuple[str, ...]
    monitored_for: timedelta | None

    @property
    def worst(self) -> MetricMovement | None:
        """The metric that moved down the most, when anything moved."""
        ranked = sorted(self.movements, key=lambda item: item.delta)
        return ranked[0] if ranked and ranked[0].delta < 0 else None


class ChangeGroupStore(Protocol):
    """Persistence the projector and the read model depend on."""

    async def group_by_audit(
        self,
        organization_id: PydanticObjectId,
        audit_id: str,
    ) -> AuditChangeGroup | None:
        """Return one organization's change group for an audit identifier."""

    async def group_by_id(
        self,
        organization_id: PydanticObjectId,
        group_id: PydanticObjectId,
    ) -> AuditChangeGroup | None:
        """Return one organization's change group by its own identifier."""

    async def save(self, group: AuditChangeGroup) -> None:
        """Persist a recomputed projection."""

    async def count(self, criteria: Mapping[str, object]) -> int:
        """Count change groups matching a criteria document."""

    async def page(
        self,
        criteria: Mapping[str, object],
        *,
        skip: int,
        limit: int,
    ) -> list[AuditChangeGroup]:
        """Return one newest-first page of change groups."""

    async def versions_for_audit(
        self,
        organization_id: PydanticObjectId,
        audit_id: str,
    ) -> list[ObjectVersion]:
        """Return every object version an audit event produced."""

    async def versions_at(
        self,
        organization_id: PydanticObjectId,
        pairs: Sequence[tuple[PydanticObjectId, int]],
    ) -> list[ObjectVersion]:
        """Return the versions addressed by explicit (logical object, version) pairs."""

    async def logical_objects(
        self,
        organization_id: PydanticObjectId,
        object_ids: Sequence[PydanticObjectId],
    ) -> list[LogicalObject]:
        """Return logical objects by identifier, scoped to one organization."""

    async def sessions_for_audit(
        self,
        organization_id: PydanticObjectId,
        audit_id: str,
    ) -> list[MonitoringSession]:
        """Return every monitoring session correlated with an audit event."""

    async def sessions_by_id(
        self,
        organization_id: PydanticObjectId,
        session_ids: Sequence[PydanticObjectId],
    ) -> list[MonitoringSession]:
        """Return monitoring sessions by identifier, scoped to one organization."""

    async def groups_touching_sites(
        self,
        organization_id: PydanticObjectId,
        site_ids: Sequence[str],
        *,
        start: datetime,
        end: datetime,
        exclude_audit_id: str,
    ) -> list[AuditChangeGroup]:
        """Return other change groups that touched the same sites inside a window."""

    async def site_names(
        self,
        organization_id: PydanticObjectId,
        site_ids: Sequence[str],
    ) -> dict[str, str]:
        """Map site Mist identifiers onto their stored names."""


class ImpactNotifier(Protocol):
    """The one notification the projector emits."""

    async def notify_impact_detected(
        self,
        *,
        organization_id: PydanticObjectId,
        change_group_id: str,
        summary: str,
        severity: NotificationSeverity = NotificationSeverity.CRITICAL,
    ) -> object:
        """Report a configuration change that degraded the network."""


class BeanieChangeGroupStore:
    """MongoDB-backed change-group storage."""

    async def group_by_audit(
        self,
        organization_id: PydanticObjectId,
        audit_id: str,
    ) -> AuditChangeGroup | None:
        """Return one organization's change group for an audit identifier."""
        return await AuditChangeGroup.find_one(
            AuditChangeGroup.organization_id == organization_id,
            AuditChangeGroup.audit_id == audit_id,
        )

    async def group_by_id(
        self,
        organization_id: PydanticObjectId,
        group_id: PydanticObjectId,
    ) -> AuditChangeGroup | None:
        """Return one organization's change group by its own identifier."""
        return await AuditChangeGroup.find_one(
            AuditChangeGroup.id == group_id,
            AuditChangeGroup.organization_id == organization_id,
        )

    async def save(self, group: AuditChangeGroup) -> None:
        """Persist a recomputed projection."""
        await group.save()

    async def count(self, criteria: Mapping[str, object]) -> int:
        """Count change groups matching a criteria document."""
        return await AuditChangeGroup.find(dict(criteria)).count()

    async def page(
        self,
        criteria: Mapping[str, object],
        *,
        skip: int,
        limit: int,
    ) -> list[AuditChangeGroup]:
        """Return one newest-first page of change groups."""
        return await AuditChangeGroup.find(dict(criteria)).sort("-occurred_at").skip(skip).limit(limit).to_list()

    async def versions_for_audit(
        self,
        organization_id: PydanticObjectId,
        audit_id: str,
    ) -> list[ObjectVersion]:
        """Return every object version an audit event produced."""
        return await ObjectVersion.find(
            ObjectVersion.organization_id == organization_id,
            ObjectVersion.audit_id == audit_id,
        ).to_list()

    async def versions_at(
        self,
        organization_id: PydanticObjectId,
        pairs: Sequence[tuple[PydanticObjectId, int]],
    ) -> list[ObjectVersion]:
        """Return the versions addressed by explicit (logical object, version) pairs."""
        if not pairs:
            return []
        return await ObjectVersion.find(
            {
                "organization_id": organization_id,
                "$or": [{"logical_object_id": logical_id, "version": version} for logical_id, version in pairs],
            }
        ).to_list()

    async def logical_objects(
        self,
        organization_id: PydanticObjectId,
        object_ids: Sequence[PydanticObjectId],
    ) -> list[LogicalObject]:
        """Return logical objects by identifier, scoped to one organization."""
        if not object_ids:
            return []
        return await LogicalObject.find(
            {"organization_id": organization_id, "_id": {"$in": list(object_ids)}}
        ).to_list()

    async def sessions_for_audit(
        self,
        organization_id: PydanticObjectId,
        audit_id: str,
    ) -> list[MonitoringSession]:
        """Return every monitoring session correlated with an audit event."""
        return await MonitoringSession.find({"organization_id": organization_id, "audit_ids": audit_id}).to_list()

    async def sessions_by_id(
        self,
        organization_id: PydanticObjectId,
        session_ids: Sequence[PydanticObjectId],
    ) -> list[MonitoringSession]:
        """Return monitoring sessions by identifier, scoped to one organization."""
        if not session_ids:
            return []
        return await MonitoringSession.find(
            {"organization_id": organization_id, "_id": {"$in": list(session_ids)}}
        ).to_list()

    async def groups_touching_sites(
        self,
        organization_id: PydanticObjectId,
        site_ids: Sequence[str],
        *,
        start: datetime,
        end: datetime,
        exclude_audit_id: str,
    ) -> list[AuditChangeGroup]:
        """Return other change groups that touched the same sites inside a window."""
        if not site_ids:
            return []
        return await AuditChangeGroup.find(
            {
                "organization_id": organization_id,
                "affected_site_ids": {"$in": list(site_ids)},
                "audit_id": {"$ne": exclude_audit_id},
                "occurred_at": {"$gte": start, "$lte": end},
            }
        ).to_list()

    async def site_names(
        self,
        organization_id: PydanticObjectId,
        site_ids: Sequence[str],
    ) -> dict[str, str]:
        """Map site Mist identifiers onto their stored names."""
        if not site_ids:
            return {}
        sites = await LogicalObject.find(
            {
                "organization_id": organization_id,
                "object_type": "sites",
                "current_mist_id": {"$in": list(site_ids)},
            }
        ).to_list()
        return {site.current_mist_id: site.name for site in sites if site.name}


def build_title(objects: Sequence[ChangedObjectRef], message: str | None) -> str:
    """Template a change group's headline from its changed objects."""
    if not objects:
        return message or "Configuration change"
    primary = objects[0]
    label = object_type_label(primary.object_type, primary.scope)
    phrased = _phrase_for(primary, label)
    if phrased is not None:
        return phrased if len(objects) == 1 else f"{phrased} · {len(objects)} objects"
    verb = _EVENT_VERB.get(VersionEvent(primary.event), primary.event) if _is_event(primary.event) else primary.event
    if len(objects) == 1:
        return f"{label} {verb} · {primary.object_name}"
    return f"{label} {verb} on {primary.object_name} · {len(objects)} objects"


def _phrase_for(primary: ChangedObjectRef, label: str) -> str | None:
    """Name the change outright when one of its fields has known phrasing.

    Only an update qualifies: a creation or deletion is already fully described
    by its verb, and saying a field "changed" on an object that did not exist
    before would be wrong.
    """
    if primary.event != VersionEvent.UPDATED.value:
        return None
    for field in primary.changed_fields:
        # Nested paths ("wlan.rf_template_id") are named by their leaf.
        phrase = _FIELD_PHRASES.get(field) or _FIELD_PHRASES.get(field.rsplit(".", 1)[-1])
        if phrase is not None:
            # A headline names the object, so the scope prefix the table column
            # needs ("Organization WLAN") only gets in the way here.
            plain = label.removeprefix("Organization ").removeprefix("Site ")
            return phrase.format(name=primary.object_name, label=plain)
    return None


def _is_event(value: str) -> bool:
    return value in {item.value for item in VersionEvent}


def build_devices_label(devices: Sequence[AffectedDevice], site_names: Mapping[str, str]) -> str:
    """Render the terse device column (``6 APs · Seattle-DC``, ``org-wide``)."""
    if not devices:
        return "org-wide"
    types = {device.device_type for device in devices if device.device_type}
    singular, plural = ("device", "devices")
    if len(types) == 1:
        noun = _DEVICE_NOUNS.get(DeviceType(next(iter(types)))) if _is_device_type(next(iter(types))) else None
        singular, plural = noun or (singular, plural)
    count = len(devices)
    noun = singular if count == 1 else plural
    sites = sorted({device.site_mist_id for device in devices if device.site_mist_id})
    if not sites:
        return f"{count} {noun} · org-wide"
    if len(sites) == 1:
        return f"{count} {noun} · {site_names.get(sites[0], sites[0])}"
    return f"{count} {noun} · {len(sites)} sites"


def _is_device_type(value: str) -> bool:
    return value in {item.value for item in DeviceType}


def build_impact_label(
    severity: ImpactSeverity,
    recovery: RecoveryState,
    movements: Sequence[MetricMovement],
) -> str:
    """Render the badge text (``CRITICAL −29``, ``RECOVERED``, ``NO IMPACT``)."""  # noqa: RUF002
    if recovery is RecoveryState.RECOVERED:
        return "RECOVERED"
    if severity is ImpactSeverity.INFO:
        return "NO DATA"
    if severity not in _IMPACTING:
        return "NO IMPACT"
    worst = min((movement.delta for movement in movements), default=0.0)
    suffix = f" {MINUS_SIGN}{abs(round(worst))}" if worst < 0 else ""
    return f"{severity.value.upper()}{suffix}"


def build_metrics(
    evidence: GroupEvidenceInput,
    severity: ImpactSeverity,
    recovery: RecoveryState,
) -> list[ChangeMetricResponse]:
    """Build the metric tiles an Overview feed card renders."""
    banded = sorted(
        (movement for movement in evidence.movements if movement.delta <= TILE_BAND),
        key=lambda movement: movement.delta,
    )
    recovered = recovery is RecoveryState.RECOVERED
    if not banded and not recovered and severity not in _IMPACTING:
        return []
    tiles = [
        ChangeMetricResponse(
            label=_metric_label(movement.metric),
            value=f"{movement.latest:.0f}%",
            **{"from": f"from {movement.baseline:.0f}%"},
            severity=movement.severity,
        )
        for movement in banded
    ]
    if recovered and not tiles:
        tiles = [
            ChangeMetricResponse(
                label=_metric_label(movement.metric),
                value=f"{movement.latest:.0f}%",
                **{"from": "back to baseline"},
                severity=ImpactSeverity.NONE,
            )
            for movement in sorted(evidence.movements, key=lambda item: item.baseline - item.latest, reverse=True)[:1]
        ]
    if not tiles:
        return []
    tiles.append(
        ChangeMetricResponse(
            label="SAMPLES",
            value=str(evidence.sample_count),
            **{"from": ""},
            severity=ImpactSeverity.NONE,
        )
    )
    if evidence.incident_count or severity in _IMPACTING:
        tiles.append(
            ChangeMetricResponse(
                label="INCIDENTS",
                value=str(evidence.incident_count) if evidence.incident_count else "None",
                **{"from": ""},
                severity=ImpactSeverity.WARNING if evidence.unresolved_incidents else ImpactSeverity.NONE,
            )
        )
    return tiles


def build_summary(
    group: AuditChangeGroup,
    evidence: GroupEvidenceInput,
    recovery: RecoveryState,
) -> str:
    """Template the sentence under a feed card's title from measured values."""
    actor = group.actor or "An unattributed actor"
    verb = (
        _EVENT_VERB.get(VersionEvent(group.changed_objects[0].event), "changed") if group.changed_objects else "changed"
    )
    count = len(group.changed_objects)
    noun = "object" if count == 1 else "objects"
    scope = _scope_clause(evidence.site_labels)
    sentences = [f"{actor} {verb} {count} {noun} {scope}."]
    if evidence.device_count:
        device_noun = evidence.device_noun
        sentences.append(f"{evidence.device_count} {device_noun} entered monitoring.")
    sentences.append(_impact_sentence(evidence, recovery))
    return " ".join(sentences)


def _scope_clause(site_labels: Sequence[str]) -> str:
    if not site_labels:
        return "organization-wide"
    if len(site_labels) == 1:
        return f"at {site_labels[0]}"
    return f"across {len(site_labels)} sites"


def _impact_sentence(evidence: GroupEvidenceInput, recovery: RecoveryState) -> str:
    worst = evidence.worst
    if recovery is RecoveryState.NOT_APPLICABLE:
        return "No device monitoring was correlated with this change."
    if worst is None:
        return "Monitoring completed with no metric moving beyond noise."
    metric = _metric_phrase(worst.metric).capitalize()
    if recovery is RecoveryState.UNRECOVERED:
        elapsed = format_duration(evidence.monitored_for) if evidence.monitored_for else "the monitoring window"
        return f"{metric} SLE has not recovered after {elapsed}."
    if recovery is RecoveryState.RECOVERED:
        return f"{metric} SLE dipped and returned to baseline."
    if recovery is RecoveryState.MONITORING:
        return f"{metric} SLE moved {worst.baseline:.0f}% → {worst.latest:.0f}% and is still settling."
    return "Monitoring completed with no metric moving beyond noise."


def build_assessment(evidence: GroupEvidenceInput, recovery: RecoveryState) -> str:
    """Template the deterministic assessment paragraph from measured values."""
    worst = evidence.worst
    if recovery is RecoveryState.NOT_APPLICABLE:
        return "No device monitoring was correlated with this change group, so no impact could be measured."
    if worst is None:
        return "No monitored metric moved beyond the noise band during the window."
    metric = _metric_phrase(worst.metric).capitalize()
    points = abs(round(worst.delta))
    noun = evidence.device_noun
    first = (
        f"{metric} fell {points} points across {worst.degraded_sessions} of {evidence.session_count} monitored {noun}"
    )
    if recovery is RecoveryState.UNRECOVERED and evidence.monitored_for is not None:
        first = f"{first} and has not recovered in {format_duration(evidence.monitored_for)}."
    elif recovery is RecoveryState.RECOVERED:
        first = f"{first} and has since returned to baseline."
    else:
        first = f"{first} and is still being monitored."
    return f"{first} {_incident_clause(evidence)} and {_competing_clause(evidence)}."


def _incident_clause(evidence: GroupEvidenceInput) -> str:
    count = evidence.incident_count
    if not count:
        return "No infrastructure incidents overlap this window"
    if count == 1:
        return "1 infrastructure incident overlaps this window"
    return f"{count} infrastructure incidents overlap this window"


def _competing_clause(evidence: GroupEvidenceInput) -> str:
    site = _site_phrase(evidence.site_labels)
    count = len(evidence.competing_group_ids)
    if not count:
        return f"no other change group touched {site}, so the regression is attributable to this change group"
    if count == 1:
        return f"1 other change group touched {site}, so attribution is shared with that change"
    return f"{count} other change groups touched {site}, so attribution is shared with those changes"


def _site_phrase(site_labels: Sequence[str]) -> str:
    if not site_labels:
        return "any site"
    if len(site_labels) == 1:
        return site_labels[0]
    return f"these {len(site_labels)} sites"


def build_evidence(
    evidence: GroupEvidenceInput,
    degraded_metrics: Sequence[str],
    confidence: BaselineConfidence,
) -> list[ChangeEvidence]:
    """Build the deterministic evidence lines shown under an assessment."""
    degraded_label = ", ".join(_metric_phrase(metric) for metric in degraded_metrics) or "none"
    items = [
        ChangeEvidence(
            label=f"Degraded metrics: {degraded_label}",
            severity=ImpactSeverity.WARNING if degraded_metrics else ImpactSeverity.NONE,
        ),
        ChangeEvidence(
            label=f"Infrastructure incidents in window: {evidence.incident_count or 'none'}",
            severity=ImpactSeverity.WARNING if evidence.unresolved_incidents else ImpactSeverity.NONE,
        ),
        ChangeEvidence(
            label=f"Competing changes at this site: {len(evidence.competing_group_ids) or 'none'}",
            severity=ImpactSeverity.WARNING if evidence.competing_group_ids else ImpactSeverity.NONE,
        ),
    ]
    samples = "no samples" if not evidence.sample_count else f"{evidence.sample_count} samples"
    items.append(
        ChangeEvidence(
            label=f"Baseline confidence: {confidence.value} · {samples}",
            severity=(ImpactSeverity.NONE if confidence is BaselineConfidence.HIGH else ImpactSeverity.WARNING),
        )
    )
    return items


def measure_movements(sessions: Sequence[MonitoringSession]) -> tuple[MetricMovement, ...]:
    """Average each metric's baseline and latest observation across sessions."""
    totals: dict[str, list[tuple[float, float]]] = {}
    for session in sessions:
        latest = session.observations[-1] if session.observations else None
        if session.baseline is None or latest is None:
            continue
        for metric, baseline in session.baseline.values.items():
            current = latest.values.get(metric)
            if current is not None:
                totals.setdefault(metric, []).append((baseline, current))
    movements = []
    for metric, pairs in totals.items():
        baseline = sum(pair[0] for pair in pairs) / len(pairs)
        current = sum(pair[1] for pair in pairs) / len(pairs)
        degraded = sum(1 for before, after in pairs if after - before <= TILE_BAND)
        movements.append(
            MetricMovement(
                metric=metric,
                baseline=round(baseline, 2),
                latest=round(current, 2),
                sessions=len(pairs),
                degraded_sessions=degraded,
            )
        )
    return tuple(sorted(movements, key=lambda movement: (movement.delta, movement.metric)))


def resolve_recovery_state(
    sessions: Sequence[MonitoringSession],
    movements: Sequence[MetricMovement],
) -> RecoveryState:
    """Classify a group's recovery from its sessions and their measured movement."""
    if not sessions:
        return RecoveryState.NOT_APPLICABLE
    if any(session.status in _OPEN_STATUSES for session in sessions):
        return RecoveryState.MONITORING
    degraded = any(session.degraded_metrics for session in sessions) or any(
        session.impact_severity in _IMPACTING for session in sessions
    )
    if not degraded:
        return RecoveryState.COMPLETED
    still_down = any(movement.delta <= TILE_BAND for movement in movements)
    return RecoveryState.UNRECOVERED if still_down else RecoveryState.RECOVERED


def resolve_baseline_confidence(sessions: Sequence[MonitoringSession]) -> BaselineConfidence:
    """Grade the evidence behind a group's before-and-after comparison."""
    if not sessions:
        return BaselineConfidence.NONE
    with_baseline = [session for session in sessions if session.baseline is not None]
    if not with_baseline:
        return BaselineConfidence.NONE
    if len(with_baseline) < len(sessions):
        return BaselineConfidence.LOW
    if all(len(session.observations) >= HIGH_CONFIDENCE_SAMPLES for session in sessions):
        return BaselineConfidence.HIGH
    return BaselineConfidence.MEDIUM


class ChangeGroupProjector:
    """Recompute a change group's stored projection from its sources.

    ``rebuild`` is the whole contract: it is safe to call from webhook
    processing, from monitoring completion, and from a backfill, in any order
    and any number of times.
    """

    def __init__(
        self,
        store: ChangeGroupStore | None = None,
        notifications: ImpactNotifier | None = None,
    ) -> None:
        self._store = store if store is not None else BeanieChangeGroupStore()
        self._notifications = notifications

    async def rebuild(
        self,
        organization_id: PydanticObjectId,
        audit_id: str,
    ) -> AuditChangeGroup | None:
        """Recompute one change group's projection idempotently."""
        group = await self._store.group_by_audit(organization_id, audit_id)
        if group is None:
            return None

        changed_objects = await self._project_objects(organization_id, audit_id)
        sessions = _distinct_sessions(await self._store.sessions_for_audit(organization_id, audit_id))

        group.changed_objects = changed_objects
        group.affected_devices = _project_devices(sessions)
        group.monitoring_session_ids = [session.id for session in sessions if session.id is not None]
        group.affected_site_ids = sorted(
            {site for site in group.affected_site_ids if site}
            | {ref.site_mist_id for ref in changed_objects if ref.site_mist_id}
            | {session.site_id for session in sessions if session.site_id}
        )
        group.occurred_at = _resolve_occurred_at(group, changed_objects, sessions)

        movements = measure_movements(sessions)
        group.impact_severity = worst_severity(session.impact_severity for session in sessions)
        group.recovery_state = resolve_recovery_state(sessions, movements)
        group.baseline_confidence = resolve_baseline_confidence(sessions)
        group.degraded_metrics = sorted({metric for session in sessions for metric in session.degraded_metrics})

        evidence = await self._collect_evidence(organization_id, group, sessions, movements)
        group.deterministic_assessment = build_assessment(evidence, group.recovery_state)
        group.evidence = build_evidence(evidence, group.degraded_metrics, group.baseline_confidence)
        group.summary = build_summary(group, evidence, group.recovery_state)
        group.projection_updated_at = utc_now()
        group.touch()
        await self._store.save(group)

        await self._announce(group)
        return group

    async def _project_objects(
        self,
        organization_id: PydanticObjectId,
        audit_id: str,
    ) -> list[ChangedObjectRef]:
        versions = await self._store.versions_for_audit(organization_id, audit_id)
        if not versions:
            return []
        # Only the newest version an audit produced for each object is the
        # "after"; a replayed webhook that produced two must not double-count.
        newest: dict[PydanticObjectId, ObjectVersion] = {}
        for version in versions:
            current = newest.get(version.logical_object_id)
            if current is None or version.version > current.version:
                newest[version.logical_object_id] = version

        logicals = await self._store.logical_objects(organization_id, list(newest))
        by_id = {logical.id: logical for logical in logicals if logical.id is not None}
        previous = await self._store.versions_at(
            organization_id,
            [(logical_id, version.version - 1) for logical_id, version in newest.items() if version.version > 1],
        )
        before = {(item.logical_object_id, item.version): item for item in previous}

        refs = []
        for logical_id, version in newest.items():
            logical = by_id.get(logical_id)
            if logical is None:
                continue
            prior = before.get((logical_id, version.version - 1))
            refs.append(
                ChangedObjectRef(
                    logical_object_id=logical_id,
                    object_type=logical.object_type,
                    object_name=logical.name,
                    scope=logical.scope,
                    site_mist_id=logical.site_mist_id,
                    event=version.event.value,
                    before_version_id=prior.id if prior is not None else None,
                    after_version_id=None if version.is_deleted else version.id,
                    before_version=prior.version if prior is not None else None,
                    after_version=None if version.is_deleted else version.version,
                    changed_fields=sorted(version.changed_fields),
                )
            )
        # The object that moved the most leads, so the templated title names it.
        refs.sort(key=lambda ref: (-len(ref.changed_fields), ref.object_type, ref.object_name))
        return refs

    async def _collect_evidence(
        self,
        organization_id: PydanticObjectId,
        group: AuditChangeGroup,
        sessions: Sequence[MonitoringSession],
        movements: tuple[MetricMovement, ...],
    ) -> GroupEvidenceInput:
        start, end = _monitoring_window(group, sessions)
        competing = await self._store.groups_touching_sites(
            organization_id,
            group.affected_site_ids,
            start=start,
            end=end,
            exclude_audit_id=group.audit_id,
        )
        names = await self._store.site_names(organization_id, group.affected_site_ids)
        incidents = [incident for session in sessions for incident in session.incidents]
        types = {session.device_type for session in sessions}
        noun = _DEVICE_NOUNS[next(iter(types))][1] if len(types) == 1 else "devices"
        return GroupEvidenceInput(
            movements=movements,
            session_count=len(sessions),
            device_count=len(group.affected_devices),
            device_noun=noun,
            sample_count=sum(len(session.observations) for session in sessions),
            incident_count=len(incidents),
            unresolved_incidents=sum(1 for incident in incidents if not incident.resolved),
            competing_group_ids=tuple(sorted(str(item.id) for item in competing if item.id is not None)),
            site_labels=tuple(names.get(site, site) for site in group.affected_site_ids),
            monitored_for=(end - start) if sessions else None,
        )

    async def _announce(self, group: AuditChangeGroup) -> None:
        if self._notifications is None or group.id is None:
            return
        if group.impact_severity is not ImpactSeverity.CRITICAL:
            return
        # The notification service deduplicates on the change group, so a
        # rebuild triggered by every later poll cannot re-alert.
        await self._notifications.notify_impact_detected(
            organization_id=group.organization_id,
            change_group_id=str(group.id),
            summary=group.summary or "A configuration change degraded the network.",
            severity=NotificationSeverity.CRITICAL,
        )


def _distinct_sessions(sessions: Sequence[MonitoringSession]) -> list[MonitoringSession]:
    """Drop repeated sessions and order them, so a replayed event changes nothing."""
    unique: dict[object, MonitoringSession] = {}
    for session in sessions:
        unique[session.id if session.id is not None else session.device_mac] = session
    return sorted(unique.values(), key=lambda session: (session.site_id, session.device_mac))


def _project_devices(sessions: Sequence[MonitoringSession]) -> list[AffectedDevice]:
    devices: dict[str, AffectedDevice] = {}
    for session in sessions:
        devices[session.device_mac] = AffectedDevice(
            device_mac=session.device_mac,
            device_name=session.device_name,
            device_type=session.device_type.value,
            site_mist_id=session.site_id,
        )
    return [devices[mac] for mac in sorted(devices)]


def _resolve_occurred_at(
    group: AuditChangeGroup,
    objects: Sequence[ChangedObjectRef],
    sessions: Sequence[MonitoringSession],
) -> datetime | None:
    if group.occurred_at is not None:
        return group.occurred_at
    candidates = [as_utc(session.created_at) for session in sessions]
    if objects and candidates:
        return min(candidates)
    return min(candidates, default=as_utc(group.created_at))


def _monitoring_window(
    group: AuditChangeGroup,
    sessions: Sequence[MonitoringSession],
) -> tuple[datetime, datetime]:
    started = [
        as_utc(session.config_applied_at or session.monitoring_started_at or session.created_at) for session in sessions
    ]
    ended = [as_utc(session.completed_at or session.monitoring_ends_at or session.updated_at) for session in sessions]
    default = as_utc(group.occurred_at or group.created_at)
    return min(started, default=default), max(ended, default=utc_now())


@dataclass(frozen=True, slots=True)
class ChangeGroupFilters:
    """Filters the Changes table and the Overview feed share."""

    range_key: str = _DEFAULT_RANGE
    severity: str = "any"
    actor: str | None = None
    query: str | None = None
    skip: int = 0
    limit: int = 100
    as_of: datetime | None = None


class ChangeGroupService:
    """Read model behind the change-group index and detail endpoints."""

    def __init__(self, store: ChangeGroupStore | None = None) -> None:
        self._store = store if store is not None else BeanieChangeGroupStore()

    async def list_groups(
        self,
        organization_id: PydanticObjectId,
        filters: ChangeGroupFilters,
        *,
        viewer_email: str,
    ) -> tuple[list[ChangeGroupSummaryResponse], int]:
        """Return one filtered page of change groups and the matching total."""
        criteria = build_criteria(organization_id, filters)
        total = await self._store.count(criteria)
        groups = await self._store.page(criteria, skip=filters.skip, limit=filters.limit)
        return await self.summarize(organization_id, groups, viewer_email=viewer_email), total

    async def summarize(
        self,
        organization_id: PydanticObjectId,
        groups: Sequence[AuditChangeGroup],
        *,
        viewer_email: str,
    ) -> list[ChangeGroupSummaryResponse]:
        """Render change groups as summaries, batching the lookups they share."""
        if not groups:
            return []
        session_ids = [session_id for group in groups for session_id in group.monitoring_session_ids]
        sessions = await self._store.sessions_by_id(organization_id, session_ids)
        by_session = {session.id: session for session in sessions if session.id is not None}
        site_ids = sorted({site for group in groups for site in group.affected_site_ids})
        names = await self._store.site_names(organization_id, site_ids)
        return [
            _summarize(
                group,
                [by_session[key] for key in group.monitoring_session_ids if key in by_session],
                names,
                viewer_email,
            )
            for group in groups
        ]

    async def get_group(
        self,
        organization_id: PydanticObjectId,
        group_id: PydanticObjectId,
        *,
        viewer_email: str,
    ) -> ChangeGroupDetailResponse | None:
        """Return one change group with its evidence and competing changes."""
        group = await self._store.group_by_id(organization_id, group_id)
        if group is None:
            return None
        sessions = await self._store.sessions_by_id(organization_id, group.monitoring_session_ids)
        names = await self._store.site_names(organization_id, group.affected_site_ids)
        start, end = _monitoring_window(group, sessions)
        competing = await self._store.groups_touching_sites(
            organization_id,
            group.affected_site_ids,
            start=start,
            end=end,
            exclude_audit_id=group.audit_id,
        )
        summary = _summarize(group, sessions, names, viewer_email)
        return ChangeGroupDetailResponse(
            **summary.model_dump(by_alias=True),
            message=group.message,
            method=group.method,
            baseline_confidence=group.baseline_confidence,
            deterministic_assessment=group.deterministic_assessment,
            evidence=[ChangeEvidenceResponse(label=item.label, severity=item.severity) for item in group.evidence],
            changed_objects=[
                ChangedObjectResponse(
                    logical_object_id=str(ref.logical_object_id),
                    object_type=ref.object_type,
                    object_name=ref.object_name,
                    scope=ref.scope,
                    site_mist_id=ref.site_mist_id,
                    event=ref.event,
                    before_version_id=str(ref.before_version_id) if ref.before_version_id else None,
                    after_version_id=str(ref.after_version_id) if ref.after_version_id else None,
                    before_version=ref.before_version,
                    after_version=ref.after_version,
                    changed_fields=list(ref.changed_fields),
                )
                for ref in group.changed_objects
            ],
            affected_devices=[
                AffectedDeviceResponse(
                    device_mac=device.device_mac,
                    device_name=device.device_name,
                    device_type=device.device_type,
                    site_mist_id=device.site_mist_id,
                )
                for device in group.affected_devices
            ],
            competing_change_group_ids=sorted(str(item.id) for item in competing if item.id is not None),
        )


def build_criteria(
    organization_id: PydanticObjectId,
    filters: ChangeGroupFilters,
) -> dict[str, object]:
    """Build the organization-scoped criteria document for a filtered query."""
    start, end = resolve_window(filters.range_key, filters.as_of)
    criteria: dict[str, object] = {
        "organization_id": organization_id,
        "occurred_at": {"$gte": start, "$lte": end},
    }
    if filters.severity == "critical":
        criteria["impact_severity"] = ImpactSeverity.CRITICAL.value
    elif filters.severity == "warning":
        criteria["impact_severity"] = ImpactSeverity.WARNING.value
    elif filters.severity == "none":
        criteria["impact_severity"] = {"$in": [ImpactSeverity.NONE.value, ImpactSeverity.INFO.value]}
    if filters.actor:
        criteria["actor"] = {"$regex": re.escape(filters.actor), "$options": "i"}
    if filters.query:
        pattern = re.escape(filters.query)
        criteria["$or"] = [
            {"audit_id": {"$regex": pattern, "$options": "i"}},
            {"actor": {"$regex": pattern, "$options": "i"}},
            {"summary": {"$regex": pattern, "$options": "i"}},
            {"changed_objects.object_name": {"$regex": pattern, "$options": "i"}},
        ]
    return criteria


def _summarize(
    group: AuditChangeGroup,
    sessions: Sequence[MonitoringSession],
    site_names: Mapping[str, str],
    viewer_email: str,
) -> ChangeGroupSummaryResponse:
    movements = measure_movements(sessions)
    incidents = [incident for session in sessions for incident in session.incidents]
    types = {session.device_type for session in sessions}
    evidence = GroupEvidenceInput(
        movements=movements,
        session_count=len(sessions),
        device_count=len(group.affected_devices),
        device_noun=_DEVICE_NOUNS[next(iter(types))][1] if len(types) == 1 else "devices",
        sample_count=sum(len(session.observations) for session in sessions),
        incident_count=len(incidents),
        unresolved_incidents=sum(1 for incident in incidents if not incident.resolved),
        competing_group_ids=(),
        site_labels=tuple(site_names.get(site, site) for site in group.affected_site_ids),
        monitored_for=None,
    )
    return ChangeGroupSummaryResponse(
        id=str(group.id),
        audit_id=group.audit_id,
        actor=group.actor,
        source=group.source,
        occurred_at=as_utc(group.occurred_at or group.created_at),
        title=build_title(group.changed_objects, group.message),
        summary=group.summary or "",
        object_count=len(group.changed_objects),
        device_count=len(group.affected_devices),
        affected_site_ids=list(group.affected_site_ids),
        devices_label=build_devices_label(group.affected_devices, site_names),
        impact_severity=group.impact_severity,
        recovery_state=group.recovery_state,
        impact_label=build_impact_label(group.impact_severity, group.recovery_state, movements),
        degraded_metrics=list(group.degraded_metrics),
        metrics=build_metrics(evidence, group.impact_severity, group.recovery_state),
        monitoring_session_ids=[str(session_id) for session_id in group.monitoring_session_ids],
        is_mine=actor_matches(group.actor, viewer_email),
    )
