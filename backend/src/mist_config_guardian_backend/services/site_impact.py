"""Event-first, site-scoped Impact queries and evidence-safe presentation."""

from datetime import datetime, timedelta
from typing import Any, cast

from beanie import PydanticObjectId

from mist_config_guardian_backend.integrations.mist_topology import device_from_stats, normalized_mac
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.monitoring import (
    ImpactAssessment,
    ImpactSeverity,
    MonitoringSession,
    SleObservation,
)
from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectVersion
from mist_config_guardian_backend.models.webhook import AuditChangeGroup, ChangedObjectRef
from mist_config_guardian_backend.schemas.impact import (
    DeviceImpact,
    Health,
    ImpactMetric,
    ImpactSite,
    ImpactSiteList,
    SiteChange,
    SiteChangeList,
    SiteTopology,
)
from mist_config_guardian_backend.services.change_groups import as_utc, build_title, object_type_label
from mist_config_guardian_backend.services.impact_evidence import legacy_assessment

_MAX_SESSIONS = 5000


def change_page_pipeline(  # noqa: PLR0913, PLR0917 - explicit bounded query coordinates
    org: PydanticObjectId, site: str, start: datetime, end: datetime, skip: int, limit: int
) -> list[dict[str, Any]]:
    """Page configuration events before expanding their device windows."""
    return [
        {"$match": {"organization_id": org, "affected_site_ids": site, "created_at": {"$lte": end}}},
        {"$set": {"at": {"$ifNull": ["$occurred_at", "$created_at"]}}},
        {"$match": {"at": {"$gte": start, "$lte": end}}},
        {
            "$project": {
                "_id": {"$toString": "$_id"},
                "audit_id": 1,
                "actor": 1,
                "message": 1,
                "summary": 1,
                "changed_objects": 1,
                "at": 1,
                "change_type": {"$arrayElemAt": ["$changed_objects.object_type", 0]},
                "scope": {"$arrayElemAt": ["$changed_objects.scope", 0]},
            }
        },
        {
            "$unionWith": {
                "coll": "monitoring_sessions",
                "pipeline": [
                    {
                        "$match": {
                            "organization_id": org,
                            "site_id": site,
                            "audit_ids": {"$size": 0},
                            "created_at": {"$gte": start, "$lte": end},
                        }
                    },
                    {
                        "$project": {
                            "_id": {"$concat": ["session:", {"$toString": "$_id"}]},
                            "at": "$created_at",
                            "message": {"$concat": ["Uncorrelated change · ", "$device_name"]},
                        }
                    },
                ],
            }
        },
        {
            "$facet": {
                "items": [{"$sort": {"at": -1, "_id": 1}}, {"$skip": skip}, {"$limit": limit}],
                "count": [{"$count": "total"}],
            }
        },
    ]


def session_projection(end: datetime) -> dict[str, Any]:
    """No raw telemetry/configuration arrays in the event index response."""
    return {
        "$project": {
            "device_mac": 1,
            "device_name": 1,
            "audit_ids": 1,
            "status": 1,
            "baseline": 1,
            "impact_severity": 1,
            "assessment": 1,
            "deterministic_summary": 1,
            "change_triggered_at": 1,
            "config_applied_at": 1,
            "monitoring_started_at": 1,
            "monitoring_ends_at": 1,
            "completed_at": 1,
            "timeline": {
                "$filter": {
                    "input": {"$ifNull": ["$timeline", []]},
                    "as": "event",
                    "cond": {"$lte": ["$$event.received_at", end]},
                }
            },
            "observations": {
                "$filter": {"input": "$observations", "as": "sample", "cond": {"$lte": ["$$sample.captured_at", end]}}
            },
            "snapshot_times": "$device_comparisons.baseline.captured_at",
        }
    }


def impact_from_session(row: dict[str, Any], end: datetime, *, historical: bool) -> DeviceImpact:
    def at(key: str) -> datetime | None:
        value = row.get(key)
        return as_utc(value) if isinstance(value, datetime) and as_utc(value) <= end else None

    observations = [sample for sample in row.get("observations", []) if as_utc(sample["captured_at"]) <= end]
    baseline = row.get("baseline") or {}
    if baseline.get("captured_at") and as_utc(baseline["captured_at"]) > end:
        baseline = {}
    latest = observations[-1] if observations else {}
    stored = ImpactAssessment.model_validate(row["assessment"]) if row.get("assessment") else None
    if stored and (historical or as_utc(stored.evaluated_at) > end):
        stored = None
    assessment = (
        stored
        if stored is not None
        else legacy_assessment(
            SleObservation.model_validate(baseline) if baseline else None,
            SleObservation.model_validate(latest) if latest else None,
            ImpactSeverity(row.get("impact_severity", "info")),
            row.get("deterministic_summary"),
        )
    )
    metrics = [ImpactMetric.model_validate(metric, from_attributes=True) for metric in assessment.metrics]
    errors = assessment.collection_errors
    measured = any(metric.comparable and metric.selected for metric in metrics)
    configured, started, completed = at("config_applied_at"), at("monitoring_started_at"), at("completed_at")
    ends = row.get("monitoring_ends_at")
    ends = as_utc(ends) if isinstance(ends, datetime) else None
    rolled_back = any(
        event["event_type"].endswith("_CONFIG_REVERTED") and as_utc(event["received_at"]) <= end
        for event in row.get("timeline", [])
    )
    config = "rolled_back" if rolled_back else "applied" if configured else "pending"
    state = "not_started"
    if started:
        state = (
            "completed"
            if completed and measured and not errors and row.get("status") != "failed"
            else "aborted"
            if completed
            else "stalled"
            if not measured or errors
            else "monitoring"
        )
    elif completed:
        state = "aborted"
    percentage = 0
    if started and ends and ends > started:
        percentage = min(
            100, max(0, round(((completed or end) - started).total_seconds() / (ends - started).total_seconds() * 100))
        )
    severity = {"none": "ok", "info": "unknown", "warning": "warning", "critical": "critical"}.get(
        assessment.severity, "unknown"
    )
    # Lifecycle failure stays filterable without hiding a critical impact verdict.
    if row.get("status") == "failed" and severity != "critical":
        severity = "error"
    headline = assessment.summary
    if historical:
        severity, headline = "unknown", "Historical lifecycle evidence; the verdict at this instant was not retained."
    snapshots = [
        as_utc(value) for value in row.get("snapshot_times", []) if isinstance(value, datetime) and as_utc(value) <= end
    ]
    return DeviceImpact(
        device_id=normalized_mac(row["device_mac"]),
        device_name=row.get("device_name") or row["device_mac"],
        session_id=str(row["_id"]),
        severity=cast("Health", severity),
        config_state=config,
        detected_at=at("change_triggered_at"),
        snapshot_at=min(snapshots) if snapshots else None,
        configured_at=configured,
        monitoring_started_at=started,
        monitoring_ends_at=ends,
        completed_at=completed,
        monitoring_state=state,
        progress=percentage,
        observation_count=len(observations),
        headline=headline,
        metrics=[] if historical else metrics,
        evidence_coverage="insufficient" if historical else assessment.coverage,
        assessment_source="historical" if historical else "stored" if stored else "legacy",
        collection_errors=errors,
        shared_window=len(row.get("audit_ids", [])) > 1,
    )


async def list_sites(org: PydanticObjectId, end: datetime) -> ImpactSiteList:
    objects = (
        await LogicalObject.find({"organization_id": org, "object_type": "sites", "created_at": {"$lte": end}})
        .sort("name", "_id")
        .limit(5000)
        .to_list()
    )
    sites = {obj.current_mist_id: ImpactSite(id=obj.current_mist_id, name=obj.name) for obj in objects}
    rows = await MonitoringSession.aggregate(
        [
            {"$match": {"organization_id": org, "created_at": {"$lte": end}}},
            {"$group": {"_id": "$site_id"}},
            {"$limit": 5000},
        ]
    ).to_list()
    for row in rows:
        sites.setdefault(row["_id"], ImpactSite(id=row["_id"], name=row["_id"]))
    ordered = sorted(sites.values(), key=lambda item: (item.name.casefold(), item.id))
    return ImpactSiteList(items=ordered)


async def stored_topology(org: PydanticObjectId, site: str, end: datetime, *, historical: bool) -> SiteTopology:
    objects = (
        await LogicalObject.find(
            {"organization_id": org, "site_mist_id": site, "object_type": "devices", "created_at": {"$lte": end}}
        )
        .limit(5000)
        .to_list()
    )
    rows = (
        await ObjectVersion.aggregate(
            [
                {
                    "$match": {
                        "organization_id": org,
                        "logical_object_id": {"$in": [obj.id for obj in objects]},
                        "observed_at": {"$lte": end},
                    }
                },
                {"$sort": {"observed_at": -1, "version": -1}},
                {"$group": {"_id": "$logical_object_id", "latest": {"$first": "$$ROOT"}}},
                {"$match": {"latest.is_deleted": False}},
                {
                    "$project": {
                        "config": {
                            "mac": "$latest.configuration.mac",
                            "name": "$latest.configuration.name",
                            "type": "$latest.configuration.type",
                            "model": "$latest.configuration.model",
                        }
                    }
                },
            ]
        ).to_list()
        if objects
        else []
    )
    devices = []
    for row in rows:
        device = device_from_stats(row["config"])
        if device is not None:
            device.health_label = "Stored inventory · health unavailable"
            devices.append(device)
    devices.sort(key=lambda device: (device.tier, device.name.casefold(), device.id))
    return SiteTopology(
        site_id=site,
        devices=devices,
        source="historical" if historical else "stored",
        warnings=["Stored inventory has no observed physical links or live health."],
    )


async def list_changes(  # noqa: PLR0913 - explicit bounded query coordinates
    org: PydanticObjectId, site: str, *, range_key: str, end: datetime | None, skip: int, limit: int
) -> SiteChangeList:
    historical = end is not None
    end = as_utc(end) if end else utc_now()
    start = end - timedelta(days={"24h": 1, "7d": 7, "30d": 30}[range_key])
    result = await AuditChangeGroup.aggregate(change_page_pipeline(org, site, start, end, skip, limit)).to_list()
    page = result[0] if result else {"items": [], "count": []}
    items = page["items"]
    audits = [row["audit_id"] for row in items if row.get("audit_id")]
    orphan_ids = [
        PydanticObjectId(row["_id"].removeprefix("session:")) for row in items if row["_id"].startswith("session:")
    ]
    sessions = (
        await MonitoringSession.aggregate(
            [
                {
                    "$match": {
                        "organization_id": org,
                        "site_id": site,
                        "created_at": {"$lte": end},
                        "$or": [{"audit_ids": {"$in": audits}}, {"_id": {"$in": orphan_ids}}],
                    }
                },
                {"$sort": {"created_at": -1, "_id": 1}},
                {"$limit": _MAX_SESSIONS + 1},
                session_projection(end),
            ]
        ).to_list()
        if items
        else []
    )
    complete = len(sessions) <= _MAX_SESSIONS
    sessions = sessions[:_MAX_SESSIONS]
    changes = []
    for row in items:
        relevant = [
            session
            for session in sessions
            if row.get("audit_id") in session.get("audit_ids", []) or row["_id"] == f"session:{session['_id']}"
        ]
        if historical:
            relevant = [
                session
                for session in relevant
                if any(
                    event.get("audit_id") == row.get("audit_id") and as_utc(event["received_at"]) <= end
                    for event in session.get("timeline", [])
                )
                or row["_id"].startswith("session:")
            ]
        # A device may have more than one window for one audit; present its latest.
        relevant = list({normalized_mac(session["device_mac"]): session for session in reversed(relevant)}.values())
        changes.append(
            SiteChange(
                id=row["_id"],
                audit_id=row.get("audit_id"),
                change_group_id=row["_id"] if row.get("audit_id") else None,
                occurred_at=row["at"],
                actor=row.get("actor"),
                change_type=object_type_label(row["change_type"], row.get("scope") or "org")
                if row.get("change_type")
                else "Configuration change",
                title=build_title(
                    []
                    if historical
                    else [ChangedObjectRef.model_validate(obj) for obj in row.get("changed_objects", [])],
                    row.get("message"),
                ),
                summary="" if historical else row.get("summary") or "",
                impacts=[impact_from_session(session, end, historical=historical) for session in relevant],
            )
        )
    return SiteChangeList(
        complete=complete,
        warnings=[]
        if complete
        else [
            (
                "Device summaries reached the 5000-window limit. "
                "Narrow the time range or open a change group for its full evidence."
            )
        ],
        items=changes,
        total=page["count"][0]["total"] if page["count"] else 0,
        as_of=end,
        historical=historical,
    )
