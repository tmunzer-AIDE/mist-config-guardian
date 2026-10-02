"""Evidence projection shared by evaluation and legacy compatibility reads."""

from mist_config_guardian_backend.models.monitoring import (
    EvidenceCoverage,
    EvidenceState,
    ImpactAssessment,
    ImpactSeverity,
    MetricEvidence,
    RelevancePlan,
    SleObservation,
)

WARNING_THRESHOLD = 10.0
CRITICAL_THRESHOLD = 25.0


def metric_errors(observation: SleObservation | None) -> dict[str, str]:
    if observation is None:
        return {}
    # Older collectors used '<metric>: <error>'. Discovery/general errors have
    # no metric identity and must never become invented metric rows.
    errors = {}
    for error in observation.errors:
        name, separator, _detail = error.partition(": ")
        if separator and name != "metric discovery" and name and not any(c.isspace() for c in name):
            errors[name] = error
    return errors | observation.metric_errors


def _names(observation: SleObservation | None) -> set[str]:
    if observation is None:
        return set()
    return (
        set(observation.values)
        | set(observation.no_data)
        | set(observation.requested_metrics)
        | set(observation.metric_states)
        | set(metric_errors(observation))
    )


def _state(observation: SleObservation | None, name: str) -> EvidenceState:  # noqa: PLR0911 - explicit evidence states
    if observation is None:
        return "pending"
    if name in metric_errors(observation):
        return "error"
    if name in observation.no_data or observation.sample_counts.get(name) == 0:
        return "no_data"
    if observation.values.get(name) == 0 and observation.sample_counts.get(name, 0) <= 0:
        return "missing"
    if name in observation.metric_states:
        state = observation.metric_states[name]
        return "missing" if state == "measured" and name not in observation.values else state
    if name in observation.values:
        return "measured"
    # Discovery errors explain why planned metrics could not be collected,
    # but remain collection-level errors rather than fabricated metric errors.
    return "missing"


def same_scope(baseline: SleObservation | None, latest: SleObservation | None) -> bool:
    return bool(baseline and latest and baseline.scope == latest.scope and baseline.scope_id == latest.scope_id)


def evidence_rows(
    baseline: SleObservation | None, latest: SleObservation | None, plan: RelevancePlan
) -> list[MetricEvidence]:
    comparable_scope = same_scope(baseline, latest)
    rows = []
    for name in sorted(_names(baseline) | _names(latest) | set(plan.metrics)):
        before, after = _state(baseline, name), _state(latest, name)
        old = baseline.values.get(name) if baseline and before == "measured" else None
        new = latest.values.get(name) if latest and after == "measured" else None
        comparable = comparable_scope and old is not None and new is not None
        rows.append(
            MetricEvidence(
                name=name,
                baseline=old,
                latest=new,
                delta=round(new - old, 2) if comparable and new is not None and old is not None else None,
                baseline_state=before,
                latest_state=after,
                baseline_error=metric_errors(baseline).get(name),
                latest_error=metric_errors(latest).get(name),
                comparable=comparable,
                selected=plan.mode == "legacy_all" or name in plan.metrics,
            )
        )
    return rows


def collection_errors(baseline: SleObservation | None, latest: SleObservation | None) -> list[str]:
    return [
        f"{label}: {error}"
        for label, observation in (("Baseline", baseline), ("Latest", latest))
        if observation
        for error in dict.fromkeys([*observation.errors, *observation.metric_errors.values()])
    ]


def evidence_coverage(
    rows: list[MetricEvidence], baseline: SleObservation | None, latest: SleObservation | None, plan: RelevancePlan
) -> EvidenceCoverage:
    selected = [row for row in rows if row.selected]
    if not selected:
        return "not_applicable" if plan.mode == "selected" and not plan.metrics else "insufficient"
    if not same_scope(baseline, latest):
        return "insufficient"
    sampled = any(row.comparable for row in selected)
    failures = any(
        row.baseline_state not in {"measured", "no_data"} or row.latest_state not in {"measured", "no_data"}
        for row in selected
    )
    # Ignore failures for explicitly excluded metrics, but never general failures.
    for observation in (baseline, latest):
        if observation:
            known = metric_errors(observation)
            excluded = {error for name, error in known.items() if name not in plan.metrics}
            failures |= any(plan.mode == "legacy_all" or error not in excluded for error in observation.errors)
    if not sampled:
        return "insufficient"
    return "partial" if failures else "complete"


def legacy_assessment(  # noqa: PLR0913 - numeric and nonnumeric legacy evidence
    baseline: SleObservation | None,
    latest: SleObservation | None,
    severity: ImpactSeverity,
    summary: str | None,
    *,
    incident_types: tuple[str, ...] = (),
    device_findings: tuple[str, ...] = (),
) -> ImpactAssessment:
    """Single compatibility projection for documents predating stored results.

    Preserve supported alarms. An unverified zero cannot support a numeric
    alarm, and an incomplete comparison cannot establish a healthy result.
    """
    plan = RelevancePlan.legacy_all()
    rows = evidence_rows(baseline, latest, plan)
    coverage = evidence_coverage(rows, baseline, latest, plan)
    if severity == ImpactSeverity.NONE and (
        coverage != "complete" or any(row.delta is not None and row.delta <= -WARNING_THRESHOLD for row in rows)
    ):
        severity = ImpactSeverity.INFO
        summary = "Legacy assessment has insufficient comparable evidence for a healthy verdict."
    result = ImpactAssessment(
        severity=severity,
        summary=summary or "Waiting for comparable evidence",
        coverage=coverage,
        metrics=rows,
        collection_errors=collection_errors(baseline, latest),
        degraded_metrics=(),
        metric_deltas={row.name: row.delta for row in rows if row.delta is not None},
        incident_types=incident_types,
        device_findings=device_findings,
    )
    return validate_zero_evidence(result, baseline, latest, cached=False)


def has_unverified_zero(observation: SleObservation | None) -> bool:
    return bool(
        observation
        and any(
            value == 0 and observation.sample_counts.get(name, 0) <= 0 for name, value in observation.values.items()
        )
    )


def validate_zero_evidence(
    assessment: ImpactAssessment, baseline: SleObservation | None, latest: SleObservation | None, *, cached: bool = True
) -> ImpactAssessment:
    """Repair cached numeric verdicts without removing incident or device evidence."""
    if not (has_unverified_zero(baseline) or has_unverified_zero(latest)):
        return assessment
    if cached and not any(row.baseline == 0 or row.latest == 0 for row in assessment.metrics):
        return assessment
    rows = evidence_rows(baseline, latest, assessment.plan)
    deltas = {row.name: row.delta for row in rows if row.selected and row.delta is not None}
    coverage = evidence_coverage(rows, baseline, latest, assessment.plan)
    if assessment.incident_types or assessment.device_findings:
        severity = assessment.severity
    elif any(delta <= -CRITICAL_THRESHOLD for delta in deltas.values()):
        severity = ImpactSeverity.CRITICAL
    elif any(delta <= -WARNING_THRESHOLD for delta in deltas.values()):
        severity = ImpactSeverity.WARNING
    else:
        severity = ImpactSeverity.NONE if coverage == "complete" else ImpactSeverity.INFO
    return assessment.model_copy(
        update={
            "metrics": rows,
            "metric_deltas": deltas,
            "coverage": coverage,
            "severity": severity,
            "degraded_metrics": tuple(sorted(name for name, delta in deltas.items() if delta <= -WARNING_THRESHOLD)),
            "summary": "Zero SLE percentages without sampled-traffic evidence are unavailable. "
            + (
                "Other recorded evidence still shows degradation."
                if severity in {ImpactSeverity.CRITICAL, ImpactSeverity.WARNING}
                else "Network degradation is not established by those values."
            ),
        }
    )


def normalized_observation(observation: SleObservation) -> SleObservation:
    """Keep unverified zeroes out of numeric charts as well as delta calculations."""
    unavailable = {
        name: _state(observation, name) for name in observation.values if _state(observation, name) != "measured"
    }
    return observation.model_copy(
        update={
            "values": {name: value for name, value in observation.values.items() if name not in unavailable},
            "metric_states": observation.metric_states | unavailable,
            "trend": {
                name: series if name not in unavailable else [None for _ in series]
                for name, series in observation.trend.items()
            },
        }
    )
