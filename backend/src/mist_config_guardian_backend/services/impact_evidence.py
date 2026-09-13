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


def _state(observation: SleObservation | None, name: str) -> EvidenceState:
    if observation is None:
        return "pending"
    if name in metric_errors(observation):
        return "error"
    if name in observation.metric_states:
        state = observation.metric_states[name]
        return "missing" if state == "measured" and name not in observation.values else state
    if name in observation.values:
        return "measured"
    if name in observation.no_data:
        return "no_data"
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


def legacy_assessment(
    baseline: SleObservation | None,
    latest: SleObservation | None,
    severity: ImpactSeverity,
    summary: str | None,
) -> ImpactAssessment:
    """Single compatibility projection for documents predating stored results.

    Preserve historical alarms; only downgrade an unsubstantiated legacy clean
    result. This is deliberately not a fresh incident-free impact assessment.
    """
    plan = RelevancePlan.legacy_all()
    rows = evidence_rows(baseline, latest, plan)
    coverage = evidence_coverage(rows, baseline, latest, plan)
    if severity == ImpactSeverity.NONE and (
        coverage != "complete" or any(row.delta is not None and row.delta <= -WARNING_THRESHOLD for row in rows)
    ):
        severity = ImpactSeverity.INFO
        summary = "Legacy assessment has insufficient comparable evidence for a healthy verdict."
    return ImpactAssessment(
        severity=severity,
        summary=summary or "Waiting for comparable evidence",
        coverage=coverage,
        metrics=rows,
        collection_errors=collection_errors(baseline, latest),
        degraded_metrics=(),
        metric_deltas={row.name: row.delta for row in rows if row.delta is not None},
        incident_types=(),
    )
