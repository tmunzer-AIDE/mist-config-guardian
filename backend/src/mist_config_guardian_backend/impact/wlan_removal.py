"""First sparse terminal rule: site WLAN removal/disablement.

The query proves observed WLAN usage and disconnects, not intent, causation or
failed joins. No aggregate infrastructure health can contribute to its verdict.
"""

from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timedelta
from hashlib import sha256
from uuid import UUID

from mist_config_guardian_backend.impact.change_context import compile_change_context
from mist_config_guardian_backend.impact.contracts import (
    SessionEvidence,
    Window,
    WlanAssessment,
    WlanFinding,
    WlanRemovalPlan,
    WlanTarget,
)
from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectVersion

_MAX_VERSIONS = 64
_MAX_TARGETS = 4
_MAX_UNMAPPED = 128


def compile_wlan_removal(  # noqa: C901, PLR0913 - explicit per-input fail-safe classification
    *,
    organization_id: str,
    audit_id: str,
    changed_at: datetime,
    logicals: Sequence[LogicalObject],
    before: Sequence[ObjectVersion],
    after: Sequence[ObjectVersion],
) -> WlanRemovalPlan:
    """Resolve known site WLAN identities; leave every other path visibly unmapped."""
    objects = {str(item.id): item for item in logicals if str(item.organization_id) == organization_id}
    priors = {
        (str(item.logical_object_id), item.version): item
        for item in before
        if str(item.organization_id) == organization_id
    }
    targets: dict[str, WlanTarget] = {}
    unmapped: set[str] = set()
    gaps: set[str] = set()
    if not after:
        gaps.add("No immutable configuration versions are available for this audit.")
    counts = Counter(str(item.logical_object_id) for item in after)
    if len(after) > _MAX_VERSIONS:
        gaps.add("Configuration version limit reached; remaining changes are unmapped.")
    for version in after[:_MAX_VERSIONS]:
        if counts[str(version.logical_object_id)] > 1:
            gaps.add(f"{version.logical_object_id}: multiple versions require net-change resolution.")
            continue
        if str(version.organization_id) != organization_id or version.audit_id != audit_id:
            gaps.add("Configuration version ownership does not match the investigation.")
            continue
        object_id = str(version.logical_object_id)
        logical = objects.get(object_id)
        prior = priors.get((object_id, version.version - 1))
        fields = version.changed_fields or ["*"]
        disabled = (
            prior is not None
            and prior.configuration.get("enabled") is not False
            and version.configuration.get("enabled") is False
        )
        if logical is None or logical.object_type not in {"wlan", "wlans"} or not (version.is_deleted or disabled):
            unmapped.update(f"{object_id}:{field}" for field in fields)
            continue
        if not version.is_deleted:
            unmapped.update(f"{object_id}:{field}" for field in fields if field.strip("/") != "enabled")
        if logical.scope != "site":
            unmapped.add(f"{object_id}:consumer-assignment")
            gaps.add("Organization WLAN consumer resolution is not implemented; assume the change is effective.")
            continue
        try:
            target = _resolve_wlan_target(logical, prior, version)
        except ValueError as exc:
            gaps.add(str(exc))
            continue
        targets[target.handle] = target
    if len(targets) > _MAX_TARGETS:
        gaps.add("WLAN target budget reached; remaining WLANs were not checked.")
    if len(unmapped) > _MAX_UNMAPPED:
        gaps.add("Unmapped path display limit reached.")
    return WlanRemovalPlan(
        organization_id=organization_id,
        audit_id=audit_id,
        changed_at=changed_at,
        change_context=compile_change_context(
            organization_id=organization_id, audit_id=audit_id, logicals=logicals, before=before, after=after
        ),
        targets=tuple(targets[key] for key in sorted(targets)[:_MAX_TARGETS]),
        unmapped=tuple(path[:512] for path in sorted(unmapped)[:_MAX_UNMAPPED]),
        gaps=tuple(sorted(gaps)),
    )


def _resolve_wlan_target(
    logical: LogicalObject,
    prior: ObjectVersion | None,
    version: ObjectVersion,
) -> WlanTarget:
    object_id = str(version.logical_object_id)
    if prior is None or prior.is_deleted or prior.id is None or version.id is None:
        msg = f"{object_id}: a valid immutable pre-change configuration is missing."
        raise ValueError(msg)
    if prior.incarnation_id != version.incarnation_id:
        msg = f"{object_id}: WLAN incarnation changed; effective identity needs resolution."
        raise ValueError(msg)
    try:
        site_id = UUID(logical.site_mist_id or "")
        wlan_id = UUID(str(prior.configuration.get("id", "")))
    except ValueError as exc:
        msg = f"{object_id}: the pre-change WLAN or site identity is missing."
        raise ValueError(msg) from exc
    identity = f"{version.organization_id}:{version.audit_id}:{prior.id}:{version.id}:{site_id}:{wlan_id}"
    return WlanTarget(
        handle=sha256(identity.encode()).hexdigest(),
        site_id=site_id,
        wlan_id=wlan_id,
        logical_object_id=object_id,
        before_version_id=str(prior.id),
        after_version_id=str(version.id),
        change_kind="removed" if version.is_deleted else "disabled",
    )


def check_windows(plan: WlanRemovalPlan, evidence_as_of: datetime) -> tuple[Window, Window]:
    """Audit-owned windows do not borrow a device session's first audit baseline."""
    return (
        Window(start=plan.changed_at - timedelta(hours=1), end=plan.changed_at),
        Window(start=plan.changed_at, end=evidence_as_of),
    )


def authorize_check(plan: WlanRemovalPlan, *, check_id: str, target_handle: str) -> WlanTarget:
    """Validate capability and opaque entity handle at the execution boundary."""
    if check_id == "wlan-client-sessions.v1":
        for target in plan.targets:
            if target.handle == target_handle:
                return target
    msg = "Check or target is not authorized by this investigation plan"
    raise ValueError(msg)


def evaluate_wlan_removal(
    plan: WlanRemovalPlan,
    evidence: Sequence[SessionEvidence],
    *,
    evidence_as_of: datetime,
) -> WlanAssessment:
    """Compose worst severity after deduplication; incomplete coverage stays visible."""
    baseline, followup = check_windows(plan, evidence_as_of)
    findings = []
    for target in plan.targets:
        readings = []
        for window in (baseline, followup):
            candidates = [item for item in evidence if item.target_handle == target.handle and item.window == window]
            # Never let a later failure be hidden by an older successful response.
            readings.append(max(candidates, key=lambda item: item.captured_at) if candidates else None)
        findings.append(_evaluate_target(target, readings, plan.changed_at))
    gaps = (*plan.gaps, *(f"Unmapped change: {path}" for path in plan.unmapped))
    complete = bool(findings) and not gaps and all(item.state != "unknown" for item in findings)
    impact = "warning" if any(item.impact == "warning" for item in findings) else "none" if complete else "info"
    return WlanAssessment(
        audit_id=plan.audit_id,
        evaluated_at=evidence_as_of,
        impact=impact,
        confidence="medium" if complete else "low",
        coverage="complete" if complete else "partial" if findings else "unmapped",
        findings=tuple(findings),
        gaps=gaps,
    )


def _evaluate_target(
    target: WlanTarget,
    readings: Sequence[SessionEvidence | None],
    changed_at: datetime,
) -> WlanFinding:
    baseline, followup = readings
    if baseline is None or followup is None or baseline.state != "complete" or followup.state != "complete":
        return WlanFinding(
            target_handle=target.handle,
            state="unknown",
            impact="info",
            confidence="low",
            explanation=(
                "Complete WLAN-scoped historical evidence is unavailable; absence of clients is not established."
            ),
        )
    clients = {row.client_mac for row in baseline.rows}
    disconnected = [
        row
        for row in followup.rows
        if row.connected_at < changed_at
        and row.disconnected_at is not None
        and changed_at <= row.disconnected_at <= followup.window.end
    ]
    affected = {row.client_mac for row in disconnected}
    return WlanFinding(
        target_handle=target.handle,
        state="possible_disruption" if affected else "no_observed_impact",
        impact="warning" if affected else "none",
        confidence="medium",
        baseline_clients=len(clients),
        disconnected_clients=len(affected),
        serving_ap_macs=tuple(sorted({row.ap_mac for row in disconnected})),
        explanation=(
            "Previously connected clients disconnected after this change. "
            "Ordinary disconnects or roaming remain possible; AP failure and causation are not established."
            if affected
            else "No disconnect of a previously connected client was observed in the scoped session evidence. "
            "Failed joins and unrecorded sessions are not covered."
        ),
    )
