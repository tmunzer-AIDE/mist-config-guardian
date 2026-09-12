"""Terminal domain evaluation with typed evidence eligibility and maximum composition."""

from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Literal

from mist_config_guardian_backend.impact.contracts import (
    DomainFinding,
    InvestigationEvidence,
    PortEvidence,
    PortHistoryEvidence,
    PortTarget,
    Window,
    WlanAssessment,
    WlanRemovalPlan,
)

_ORDER = {"none": 0, "info": 1, "warning": 2, "critical": 3}


def compose_domains(
    plan: WlanRemovalPlan, evidence: Sequence[InvestigationEvidence], base: WlanAssessment
) -> WlanAssessment:
    findings = []
    for target in plan.port_targets:
        history = next(
            (e for e in evidence if isinstance(e, PortHistoryEvidence) and e.target_handle == target.handle), None
        )
        snapshot = next((e for e in evidence if isinstance(e, PortEvidence) and e.target_handle == target.handle), None)
        findings.extend(
            _port_finding(plan, target, rule, history, snapshot, as_of=base.evaluated_at) for rule in target.domains
        )
    if not findings:
        return base
    impact = max([base.impact, *(f.impact for f in findings)], key=_ORDER.__getitem__)
    return WlanAssessment.model_validate(
        {
            **base.model_dump(),
            "policy_version": "impact-domains.v1",
            "domain_findings": findings,
            "impact": impact,
            "coverage": "partial",
            "confidence": "low",
        }
    )


def _port_finding(  # noqa: PLR0913 - target, evidence and assessment interval must agree
    plan: WlanRemovalPlan,
    target: PortTarget,
    rule: Literal["port-availability.v1", "switch-poe.v1"],
    history: PortHistoryEvidence | None,
    snapshot: PortEvidence | None,
    *,
    as_of: datetime,
) -> DomainFinding:
    unknown = DomainFinding(
        rule_id=rule,
        target_handle=target.handle,
        device_mac=target.device_mac,
        port_id=target.port_id,
        service="port_power" if rule == "switch-poe.v1" else "port_link",
        state="unknown",
        impact="info",
        current_impact="info",
        confidence="low",
        explanation="Comparable prior service and complete port event history are required.",
    )
    if (
        history is None
        or history.state != "complete"
        or history.window != Window(start=plan.changed_at - timedelta(hours=1), end=as_of)
    ):
        return unknown
    down = "SW_POE_PORT_DISABLED" if rule == "switch-poe.v1" else "SW_PORT_DOWN"
    up = "SW_POE_PORT_ENABLED" if rule == "switch-poe.v1" else "SW_PORT_UP"
    events = sorted((r for r in history.rows if r.event_type in {up, down}), key=lambda r: r.occurred_at)
    if any(not history.window.start <= r.occurred_at <= history.window.end for r in events):
        return unknown
    # Simultaneous contradictory observations cannot be ordered by enum or array position.
    if any(len({r.event_type for r in events if r.occurred_at == row.occurred_at}) > 1 for row in events):
        return unknown.model_copy(update={"explanation": "Contradictory same-time port events prevent state ordering."})
    losses = [r for r in events if r.event_type == down and plan.changed_at <= r.occurred_at <= history.window.end]
    if not losses:
        return unknown.model_copy(
            update={
                "explanation": "No scoped loss event was observed; absence of events does not establish service health."
            }
        )
    loss = losses[0]
    if rule == "switch-poe.v1":
        row = (
            snapshot.rows[0]
            if (
                snapshot
                and snapshot.state == "complete"
                and snapshot.rows
                and snapshot.window == Window(start=plan.changed_at, end=history.window.end)
            )
            else None
        )
        # An enabled event is administrative state, not proof that power was delivered.
        baseline = bool(
            row
            and row.observed_at
            and plan.changed_at - timedelta(minutes=5) <= row.observed_at < plan.changed_at
            and row.poe_on is True
            and row.power_draw is not None
            and row.power_draw > 0
        )
        recovered = None  # Enabling PoE alone never establishes restored delivery.
    else:
        earlier = [r for r in events if r.occurred_at < plan.changed_at]
        baseline = bool(earlier and earlier[-1].event_type == up)
        later = [r for r in events if r.occurred_at > loss.occurred_at]
        recovered = later[-1].occurred_at if later and later[-1].event_type == up else None
    if not baseline:
        return unknown.model_copy(
            update={
                "occurred_at": loss.occurred_at,
                "explanation": "A scoped disable/down event occurred, but prior active service is not established.",
            }
        )
    severity = "critical" if rule == "switch-poe.v1" else "warning"
    return DomainFinding(
        rule_id=rule,
        target_handle=target.handle,
        device_mac=target.device_mac,
        port_id=target.port_id,
        service="port_power" if rule == "switch-poe.v1" else "port_link",
        state="recovered" if recovered else "possible_disruption",
        impact=severity,
        current_impact="none" if recovered else severity,
        confidence="medium",
        attribution="plausible",
        occurred_at=loss.occurred_at,
        recovered_at=recovered,
        explanation=(
            "Previously powered port was disabled after the change; AP failure is not established."
            if rule == "switch-poe.v1"
            else "Previously active port went down after the change; alternate paths and causes remain unresolved."
        ),
    )
