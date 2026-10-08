import { ChangeGroupDetail } from '../../core/change-group.model';
import { Tone } from '../../core/tone';
import { MonitoringSession, readAiAssessment } from '../impact/monitoring.model';
import { MetricEvidence } from '../impact/site-impact.model';

/** Incidents and operational findings do not imply a measured metric decline. */
export function measuredDegradation(metrics: MetricEvidence[]): boolean {
  return metrics.some((m) => comparableMetric(m) && m.delta! <= -10);
}

function comparableMetric(m: MetricEvidence): boolean {
  return (
    m.selected !== false &&
    m.comparable !== false &&
    !['no_data', 'missing', 'error'].includes(m.baseline_state ?? '') &&
    !['no_data', 'missing', 'error'].includes(m.latest_state ?? '') &&
    typeof m.delta === 'number' &&
    Number.isFinite(m.delta)
  );
}

export function interpretationNeedsReview(session: MonitoringSession): boolean {
  const ai = readAiAssessment(session.ai_assessment);
  if (!ai) return false;
  const ranks: Record<string, number> = { none: 0, info: 1, warning: 2, critical: 3 };
  if ((ranks[ai.severity?.toLowerCase() ?? ''] ?? -1) > ranks[session.impact_severity]) return true;
  const metrics = session.assessment?.metrics.filter(comparableMetric) ?? [];
  return (
    metrics.length > 0 &&
    metrics.every((m) => m.delta! >= 0) &&
    /gateway health|network metric|bandwidth|wan link/i.test(ai.explanation) &&
    /degrad/i.test(ai.explanation) &&
    !/\b(no|without)\s+(significant\s+)?degradation/i.test(ai.explanation)
  );
}

export function changeOutcome(detail: ChangeGroupDetail, sessions: MonitoringSession[]) {
  const impacts = detail.site_impacts?.flatMap((site) => site.devices) ?? [];
  const projectedMetrics = impacts.flatMap((device) => device.metrics);
  const metrics = projectedMetrics.length
    ? projectedMetrics
    : sessions.flatMap((s) => s.assessment?.metrics ?? []);
  const comparable = metrics.filter(comparableMetric);
  const incidents = sessions.flatMap((session) =>
    session.incidents.map((incident) => ({
      ...incident,
      device: session.device_name || session.device_mac,
      key: `${session.id}:${incident.event_type}:${incident.occurred_at}`,
    })),
  );
  const failures = incidents.filter((i) => i.event_type.endsWith('_CONFIG_FAILED'));
  const open = failures.filter((i) => !i.resolved);
  const recovered = failures.some((i) => i.resolved) && !open.length;
  const uncertain =
    detail.impact_known === false ||
    !!detail.missing_monitoring_sessions ||
    !comparable.length ||
    impacts.some((d) =>
      ['partial', 'insufficient'].includes(d.evidence_coverage ?? 'insufficient'),
    ) ||
    detail.site_impacts?.some((site) => site.unmonitored_devices.length > 0) ||
    (!impacts.length &&
      sessions.some((s) => !s.assessment || s.assessment.coverage !== 'complete'));
  const degraded = measuredDegradation(metrics);
  const remainingFinding = recovered && ['critical', 'warning'].includes(detail.impact_severity);
  const label =
    detail.impact_validation === 'excluded'
      ? 'Network validation not required'
      : detail.impact_known === false
        ? 'Historical configuration'
        : open.length
          ? 'Deployment failure needs review'
          : remainingFinding
            ? 'Recorded finding needs review'
            : recovered
              ? 'Deployment recovered'
              : detail.recovery_state === 'monitoring'
                ? 'Monitoring'
                : detail.impact_severity === 'critical'
                  ? 'Critical finding'
                  : detail.impact_severity === 'warning'
                    ? 'Review required'
                    : uncertain
                      ? 'Impact not established'
                      : 'No degradation measured';
  const headline =
    detail.impact_validation === 'excluded'
      ? 'Network validation not required for this change'
      : detail.impact_known === false
        ? 'Recorded outcome is not available at this past instant'
        : open.length
          ? 'Configuration failure remains open in the recorded evidence'
          : recovered
            ? `Configuration recovered; ${remainingFinding ? 'a recorded finding still needs review' : degraded ? 'service metrics degraded' : uncertain ? 'service evidence is incomplete' : 'no degradation measured'}`
            : degraded
              ? 'Measured network degradation needs review'
              : ['critical', 'warning'].includes(detail.impact_severity)
                ? 'A recorded finding needs review'
                : uncertain
                  ? 'Network impact has not been established'
                  : 'No degradation detected in comparable network metrics';
  const tone: Tone =
    detail.impact_known === false || detail.impact_validation === 'excluded'
      ? 'info'
      : open.length || detail.impact_severity === 'critical'
        ? 'crit'
        : degraded || detail.impact_severity === 'warning'
          ? 'warn'
          : uncertain
            ? 'info'
            : 'ok';
  const noTraffic = [
    ...new Set(
      metrics
        .filter((m) => m.baseline_state === 'no_data' || m.latest_state === 'no_data')
        .map((m) => m.name),
    ),
  ];
  return {
    label,
    headline,
    tone,
    incidents,
    failures,
    open,
    recovered,
    degraded,
    uncertain,
    comparable,
    noTraffic,
    deployment: open.length
      ? 'Failed · unresolved'
      : recovered
        ? 'Recovered after failure'
        : impacts.some((d) => d.config_state === 'rolled_back')
          ? 'Rolled back'
          : impacts.length && impacts.every((d) => d.config_state === 'applied')
            ? 'Applied'
            : 'Not established',
    service: degraded
      ? 'Measured degradation'
      : comparable.length
        ? 'No measured degradation'
        : 'Not established',
    experience: noTraffic.includes('application-health')
      ? 'Not measured · no application traffic'
      : comparable.some((m) => m.name === 'application-health')
        ? 'Application health measured'
        : 'User experience not established',
    coverage: uncertain ? 'Incomplete evidence' : 'Comparable metrics available',
    latestAt:
      [
        ...impacts.map((d) => d.completed_at),
        ...sessions.map((s) => s.completed_at ?? s.observations.at(-1)?.captured_at),
      ]
        .filter((at): at is string => !!at && Number.isFinite(Date.parse(at)))
        .sort((a, b) => Date.parse(a) - Date.parse(b))
        .at(-1) ?? null,
    attribution:
      detail.competing_change_group_ids.length > 0 || sessions.some((s) => s.audit_ids.length > 1),
    predates: incidents.some((i) => new Date(i.occurred_at) < new Date(detail.occurred_at)),
  };
}
