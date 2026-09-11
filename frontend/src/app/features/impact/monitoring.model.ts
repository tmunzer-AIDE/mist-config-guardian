import { BaselineConfidence } from '../../core/change-group.model';
import { Tone } from '../../core/tone';

export type MonitoringStatus = 'awaiting_config' | 'monitoring' | 'completed' | 'failed';
export type ImpactSeverity = 'none' | 'info' | 'warning' | 'critical';

/** Left-rail filter vocabulary: the four statuses plus the unfiltered default. */
export type StatusFilter = 'all' | MonitoringStatus;
/** Severity narrowing, carried on the deep link and forwarded to the API. */
export type SeverityFilter = 'any' | ImpactSeverity;

export interface SleObservation {
  no_data?: string[];
  scope?: 'site' | 'device';
  captured_at: string;
  window_start?: string | null;
  window_end?: string | null;
  values: Record<string, number>;
  errors: string[];
  /**
   * Per-bucket success rates spanning the whole window, `null` where a bucket
   * carried no sampled traffic. Bucket instants are not transmitted: every
   * metric shares the observation's window, so a series of `k` entries places
   * bucket `i` at `window_start + i * (window_end - window_start) / k`.
   * Absent on sessions stored before the anchored baseline landed.
   */
  trend?: Record<string, (number | null)[]>;
  /** Which part of the window `values` averages. Absent means the whole of it. */
  baseline_window?: 'last-hour' | 'full-window';
}

export interface MonitoringIncident {
  event_type: string;
  occurred_at: string;
  severity: ImpactSeverity;
  resolved: boolean;
  resolved_at: string | null;
}

export interface MonitoringSession {
  id: string;
  audit_ids: string[];
  change_groups?: { id: string; audit_id: string; title: string; occurred_at: string | null }[];
  timeline?: {
    key: string;
    event_type: string;
    occurred_at: string;
    received_at: string;
    audit_id: string | null;
  }[];
  peak_impact_severity?: ImpactSeverity;
  site_id: string;
  device_mac: string;
  device_name: string;
  device_type: string;
  status: MonitoringStatus;
  change_triggered_at?: string | null;
  device_comparisons?: DeviceStateComparison[];
  device_findings?: DeviceStateFinding[];
  baseline: SleObservation | null;
  observations: SleObservation[];
  incidents: MonitoringIncident[];
  config_applied_at: string | null;
  monitoring_started_at: string | null;
  monitoring_ends_at: string | null;
  impact_severity: ImpactSeverity;
  deterministic_summary: string | null;
  degraded_metrics: string[];
  ai_assessment: Record<string, unknown> | null;
  ai_assessment_error: string | null;
  warnings: string[];
  created_at: string;
  completed_at: string | null;
  /**
   * Added by the monitoring workstream. Absent on payloads produced before that
   * lands, so every reader treats a missing value as `'none'`.
   */
  baseline_confidence?: BaselineConfidence;
  /**
   * Added by the change-correlation workstream. Absent — or null — until a
   * session is correlated, which disables the change-group and restore links.
   */
  change_group_id?: string | null;
}

export interface MonitoringSessionList {
  items: MonitoringSession[];
  total: number;
}

/** One bar of the SLE series: a sample, and which side of the change it sits on. */
export interface SleBar {
  at: string;
  /** Success rate, 0..100, as the SLE client reports it. */
  value: number;
  preChange: boolean;
}

/** One row of the "Baseline versus latest" panel. */
export interface MetricDelta {
  key: string;
  label: string;
  baseline: number;
  latest: number;
  delta: number;
  deltaLabel: string;
  tone: Tone;
}

/** The parts of a provider's free-form assessment object the page renders. */
export interface AiAssessmentView {
  severity: string | null;
  confidence: string | null;
  explanation: string;
  recommendations: string[];
}

const STATUS_LABELS: Record<MonitoringStatus, string> = {
  awaiting_config: 'AWAITING CONFIG',
  monitoring: 'MONITORING',
  completed: 'COMPLETED',
  failed: 'FAILED',
};

const FILTER_LABELS: Record<StatusFilter, string> = {
  all: 'All',
  awaiting_config: 'Awaiting config',
  monitoring: 'Monitoring',
  completed: 'Completed',
  failed: 'Failed',
};

// The SLE client's metric keys, spelled the way the design renders them.
const METRIC_LABELS: Record<string, string> = {
  'failed-to-connect': 'Connection success',
  'ap-availability': 'AP availability',
  'switch-bandwidth': 'Switch bandwidth',
  'gateway-bandwidth': 'Gateway bandwidth',
  'application-health': 'Application health',
  'time-to-connect': 'Time to connect',
  'successful-connect': 'Successful connect',
  throughput: 'Throughput',
  roaming: 'Roaming',
  capacity: 'Capacity',
  coverage: 'Coverage',
  'ap-health': 'AP health',
  'switch-throughput': 'Switch throughput',
  'switch-health': 'Switch health',
  'switch-stc': 'Switch STC',
  'switch-stc-new': 'Switch STC (new)',
  'gateway-health': 'Gateway health',
  'wan-link-health': 'WAN link health',
};

// Mirrors the backend's classifier thresholds so the bar tone and the API's
// severity never disagree about the same delta.
const WARNING_DELTA = -10;
const CRITICAL_DELTA = -25;

export const STATUS_FILTERS: StatusFilter[] = [
  'all',
  'awaiting_config',
  'monitoring',
  'completed',
  'failed',
];

export function statusLabel(status: MonitoringStatus): string {
  return STATUS_LABELS[status];
}

export function filterLabel(filter: StatusFilter): string {
  return FILTER_LABELS[filter];
}

export function severityLabel(severity: ImpactSeverity): string {
  return severity.toUpperCase();
}

export function metricLabel(key: string): string {
  const known = METRIC_LABELS[key];
  if (known) {
    return known;
  }
  const words = key.replace(/[-_]/g, ' ');
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** Baseline confidence, defaulting to `none` while the field is not delivered. */
export function baselineConfidence(session: MonitoringSession): BaselineConfidence {
  return session.baseline_confidence ?? 'none';
}

/** True when the baseline is solid enough to call a quiet window "no impact". */
export function hasTrustedBaseline(session: MonitoringSession): boolean {
  const confidence = baselineConfidence(session);
  return confidence === 'high' || confidence === 'medium';
}

/**
 * Narrow a session list by status and severity.
 *
 * The API applies the same predicate server-side; doing it here as well keeps
 * the rendered list consistent when a cached page outlives its request.
 */
export function filterSessions(
  items: MonitoringSession[],
  status: StatusFilter,
  severity: SeverityFilter = 'any',
): MonitoringSession[] {
  return items.filter(
    (session) =>
      (status === 'all' || session.status === status) &&
      (severity === 'any' || session.impact_severity === severity),
  );
}

/** Total SLE readings behind the comparison — observations times metrics. */
export function sampleCount(session: MonitoringSession): number {
  return session.observations.reduce((total, item) => total + Object.keys(item.values).length, 0);
}

/** The metric the chart plots: the worst degraded one, else the largest mover. */
export function primaryMetric(session: MonitoringSession): string | null {
  const deltas = metricDeltas(session);
  const degraded = session.degraded_metrics.find((key) =>
    deltas.some((metric) => metric.key === key),
  );
  if (degraded) {
    return degraded;
  }
  if (deltas.length > 0) {
    return deltas[0].key;
  }
  const observed = session.observations.find((item) => Object.keys(item.values).length > 0);
  const fallback = observed ?? session.baseline;
  return fallback ? (Object.keys(fallback.values).sort()[0] ?? null) : null;
}

/**
 * Build the chart series for one metric.
 *
 * Place observations at the end of the measured window. The 24-hour baseline
 * is pre-change evidence even when fetched after a delayed webhook arrives.
 */
export function sleSeries(session: MonitoringSession, metric: string): SleBar[] {
  const appliedAt = session.config_applied_at ? Date.parse(session.config_applied_at) : null;
  const baseline = session.baseline;
  const observations = session.observations
    .filter((sample) => Object.hasOwn(sample.values, metric))
    .map((sample) => ({
      at: sample.window_end ?? sample.captured_at,
      value: sample.values[metric],
      preChange: appliedAt !== null && Date.parse(sample.window_end ?? sample.captured_at) < appliedAt,
    }));
  const before = baseline ? baselineBars(baseline, metric) : [];
  return [...before, ...observations].sort((left, right) => Date.parse(left.at) - Date.parse(right.at));
}

/**
 * The pre-change bars for one metric.
 *
 * Prefers the stored per-bucket trend so the chart shows the day leading up to
 * the change. Sessions recorded before the trend existed still carry a single
 * averaged value, and one bar is the honest way to draw one average.
 */
function baselineBars(baseline: SleObservation, metric: string): SleBar[] {
  const buckets = bucketInstants(baseline, baseline.trend?.[metric]);
  if (buckets.length > 0) {
    return buckets;
  }
  return Object.hasOwn(baseline.values, metric)
    ? [{ at: baseline.window_end ?? baseline.captured_at, value: baseline.values[metric], preChange: true }]
    : [];
}

/**
 * Place each sampled bucket at the instant it ends.
 *
 * Unsampled buckets are dropped rather than drawn at zero: a quiet bucket is
 * absence of evidence, and the rest of the page never invents a rate for one.
 */
function bucketInstants(baseline: SleObservation, series: (number | null)[] | undefined): SleBar[] {
  const start = baseline.window_start ? Date.parse(baseline.window_start) : NaN;
  const end = Date.parse(baseline.window_end ?? baseline.captured_at);
  if (!series || series.length === 0 || Number.isNaN(start) || Number.isNaN(end) || end <= start) {
    return [];
  }
  const bucket = (end - start) / series.length;
  return series.flatMap((value, index) =>
    value === null
      ? []
      : [{ at: new Date(start + bucket * (index + 1)).toISOString(), value, preChange: true }],
  );
}

/** Position of the "CHANGE APPLIED" marker as a 0..100 percentage of the plot. */
export function changeMarkerPercent(bars: SleBar[]): number | null {
  if (bars.length === 0 || !bars.some((bar) => bar.preChange)) {
    return null;
  }
  return (bars.filter((bar) => bar.preChange).length / bars.length) * 100;
}

/**
 * How the baseline figure was measured, for the label beside it.
 *
 * Worth stating rather than implying: a baseline that widened back to the whole
 * day because its final hour carried no traffic is a weaker comparison than one
 * anchored on the hour before the change, and the two must not read alike.
 */
export function baselineWindowLabel(session: MonitoringSession): string {
  return session.baseline?.baseline_window === 'last-hour' ? 'PRECEDING HOUR' : 'PRECEDING 24H';
}

/**
 * Five axis labels, read from the bars actually plotted.
 *
 * The bars are equal width, so slot `j` reads the bar `j/4` of the way along.
 * This used to hard-code the middle slot as the change instant, which only held
 * while the baseline was a single bar; with a day of buckets ahead of it the
 * change is rarely halfway, and the plot's own marker is the honest place to
 * name it.
 */
export function axisFor(bars: SleBar[], session: MonitoringSession): string[] {
  if (bars.length === 0) {
    return [];
  }
  const applied = session.config_applied_at
    ? Date.parse(session.config_applied_at)
    : Date.parse(bars[0].at);
  const live = session.status === 'monitoring' || session.status === 'awaiting_config';
  const slots = 5;
  return Array.from({ length: slots }, (_unused, slot) => {
    if (live && slot === slots - 1) {
      return 'NOW';
    }
    const index = Math.round((slot / (slots - 1)) * (bars.length - 1));
    return offsetLabel(Date.parse(bars[index].at) - applied);
  });
}

function offsetLabel(deltaMs: number): string {
  const minutes = Math.round(deltaMs / 60_000);
  const sign = minutes < 0 ? '−' : '+';
  const magnitude = Math.abs(minutes);
  return magnitude < 60 ? `${sign}${magnitude}M` : `${sign}${Math.round(magnitude / 60)}H`;
}

/** Baseline-versus-latest rows, worst mover first. */
export function metricDeltas(session: MonitoringSession): MetricDelta[] {
  const baseline = session.baseline;
  const latest = session.observations.at(-1) ?? null;
  if (!baseline || !latest || (baseline.scope ?? 'site') !== (latest.scope ?? 'site')) {
    return [];
  }
  return Object.keys(baseline.values)
    .filter((key) => Object.hasOwn(latest.values, key))
    .map((key) => {
      const before = baseline.values[key];
      const after = latest.values[key];
      const delta = Math.round((after - before) * 10) / 10;
      return {
        key,
        label: metricLabel(key),
        baseline: before,
        latest: after,
        delta,
        deltaLabel: deltaLabel(delta),
        tone: deltaTone(delta),
      };
    })
    .sort((left, right) => left.delta - right.delta);
}

/** `−29`, `+1`, `0` — the design's signed delta, with a real minus sign. */
export function deltaLabel(delta: number): string {
  const magnitude = Math.abs(Math.round(delta * 10) / 10);
  if (magnitude === 0) {
    return '0';
  }
  return `${delta < 0 ? '−' : '+'}${magnitude}`;
}

/** Tone for a delta, using the classifier's own warning/critical thresholds. */
export function deltaTone(delta: number): Tone {
  if (delta <= CRITICAL_DELTA) {
    return 'crit';
  }
  if (delta <= WARNING_DELTA) {
    return 'warn';
  }
  if (delta < 0) {
    return 'none';
  }
  return delta > 0 ? 'ok' : 'none';
}

/**
 * Read a provider's assessment object defensively.
 *
 * The field is `dict[str, object]` on the wire — whatever the configured model
 * returned — so nothing here may assume a key exists, and an object with no
 * readable prose is treated as no assessment at all.
 */
export function readAiAssessment(raw: Record<string, unknown> | null): AiAssessmentView | null {
  if (!raw) {
    return null;
  }
  const explanation =
    textOf(raw['explanation']) || textOf(raw['summary']) || textOf(raw['assessment']);
  const recommendations = listOf(raw['recommendations']);
  if (!explanation && recommendations.length === 0) {
    return null;
  }
  return {
    severity: textOf(raw['severity']) || null,
    confidence: textOf(raw['confidence']) || null,
    explanation,
    recommendations,
  };
}

/** `9F2A…C41` — the correlated audit ID, shortened for the meta strip. */
export function shortAudit(auditId: string): string {
  const compact = auditId.replace(/-/g, '').toUpperCase();
  return compact.length > 7 ? `${compact.slice(0, 4)}…${compact.slice(-3)}` : compact;
}

function textOf(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function listOf(value: unknown): string[] {
  if (typeof value === 'string') {
    const single = value.trim();
    return single ? [single] : [];
  }
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((item) => (typeof item === 'string' ? item.trim() : '')).filter(Boolean);
}

export interface DeviceStateObservation {
  captured_at: string;
  device: Record<string, unknown>;
  radios: Record<string, unknown>[];
  wlans: Record<string, unknown>[];
  clients: Record<string, unknown>[];
  ports: Record<string, unknown>[];
  bgp: Record<string, unknown>[];
  ospf: Record<string, unknown>[];
  tunnels: Record<string, unknown>[];
  vpn_peers: Record<string, unknown>[];
  available: string[];
  errors: Record<string, string>;
}
export interface DeviceStateFinding {
  kind: string;
  subject: string;
  before: string;
  after: string;
  severity: string;
  detail: string;
  affected_clients: number;
}

export interface DeviceStateComparison {
  triggered_at: string;
  baseline: DeviceStateObservation;
  due_at: string;
  followup: DeviceStateObservation | null;
  findings: DeviceStateFinding[];
  latest?: DeviceStateObservation | null;
  current_findings?: DeviceStateFinding[] | null;
  recovered_at?: string | null;
}
