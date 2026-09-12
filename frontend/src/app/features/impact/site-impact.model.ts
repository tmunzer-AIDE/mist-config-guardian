import { AuditImpactSummary } from '../../core/audit-impact.model';
export type Health = 'ok' | 'warning' | 'error' | 'critical' | 'unknown';
export type EvidenceState = 'measured' | 'no_data' | 'pending' | 'missing' | 'error' | 'unsupported' | 'disabled';
export interface MetricEvidence {
  name: string;
  baseline: number | null;
  latest: number | null;
  delta: number | null;
  baseline_state?: EvidenceState;
  latest_state?: EvidenceState;
  baseline_error?: string | null;
  latest_error?: string | null;
  comparable?: boolean;
  selected?: boolean;
}
export function evidenceValue(value: number | null, state?: EvidenceState): string {
  if (value !== null && value !== undefined && (!state || state === 'measured')) return `${value}%`;
  return ({ measured: 'Missing value', no_data: 'No sampled traffic', pending: 'Pending',
    missing: 'Missing evidence', error: 'Collection failed', unsupported: 'Unsupported',
    disabled: 'Disabled' })[state ?? 'missing'];
}
export interface ImpactSite {
  id: string;
  name: string;
}
export interface TopologyDevice {
  id: string;
  name: string;
  mac: string;
  kind: 'ap' | 'switch' | 'gateway' | 'unknown';
  model: string;
  ip: string | null;
  clients: number | null;
  parent: string | null;
  uplink: string | null;
  tier: number;
  health: Health;
  health_label: string;
  last_seen: string | null;
}
export interface TopologyLink {
  source: string;
  target: string;
  source_ports: string[];
  target_ports: string[];
}
export interface SiteTopology {
  site_id: string;
  devices: TopologyDevice[];
  links?: TopologyLink[];
  collected_at: string | null;
  source: 'mist' | 'stored' | 'historical';
  complete: boolean;
  warnings: string[];
}
export interface DeviceImpact {
  device_id: string;
  device_name: string;
  session_id: string;
  severity: Health;
  config_state: 'pending' | 'applied' | 'rolled_back' | 'unknown';
  detected_at: string | null;
  snapshot_at: string | null;
  configured_at: string | null;
  monitoring_started_at: string | null;
  monitoring_ends_at: string | null;
  completed_at: string | null;
  monitoring_state: 'not_started' | 'monitoring' | 'completed' | 'stalled' | 'aborted' | 'unknown';
  progress: number;
  observation_count: number;
  headline: string;
  shared_window: boolean;
  metrics: MetricEvidence[];
  evidence_coverage?: 'complete' | 'partial' | 'insufficient' | 'not_applicable';
  assessment_source?: 'stored' | 'legacy' | 'historical';
  collection_errors: string[];
}
export interface SiteChange {
  shadow_impact?: AuditImpactSummary | null;
  id: string;
  audit_id: string | null;
  change_group_id: string | null;
  occurred_at: string;
  actor: string | null;
  change_type: string;
  title: string;
  summary: string;
  impacts: DeviceImpact[];
}
export interface SiteChangeList {
  complete: boolean;
  warnings: string[];
  items: SiteChange[];
  total: number;
  as_of: string;
  historical: boolean;
}
export type ChangePhase = 'pending' | 'monitoring' | 'settled';
export function changePhase(change: SiteChange): ChangePhase {
  if (!change.impacts.length || change.impacts.some((i) => i.config_state === 'pending'))
    return 'pending';
  return change.impacts.some((i) => ['monitoring', 'stalled'].includes(i.monitoring_state))
    ? 'monitoring'
    : 'settled';
}
export function changeProgress(change: SiteChange): number {
  return change.impacts.length
    ? Math.round(change.impacts.reduce((sum, i) => sum + i.progress, 0) / change.impacts.length)
    : 0;
}
export function changeHealth(change: SiteChange): Health {
  return (
    (['critical', 'error', 'warning', 'unknown', 'ok'].find((tone) =>
      change.impacts.some((i) => i.severity === tone),
    ) as Health) ?? 'unknown'
  );
}
export function impactDevices(topology: TopologyDevice[], changes: SiteChange[]): TopologyDevice[] {
  const devices = new Map(topology.map((device) => [device.id, device]));
  for (const change of changes)
    for (const impact of change.impacts)
      if (!devices.has(impact.device_id)) {
        devices.set(impact.device_id, {
          id: impact.device_id,
          name: impact.device_name || impact.device_id,
          mac: impact.device_id,
          kind: 'unknown',
          model: '',
          ip: null,
          clients: null,
          parent: null,
          uplink: null,
          tier: 3,
          health: 'unknown',
          health_label: 'Not returned in topology',
          last_seen: null,
        });
      }
  return [...devices.values()];
}
export interface Viewport {
  zoom: number;
  x: number;
  y: number;
}
export function boundedView(
  view: Viewport,
  width: number,
  height: number,
  canvasWidth: number,
  canvasHeight: number,
): Viewport {
  const scaledWidth = canvasWidth * view.zoom,
    scaledHeight = canvasHeight * view.zoom;
  const bound = (offset: number, available: number, size: number) =>
    Math.min(
      Math.max(70, available - size + 70),
      Math.max(Math.min(-70, available - size - 70), offset),
    );
  return { ...view, x: bound(view.x, width, scaledWidth), y: bound(view.y, height, scaledHeight) };
}
export function zoomAt(view: Viewport, factor: number, x: number, y: number): Viewport {
  const zoom = Math.min(2.6, Math.max(0.3, view.zoom * factor));
  return {
    zoom,
    x: x - ((x - view.x) * zoom) / view.zoom,
    y: y - ((y - view.y) * zoom) / view.zoom,
  };
}
