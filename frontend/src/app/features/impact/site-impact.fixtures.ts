import { DeviceImpact, SiteChange } from './site-impact.model';
export function impact(overrides: Partial<DeviceImpact> = {}): DeviceImpact {
  return {
    device_id: 'aabbccddeeff',
    device_name: 'Access switch',
    session_id: 's1',
    severity: 'unknown',
    config_state: 'pending',
    detected_at: '2026-09-09T10:00:00Z',
    snapshot_at: null,
    configured_at: null,
    monitoring_started_at: null,
    monitoring_ends_at: null,
    completed_at: null,
    monitoring_state: 'not_started',
    progress: 0,
    observation_count: 0,
    headline: 'Waiting for evidence',
    metrics: [],
    collection_errors: [],
    shared_window: false,
    ...overrides,
  };
}
export function change(overrides: Partial<SiteChange> = {}): SiteChange {
  return {
    id: 'c1',
    audit_id: 'a1',
    change_group_id: 'g1',
    occurred_at: '2026-09-09T10:00:00Z',
    actor: 'Admin',
    change_type: 'Switch template',
    title: 'PoE policy updated',
    summary: '',
    impacts: [impact()],
    ...overrides,
  };
}
