export type ImpactBand = 'none' | 'info' | 'warning' | 'critical';
export interface ReportDeviceImpact {
  device_mac: string; site_id: string;
  role: 'affected_switch_port' | 'serving_affected_clients';
  service: 'port_link' | 'port_power' | 'wlan_sessions' | 'wlan_authentication';
  target_handle: string; port_id: string | null;
  impact: ImpactBand; current_impact: ImpactBand; confidence: 'low' | 'medium';
  attribution: 'plausible'; device_failure: 'not_established';
}
export interface EvidenceDataset {
  id: string; check_id: string; target_handle: string;
  window: { start: string; end: string }; captured_at: string; state: string;
  title: string; kind: 'table' | 'bar' | 'histogram' | 'timeline';
  columns: string[]; rows: (string | number | null)[][];
  omitted_rows: number; explanation: string;
}
export interface ImpactReport {
  schema_version: 1; investigation_id: string; audit_id: string; revision: number;
  generated_at: string; evidence_as_of: string;
  peak_impact: ImpactBand; peak_revision: number; peak_confidence: 'low' | 'medium';
  current_impact: ImpactBand; confidence: 'low' | 'medium';
  history_complete: boolean; coverage: string; attribution: string;
  sections: Record<'summary' | 'change' | 'scope' | 'findings' | 'evidence' | 'timeline' | 'context' | 'gaps_and_next_checks',
    { state: 'available' | 'partial' | 'unavailable'; explanation: string }>;
  datasets: EvidenceDataset[]; impacted_devices: ReportDeviceImpact[];
  omitted_device_impacts: number; device_coverage: 'observed_only'; gaps: string[];
}
export interface ReportHistory {
  investigation_id: string; published_revision: number; complete: boolean;
  reports: ImpactReport[]; gaps: string[];
}
