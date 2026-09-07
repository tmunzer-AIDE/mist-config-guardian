export type MonitoringStatus = 'awaiting_config' | 'monitoring' | 'completed' | 'failed';
export type ImpactSeverity = 'none' | 'info' | 'warning' | 'critical';

export interface SleObservation {
  captured_at: string;
  values: Record<string, number>;
  errors: string[];
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
  site_id: string;
  device_mac: string;
  device_name: string;
  device_type: string;
  status: MonitoringStatus;
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
}

export interface MonitoringSessionList {
  items: MonitoringSession[];
  total: number;
}
