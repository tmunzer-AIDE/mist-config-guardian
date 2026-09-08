/**
 * Change-group read model shared by Overview, Changes, Impact, and search.
 *
 * A change group is one Mist administrator action (`organization_id + audit_id`)
 * together with every object version it produced and every device it touched.
 */

export type ImpactSeverity = 'none' | 'info' | 'warning' | 'critical';
export type RecoveryState = 'not_applicable' | 'monitoring' | 'recovered' | 'unrecovered' | 'completed';
export type BaselineConfidence = 'high' | 'medium' | 'low' | 'none';
export type ChangeSource = 'webhook' | 'reconcile' | 'restore' | 'snapshot';

export interface ChangedObject {
  logical_object_id: string;
  object_type: string;
  object_name: string;
  scope: string;
  site_mist_id: string | null;
  event: string;
  before_version_id: string | null;
  after_version_id: string | null;
  before_version: number | null;
  after_version: number | null;
  changed_fields: string[];
}

export interface AffectedDevice {
  device_mac: string;
  device_name: string;
  device_type: string;
  site_mist_id: string;
}

export interface ChangeEvidence {
  label: string;
  severity: ImpactSeverity;
}

/** A metric tile rendered on an Overview feed card. */
export interface ChangeMetric {
  label: string;
  value: string;
  from: string;
  severity: ImpactSeverity;
}

export interface ChangeGroupSummary {
  id: string;
  audit_id: string;
  actor: string | null;
  source: ChangeSource;
  occurred_at: string;
  title: string;
  summary: string;
  object_count: number;
  device_count: number;
  affected_site_ids: string[];
  devices_label: string;
  impact_severity: ImpactSeverity;
  recovery_state: RecoveryState;
  impact_label: string;
  degraded_metrics: string[];
  metrics: ChangeMetric[];
  monitoring_session_ids: string[];
  /**
   * False when the summary was built for a past instant: impact and recovery
   * are current knowledge about a change, so a past view withholds them. The
   * neutral severity that comes with it means "not shown", not "no impact".
   */
  impact_known?: boolean;
  is_mine: boolean;
}

export interface ChangeGroupDetail extends ChangeGroupSummary {
  message: string | null;
  method: string | null;
  baseline_confidence: BaselineConfidence;
  deterministic_assessment: string | null;
  evidence: ChangeEvidence[];
  changed_objects: ChangedObject[];
  affected_devices: AffectedDevice[];
  competing_change_group_ids: string[];
}

export interface ChangeGroupPage {
  items: ChangeGroupSummary[];
  total: number;
}
