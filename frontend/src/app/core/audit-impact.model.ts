export type ShadowResult = 'not_recorded' | 'pending' | 'unavailable' |
  'insufficient_evidence' | 'no_observed_disconnect' | 'possible_disruption';

export interface AuditImpactSummary {
  mode: 'shadow';
  assessment_source: 'audit_investigation';
  result: ShadowResult;
  investigation_id: string | null;
  report_id: string | null;
  revision: number | null;
  status: string | null;
  stop_reason: string;
  policy_version: string | null;
  evaluated_at: string | null;
  impact: 'info' | 'none' | 'warning' | 'critical' | null;
  confidence: 'low' | 'medium' | null;
  coverage: 'complete' | 'partial' | 'unmapped' | null;
  gap_count: number;
  unmapped_count: number;
}

export type ShadowFeedCounts = Record<ShadowResult, number> & {
  scope: 'returned_feed'; mode: 'shadow'; total: number;
};

export const SHADOW_LABELS: Record<ShadowResult, string> = {
  not_recorded: 'No investigation recorded',
  pending: 'Awaiting evidence',
  unavailable: 'Assessment unavailable',
  insufficient_evidence: 'Insufficient evidence',
  no_observed_disconnect: 'No observed disconnect',
  possible_disruption: 'Possible disruption',
};
