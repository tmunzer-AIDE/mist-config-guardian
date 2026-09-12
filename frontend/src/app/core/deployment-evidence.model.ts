/** Deployment evidence never implies outage, impact, or a complete expected device set. */
export interface DeploymentEvidence {
  schema_version: 1;
  collected_at: string;
  state: 'available' | 'partial' | 'unavailable';
  coverage: 'observed_receipts_only';
  expected_device_count: null;
  gaps: string[];
  devices: {
    device_mac: string;
    site_id: string;
    device_type: string;
    outcome: 'pending' | 'configured' | 'failed' | 'reverted' | 'unknown';
    correlation: 'audit_id' | 'session_candidate' | 'ambiguous';
    last_event_at: string | null;
    receipt_ids: string[];
  }[];
  observations: {
    receipt_id: string;
    received_at: string;
    correlation: string;
    signal: { event_type: string; outcome: string; device_mac: string | null;
      site_id: string | null; occurred_at: string | null; gaps: string[] };
  }[];
}
