export type MistCloudRegion =
  | 'global_01'
  | 'global_02'
  | 'global_03'
  | 'global_04'
  | 'global_05'
  | 'emea_01'
  | 'emea_02'
  | 'emea_03'
  | 'emea_04'
  | 'apac_01'
  | 'apac_02'
  | 'apac_03';
export type OrganizationStatus = 'pending' | 'verified' | 'error' | 'disabled';

export interface Organization {
  id: string;
  mist_org_id: string;
  name: string;
  cloud_region: MistCloudRegion;
  status: OrganizationStatus;
  service_token_set: boolean;
  service_token_last_four: string;
  credential_verified_at: string | null;
  credential_error: string | null;
  discovered_privileges: string[];
  webhook_secret_set: boolean;
  webhook_secret_last_four: string | null;
  webhook_secret_rotated_at: string | null;
  webhook_last_received_at: string | null;
  webhook_last_signature_valid: boolean | null;
  initial_snapshot_completed_at: string | null;
  reconciliation_cron: string;
  configuration_retention_days: number;
  monitoring_retention_days: number;
  created_at: string;
  updated_at: string;
}

export interface OrganizationList {
  items: Organization[];
  total: number;
}

export interface OrganizationCreate {
  cloud_region: MistCloudRegion;
  service_token: string;
  reconciliation_cron: string;
  configuration_retention_days: number;
  monitoring_retention_days: number;
}

export interface OrganizationUpdate {
  name?: string;
  reconciliation_cron?: string;
  configuration_retention_days?: number;
  monitoring_retention_days?: number;
}

export type SnapshotStatus = 'pending' | 'running' | 'completed' | 'partial' | 'failed';

export interface SnapshotManifest {
  id: string;
  kind: 'initial' | 'reconciliation' | 'manual';
  status: SnapshotStatus;
  started_at: string | null;
  completed_at: string | null;
  discovered_objects: number;
  created_versions: number;
  unchanged_objects: number;
  deleted_objects: number;
  errors: { object_type: string; scope_id: string | null; message: string }[];
  created_at: string;
}

export interface SnapshotManifestList {
  items: SnapshotManifest[];
  total: number;
}

export interface WebhookSecret {
  endpoint: string;
  secret: string;
}

/**
 * API host per Mist cloud region, mirroring `integrations/mist.REGION_HOSTS`
 * on the backend. Settings shows the host so an operator can confirm which
 * cloud a service token was issued against.
 */
export const MIST_REGION_HOSTS: Record<MistCloudRegion, string> = {
  global_01: 'api.mist.com',
  global_02: 'api.gc1.mist.com',
  global_03: 'api.ac2.mist.com',
  global_04: 'api.gc2.mist.com',
  global_05: 'api.gc4.mist.com',
  emea_01: 'api.eu.mist.com',
  emea_02: 'api.gc3.mist.com',
  emea_03: 'api.ac6.mist.com',
  emea_04: 'api.gc6.mist.com',
  apac_01: 'api.ac5.mist.com',
  apac_02: 'api.gc5.mist.com',
  apac_03: 'api.gc7.mist.com',
};

/** `Global 03 · api.ac2.mist.com` — the region line on an organization card. */
export function regionLabel(region: MistCloudRegion): string {
  const [area, index] = region.split('_');
  const name = area === 'global' ? 'Global' : area.toUpperCase();
  return `${name} ${index} · ${MIST_REGION_HOSTS[region]}`;
}

/** Every region, ordered as the onboarding form lists them. */
export const MIST_REGIONS: MistCloudRegion[] = Object.keys(MIST_REGION_HOSTS) as MistCloudRegion[];
