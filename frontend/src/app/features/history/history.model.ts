export interface ConfigurationObject {
  id: string;
  scope: 'org' | 'site';
  object_type: string;
  current_mist_id: string;
  site_mist_id: string | null;
  name: string;
  is_deleted: boolean;
  current_version: number;
  updated_at: string;
}

export interface ConfigurationObjectList {
  items: ConfigurationObject[];
  total: number;
}

export interface ConfigurationVersion {
  id: string;
  version: number;
  event: 'initial' | 'created' | 'updated' | 'deleted' | 'restored';
  configuration: Record<string, unknown>;
  configuration_hash: string;
  changed_fields: string[];
  is_deleted: boolean;
  observed_at: string;
  actor: string | null;
  audit_id: string | null;
}

export interface ConfigurationVersionList {
  items: ConfigurationVersion[];
  total: number;
}
