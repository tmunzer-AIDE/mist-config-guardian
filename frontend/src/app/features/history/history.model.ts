import { Tone } from '../../core/tone';

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

export type ConfigurationEvent = 'initial' | 'created' | 'updated' | 'deleted' | 'restored';

export interface ConfigurationVersion {
  id: string;
  version: number;
  event: ConfigurationEvent;
  configuration: Record<string, unknown>;
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

/** Query shape for the paged object list. Every field is optional. */
export interface ObjectQuery {
  objectType?: string;
  siteId?: string;
  includeDeleted?: boolean;
  skip?: number;
  limit?: number;
}

/**
 * Rail grouping label, in the prototype's `OBJECT_GROUPS` vocabulary
 * (`ORG SCOPE · WLAN`, `SITE · SEATTLE-DC`).
 *
 * The objects endpoint carries a site's Mist id but not its name, so a
 * site-scoped group is labelled by the shortened id until the API exposes one.
 */
export function objectGroupLabel(object: ConfigurationObject): string {
  if (object.scope === 'site') {
    return `SITE · ${shortMistId(object.site_mist_id ?? 'unassigned')}`;
  }
  return `ORG SCOPE · ${object.object_type.toUpperCase()}`;
}

/** `WLAN · ORG SCOPE` — the type/scope meta line in the comparison header. */
export function objectKindLabel(object: ConfigurationObject): string {
  const scope = object.scope === 'site' ? `SITE ${shortMistId(object.site_mist_id ?? 'unassigned')}` : 'ORG SCOPE';
  return `${object.object_type.toUpperCase()} · ${scope}`;
}

/** `4d0e…7b2` — the elided Mist identifier the design shows beside a name. */
export function shortMistId(value: string): string {
  const compact = value.replace(/-/g, '');
  return compact.length > 7 ? `${compact.slice(0, 4)}…${compact.slice(-3)}` : compact;
}

/** Tone for a version's event badge, matching the prototype's mapping. */
export function eventTone(event: ConfigurationEvent): Tone {
  if (event === 'restored') {
    return 'ok';
  }
  return event === 'initial' ? 'none' : 'warn';
}
