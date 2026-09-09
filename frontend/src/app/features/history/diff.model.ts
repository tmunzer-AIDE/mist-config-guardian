import { Tone } from '../../core/tone';
import { ConfigurationEvent } from './history.model';

/** Change classification, uppercase exactly as the API emits it. */
export type DiffChangeKind = 'ADDED' | 'MODIFIED' | 'REMOVED';

/**
 * One changed configuration leaf.
 *
 * `before` and `after` are display strings the API already rendered and
 * redacted; the absent side of an addition or removal is null.
 */
export interface DiffEntry {
  field: string;
  kind: DiffChangeKind;
  before: string | null;
  after: string | null;
  /** Deterministic, server-computed explanation. Never model-generated. */
  note: string;
  /** Key of the section this entry belongs to. */
  section: string;
  /** True when the deterministic ranker considers this change high blast radius. */
  notable: boolean;
  /** True when the value was redacted before it left the server. */
  secret: boolean;
  /** True when a secret changed but the server could not compare the values. */
  secret_unknown: boolean;
  /** True when only list ordering changed, not membership. */
  reordered: boolean;
}

export interface DiffCounts {
  changed: number;
  added: number;
  modified: number;
  removed: number;
}

export interface DiffSection {
  key: string;
  name: string;
  /** The configuration path this section groups, e.g. `port_config{}`. */
  path: string;
  counts: DiffCounts;
  /** `3 added, 10 modified, 1 removed` — computed by the API. */
  detail: string;
  /** How many of this section's entries are notable. */
  notable: number;
  entries: DiffEntry[];
  /** False when the section was fetched without its entry bodies. */
  entries_included: boolean;
}

/** Identity of one side of a comparison. */
export interface DiffVersionRef {
  id: string;
  logical_object_id: string;
  version: number;
  event: ConfigurationEvent;
  observed_at: string;
  actor: string | null;
  is_deleted: boolean;
}

/**
 * How the comparison should be rendered. The API decides: at or below eight
 * changed fields the design shows compact change cards, above it the sectioned
 * view. The page never counts for itself.
 */
export type DiffMode = 'chips' | 'sections';

export interface ConfigurationDiff {
  mode: DiffMode;
  /** `3 fields changed · 0 added · 3 modified · 0 removed`. */
  summary: string;
  counts: DiffCounts;
  /** Populated in `chips` mode only, and only when entries were requested. */
  entries: DiffEntry[];
  /** Highest blast-radius entries, ranked by the API, capped at ten. */
  notable: DiffEntry[];
  sections: DiffSection[];
  entries_included: boolean;
  truncated: boolean;
  secret_fields: number;
  from_version: DiffVersionRef | null;
  to_version: DiffVersionRef | null;
}

/** Already-redacted side-by-side documents for the raw view. */
export interface RawConfigurationDiff {
  before: Record<string, unknown>;
  after: Record<string, unknown>;
  line_count: number;
  from_version: DiffVersionRef | null;
  to_version: DiffVersionRef | null;
}

export type DiffExportFormat = 'json' | 'patch';

/** How many entries a section shows before the "show more" control appears. */
export const SECTION_PAGE_SIZE = 6;

/** The absent side of an addition or removal, as the design renders it. */
export const ABSENT = '—';

/** Render one side of a change, mapping the API's null onto an em dash. */
export function diffValue(value: string | null): string {
  return value === null || value === '' ? ABSENT : value;
}

/** Tone for an ADDED / MODIFIED / REMOVED tag. */
export function entryTone(kind: DiffChangeKind): Tone {
  if (kind === 'ADDED') {
    return 'ok';
  }
  return kind === 'REMOVED' ? 'crit' : 'warn';
}

/** `14 changes · 3 added, 10 modified, 1 removed` — the section head line. */
export function sectionCountLabel(section: DiffSection): string {
  const changed = section.counts.changed;
  return `${changed} ${changed === 1 ? 'change' : 'changes'} · ${section.detail}`;
}

/**
 * Pretty-print a redacted document for the raw side-by-side view.
 *
 * Keys are sorted so the two columns line up the way the API counted them, and
 * so a re-ordered document does not read as a change.
 */
export function renderDocument(document: Record<string, unknown>): string[] {
  return JSON.stringify(sortValue(document), null, 2).split('\n');
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }
  if (value !== null && typeof value === 'object') {
    const source = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(source).sort()) {
      sorted[key] = sortValue(source[key]);
    }
    return sorted;
  }
  return value;
}
