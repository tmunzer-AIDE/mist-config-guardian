/**
 * Guardian read model: one audit's investigation, and the vocabulary for saying
 * honestly what it does and does not know.
 *
 * Four answers are deliberately distinct here, because conflating any two of
 * them would describe a change falsely:
 *
 * - **not recorded** — no investigation exists for the audit (`guardian` is
 *   `null`). Nothing was concluded, so nothing is claimed.
 * - **unavailable** — a projection that could not be read. It is not "clean".
 * - **pending** — an investigation is still running and has published nothing.
 * - **a published result** — which is itself either an *early* result, taken
 *   while the investigation could still continue, or a *final* one.
 *
 * Every string a provider or a model produced (device and object names, the
 * agent's summary, findings and gaps) is rendered as text by the components
 * that consume this model, never as markup.
 */

/** Severity bands, in the backend's order `none < info < warning < critical`. */
export type Band = 'none' | 'info' | 'warning' | 'critical';
export type Recovery = 'none' | 'recovered' | 'unrecovered';
export type Confidence = 'low' | 'medium';
export type Coverage = 'complete' | 'partial' | 'insufficient' | 'not_applicable';
export type RunKind = 'early' | 'final';
export type RunState = 'running' | 'succeeded' | 'failed' | 'abandoned';
export type RootStatus = 'waiting' | 'done';
/** Whether the summary could be read at all; `unavailable` carries nothing else. */
export type GuardianAvailability = 'projected' | 'unavailable';

export interface CompactImpactedDevice {
  mac: string;
  site_id: string;
  name: string;
  peak: Band;
  current: Band;
}

/** The root's published summary of one succeeded run. `summary` is composed deterministically, not written by the agent. */
export interface GuardianResult {
  run_id: string;
  run_kind: RunKind;
  evaluated_at: string;
  peak: Band;
  current: Band;
  recovery: Recovery;
  confidence: Confidence;
  coverage: Coverage;
  sources: string[];
  impacted_devices: CompactImpactedDevice[];
  impacted_device_count: number;
  summary: string;
}

/**
 * A published run's own impacted-device rows and how many it never recorded.
 *
 * On a site page `devices` is already filtered to that site by the server.
 * `omitted` counts devices whose identity — and therefore whose site — the run
 * never recorded, so it is never presented as belonging to the selected site.
 */
export interface GuardianImpactedDevices {
  devices: CompactImpactedDevice[];
  omitted: number;
}

export interface GuardianSummary {
  availability: GuardianAvailability;
  status: RootStatus | null;
  status_reason: string | null;
  result: GuardianResult | null;
  impacted?: GuardianImpactedDevices | null;
}

/** One bucket per returned feed row: no root, an unreadable projection, a pending root, or the published peak. */
export interface GuardianFeedCounts {
  scope: 'returned_feed';
  total: number;
  not_recorded: number;
  unavailable: number;
  pending: number;
  none: number;
  info: number;
  warning: number;
  critical: number;
}

// The rendered report ------------------------------------------------------

/** One report section: the rows it shows, the count it left out, and, when it shows none, why. */
export interface ReportSection<T> {
  items: T[];
  omitted: number;
  explanation: string | null;
}

export interface RunBudget {
  model_turns: number;
  mcp_calls: number;
  rule_reads: number;
}

export interface RunAnchor {
  changed_at: string;
  source: 'audit' | 'device_trigger' | 'receipt';
}

export interface ReportRun {
  kind: RunKind;
  attempt: number;
  state: RunState;
  failure_reason: string | null;
  started_at: string;
  finished_at: string | null;
  anchor: RunAnchor | null;
  as_of: string | null;
  budget: RunBudget;
}

export interface ReportHeader {
  peak: Band;
  current: Band;
  recovery: Recovery;
  confidence: Confidence;
  coverage: Coverage;
  sources: string[];
}

/** The deterministic sentence, and the agent's own words — which the panel always labels as AI. */
export interface ReportSummary {
  deterministic: string;
  ai: string | null;
  ai_note: string | null;
}

export interface ChangeAtom {
  id: string;
  logical_object_id: string;
  version: number;
  attribute: string;
  paths: string[][];
  paths_complete: boolean;
}

export interface Target {
  device_mac: string | null;
  site_id: string | null;
  port_id: string | null;
  wlan_id: string | null;
}

export interface LedgerRow {
  atom_id: string;
  target: Target;
  resolution: 'claimed' | 'excluded' | 'uncovered';
  obligation_ids: string[];
  uncovered_paths: string[][];
}

/** `change_ref` is null for the core `input` kind: an input the attempt could not see in full names no atom. */
export interface Obligation {
  id: string;
  owner: string;
  change_ref: string | null;
  paths: string[][];
  role: 'precondition' | 'observation';
  kind: 'anchor' | 'deployment' | 'monitoring' | 'rule' | 'input';
  target: Target;
  metric: string | null;
  empty_policy: 'not_exercised' | 'incomplete' | null;
}

export interface ObligationStatus {
  status: 'satisfied' | 'not_exercised' | 'unsatisfied';
  reason: string | null;
  evidence_ids: string[];
}

export interface ObligationOutcome {
  obligation: Obligation;
  status: ObligationStatus;
}

export interface CoverageSection {
  coverage: Coverage | null;
  rows: ReportSection<LedgerRow>;
  obligations: ReportSection<ObligationOutcome>;
}

export interface ComponentSeverity {
  peak: Band;
  current: Band;
}

export interface DeviceMonitoring {
  mac: string;
  site_id: string | null;
  name: string;
  session_id: string | null;
  exclusive: boolean | null;
  terminal: boolean | null;
  status: 'satisfied' | 'not_exercised' | 'unsatisfied' | 'no_checks';
  metrics: ComponentSeverity | null;
  incidents: ComponentSeverity | null;
  device_state: ComponentSeverity | null;
  peak: Band | null;
  current: Band | null;
  deployment: 'unknown' | 'configured' | 'failed' | 'reverted' | 'ambiguous' | null;
  deployment_precondition: 'satisfied' | 'unsatisfied' | null;
}

export interface FindingRow {
  source: string;
  text: string;
  severity: Band;
  evidence_ids: string[];
}

export interface EvidenceRow {
  id: string;
  source: string;
  kind: string;
  title: string;
  captured_at: string;
  window: { start: string; end: string } | null;
  scope: { site_ids: string[]; device_macs: string[] };
  collection: 'complete' | 'partial' | 'error';
  representation: 'full' | 'digest';
  citable: boolean;
  detail: string;
}

export interface Gap {
  source: string;
  text: string;
}

export interface GuardianReport {
  run: ReportRun;
  header: ReportHeader | null;
  header_note: string | null;
  summary: ReportSummary;
  change: ReportSection<ChangeAtom>;
  coverage: CoverageSection;
  devices: ReportSection<DeviceMonitoring>;
  impacted: ReportSection<CompactImpactedDevice>;
  findings: ReportSection<FindingRow>;
  evidence: ReportSection<EvidenceRow>;
  gaps: ReportSection<Gap>;
}

// Endpoint responses -------------------------------------------------------

export interface GuardianRunReport {
  id: string;
  kind: RunKind;
  attempt: number;
  state: RunState;
  published: boolean;
  report: GuardianReport;
}

export interface GuardianAttemptSummary {
  id: string;
  kind: RunKind;
  attempt: number;
  state: RunState;
  failure_reason: string | null;
  budget: RunBudget;
  published: boolean;
}

export interface GuardianRoot {
  id: string;
  audit_id: string;
  changed_at: string;
  anchor_known: boolean;
  status: RootStatus;
  status_reason: string | null;
  next_check_at: string | null;
  attempts: { early: number; final: number };
  early_run_id: string | null;
  final_run_id: string | null;
  result: GuardianResult | null;
}

export interface GuardianInvestigation {
  root: GuardianRoot;
  runs: GuardianRunReport[];
  attempts: GuardianAttemptSummary[];
  /** Attempts whose stored run this build could not read: counted, never dropped in silence. */
  unreadable_attempts: number;
}

/** One stored model turn, as the expanded attempt shows it. */
export interface GuardianStep {
  turn: number;
  action: 'call' | 'report' | 'invalid';
  tool?: string | null;
  evidence_id?: string | null;
  collection?: 'complete' | 'partial' | 'error' | null;
  duration_ms?: number;
  output?: string;
  rejection?: string | null;
  detail?: string;
  prompt_version?: string;
  prompt_size?: number;
  visible_evidence_ids?: string[];
  withheld_evidence_ids?: string[];
}

export interface GuardianRunDetail extends GuardianRunReport {
  investigation_id: string;
  audit_id: string;
  failure_reason: string | null;
  steps: GuardianStep[];
  budget: RunBudget;
}

// States -------------------------------------------------------------------

/**
 * What a summary says, as one closed set of answers.
 *
 * `result` carries `early` (the published run was the early one) and
 * `continuing` (the root has not finished), so a result taken while the
 * investigation could still change can never be shown as a settled one.
 */
export type GuardianState =
  | { kind: 'not_recorded' }
  | { kind: 'unavailable' }
  | { kind: 'pending'; reason: string | null }
  | { kind: 'unresolved'; reason: string | null }
  | { kind: 'result'; result: GuardianResult; early: boolean; continuing: boolean; reason: string | null };

export function guardianState(summary: GuardianSummary | null | undefined): GuardianState {
  if (!summary) {
    return { kind: 'not_recorded' };
  }
  if (summary.availability === 'unavailable') {
    return { kind: 'unavailable' };
  }
  const reason = summary.status_reason ?? null;
  const result = summary.result;
  if (result) {
    return {
      kind: 'result',
      result,
      early: result.run_kind === 'early',
      continuing: summary.status !== 'done',
      reason,
    };
  }
  return summary.status === 'done' ? { kind: 'unresolved', reason } : { kind: 'pending', reason };
}

/** What a peak band means in words. `info` is "not established", never "no impact". */
export const BAND_LABEL: Record<Band, string> = {
  none: 'No impact observed',
  info: 'Impact not established',
  warning: 'Possible disruption',
  critical: 'Service loss',
};

export const RECOVERY_LABEL: Record<Recovery, string> = {
  none: '',
  recovered: 'Recovered',
  unrecovered: 'Not recovered',
};

export const COVERAGE_LABEL: Record<Coverage, string> = {
  complete: 'complete',
  partial: 'partial',
  insufficient: 'insufficient',
  not_applicable: 'not applicable',
};

export const RUN_KIND_LABEL: Record<RunKind, string> = {
  early: 'Early result',
  final: 'Final result',
};

/** The headline one line of a badge carries, for every state. */
export function guardianHeadline(state: GuardianState): string {
  switch (state.kind) {
    case 'not_recorded':
      return 'No investigation recorded';
    case 'unavailable':
      return 'Result could not be read';
    case 'pending':
      return 'Investigating';
    case 'unresolved':
      return 'No result published';
    case 'result':
      return BAND_LABEL[state.result.peak];
  }
}

/** The design's tone for a state. An unknown answer is never coloured as a clean one. */
export function guardianTone(state: GuardianState): 'crit' | 'warn' | 'info' | 'none' {
  if (state.kind !== 'result') {
    return 'info';
  }
  switch (state.result.peak) {
    case 'critical':
      return 'crit';
    case 'warning':
      return 'warn';
    case 'info':
      return 'info';
    default:
      return 'none';
  }
}

/**
 * Why a result that is not final is not final, in the words the badge and the
 * panel both use. An early result published by a finished investigation is the
 * one that most needs saying: no final result is coming.
 */
export function earlyNote(state: Extract<GuardianState, { kind: 'result' }>): string | null {
  if (!state.early) {
    return null;
  }
  return state.continuing
    ? 'Early result · the investigation is still running and may publish a final result'
    : 'Early result · the investigation ended without publishing a final result';
}

/**
 * How many impacted devices an investigation never recorded individually, for a
 * list the server has filtered to one site.
 *
 * The site overlay's count is the published run's own omissions and nothing
 * else: those devices have no recorded identity, so their site is unknown and
 * this site never claims them. (A report section's count is a different number,
 * because it also folds in the rows past the display limit; the panel words
 * that one for itself.)
 */
export function omittedSiteDeviceNote(omitted: number): string | null {
  if (omitted <= 0) {
    return null;
  }
  const devices = `${omitted} further impacted ${omitted === 1 ? 'device was' : 'devices were'} not recorded individually`;
  return `${devices}. Their identity, and so their site, is unknown: they are not claimed for this site.`;
}

/** A source's name in words, with the agent always named as AI. */
export function sourceLabel(source: string): string {
  if (source === 'agent') {
    return 'AI agent';
  }
  if (source.startsWith('rule:')) {
    return `Rule ${source.slice(5)}`;
  }
  if (source.startsWith('mcp:')) {
    return `MCP ${source.slice(4)}`;
  }
  return source.charAt(0).toUpperCase() + source.slice(1);
}
