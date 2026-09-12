import { MistLoginCredentials } from '../../core/auth.service';

export type RestoreCredential = string | { mist_login: MistLoginCredentials };

import { Tone } from '../../core/tone';

export type RestoreMode = 'exact' | 'non_destructive';
export type RestoreStatus =
  | 'planned'
  | 'queued'
  | 'running'
  | 'completed'
  | 'failed'
  | 'compensation_available'
  | 'compensated';

export type RestoreActionKind = 'create' | 'update' | 'delete';
export type RestoreActionStatus = 'pending' | 'executing' | 'completed' | 'failed' | 'skipped';

export interface RestoreAction {
  logical_object_id: string;
  source_version_id: string;
  baseline_version_id?: string | null;
  order: number;
  action: RestoreActionKind;
  scope: string;
  object_type: string;
  object_name: string;
  current_mist_id: string;
  site_mist_id: string | null;
  configuration: Record<string, unknown>;
  depends_on: string[];
  status: RestoreActionStatus;
  resulting_mist_id: string | null;
  error: string | null;
}

export type ApprovalStatus = 'pending' | 'approved' | 'rejected' | 'expired' | 'invalidated';

export type ApprovalRule =
  | 'organization_scope'
  | 'exact_mode_deletes'
  | 'object_count_threshold'
  | 'sensitive_object_type';

/** One policy rule with the evidence that made this plan need a second pair of eyes. */
export interface TriggeredRule {
  rule: ApprovalRule;
  detail: string;
}

/**
 * A second-administrator review of a restore plan.
 *
 * The plan hash binds the decision to the exact action list that was reviewed:
 * re-planning invalidates an approval rather than silently reusing it.
 */
export interface ApprovalRequest {
  id: string;
  restore_operation_id: string;
  status: ApprovalStatus;
  triggered_rules: TriggeredRule[];
  requested_by_email: string;
  decided_by_email: string | null;
  decided_at: string | null;
  decision_reason: string | null;
  expires_at: string | null;
  plan_hash: string;
  summary: string;
  object_count: number;
  delete_count: number;
  created_at: string;
}

export interface RestoreOperation {
  id: string;
  mode: RestoreMode;
  include_dependencies: boolean;
  /**
   * The versions the requester chose. Empty on operations planned before it
   * was recorded; such a plan cannot be rebuilt, so its mode is immutable.
   */
  requested_version_ids?: string[];
  baseline_snapshot_id?: string | null;
  prepared_until?: string | null;
  target_at: string;
  status: RestoreStatus;
  actions: RestoreAction[];
  warnings: string[];
  preflight_errors: string[];
  credential_actor: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  task_id: string | null;
  /** Null when no policy rule asked for a second administrator. */
  approval?: ApprovalRequest | null;
  compensation_available?: boolean;
}

export interface RestoreOperationPage {
  items: RestoreOperation[];
  total: number;
}

/** One restorable object version offered on step 1. */
export interface RestoreTarget {
  logical_object_id: string;
  version_id: string;
  name: string;
  object_type: string;
  scope: string;
  site_mist_id: string | null;
  site_name: string | null;
  version: number;
  observed_at: string;
}

export interface RestoreTargetTypeCount {
  type: string;
  count: number;
}

export interface RestoreTargetSite {
  id: string;
  name: string;
}

export interface RestoreTargetList {
  items: RestoreTarget[];
  total: number;
  /** Type vocabulary and counts for the TYPE row, faceted server-side. */
  types: RestoreTargetTypeCount[];
  /** Site vocabulary for the site select, faceted server-side. */
  sites: RestoreTargetSite[];
}

export type TargetScope = 'all' | 'org' | 'site';

/** Filters accepted by the restore targets endpoint. */
export interface RestoreTargetQuery {
  scope?: TargetScope;
  siteId?: string;
  objectType?: string;
  q?: string;
  skip?: number;
  limit?: number;
}

export type VerificationCheckStatus = 'ok' | 'failed' | 'skipped';

export interface VerificationCheck {
  label: string;
  status: VerificationCheckStatus;
  detail?: string | null;
}

export interface RestoreVerification {
  verified: boolean;
  checks: VerificationCheck[];
  post_snapshot_id: string | null;
  monitoring_session_ids: string[];
}

/** True while the worker still owns the operation, so the page must keep polling. */
export function isRestoreInFlight(status: RestoreStatus): boolean {
  return status === 'queued' || status === 'running';
}

/** True once the operation has reached a state the worker will not leave on its own. */
export function isRestoreTerminal(status: RestoreStatus): boolean {
  return (
    status === 'completed' ||
    status === 'failed' ||
    status === 'compensated' ||
    status === 'compensation_available'
  );
}

/** True when the operation failed in a way compensation can reverse. */
export function offersCompensation(operation: RestoreOperation): boolean {
  return operation.compensation_available === true || operation.status === 'compensation_available';
}

const MODE_LABELS: Record<RestoreMode, string> = {
  exact: 'Exact point-in-time',
  non_destructive: 'Non-destructive',
};

export function restoreModeLabel(mode: RestoreMode): string {
  return MODE_LABELS[mode] ?? mode;
}

/** The one-line consequence of a mode, spelled out wherever the mode is chosen. */
export function restoreModeConsequence(mode: RestoreMode): string {
  return mode === 'exact'
    ? 'Reproduce the historical state exactly, deleting objects that did not exist then. Deletions are permanent in Mist.'
    : 'Restore the selected state and leave everything else alone. Objects created since the target moment survive.';
}

/** `COMPENSATION AVAILABLE` — the badge text for a status value. */
export function restoreStatusLabel(status: RestoreStatus): string {
  return (status ?? '').replace(/_/g, ' ').toUpperCase() || 'UNKNOWN';
}

export function restoreStatusTone(status: RestoreStatus): Tone {
  if (status === 'completed') {
    return 'ok';
  }
  if (status === 'failed') {
    return 'crit';
  }
  if (status === 'compensated' || status === 'compensation_available') {
    return 'warn';
  }
  if (status === 'queued' || status === 'running') {
    return 'info';
  }
  return 'none';
}

/** `CREATE` / `UPDATE` / `DELETE`, and the tone the design gives each. */
export function actionKindLabel(kind: RestoreActionKind): string {
  return kind.toUpperCase();
}

export function actionKindTone(kind: RestoreActionKind): Tone {
  if (kind === 'delete') {
    return 'crit';
  }
  return kind === 'create' ? 'ok' : 'warn';
}

/**
 * The status word one action shows.
 *
 * A pending action reads `PLANNED` while nothing has been authorized and
 * `QUEUED` once the worker owns the operation, which is the distinction the
 * design draws between step 2 and step 4.
 */
export function actionStatusLabel(
  action: RestoreAction,
  operationStatus: RestoreStatus,
): string {
  switch (action.status) {
    case 'completed':
      return 'APPLIED';
    case 'executing':
      return 'RUNNING';
    case 'failed':
      return 'FAILED';
    case 'skipped':
      return 'SKIPPED';
    default:
      return operationStatus === 'planned' ? 'PLANNED' : 'QUEUED';
  }
}

export function actionStatusTone(status: RestoreActionStatus): Tone {
  switch (status) {
    case 'completed':
      return 'ok';
    case 'failed':
      return 'crit';
    case 'executing':
      return 'info';
    default:
      return 'none';
  }
}

/**
 * The plan's actions in dependency order.
 *
 * The list is sorted rather than trusted in array order, and an operation that
 * arrives without one reads as an empty plan instead of breaking the page.
 */
export function orderedActions(operation: RestoreOperation): RestoreAction[] {
  return [...(operation.actions ?? [])].sort((left, right) => left.order - right.order);
}

/** Actions the worker has finished, which is what the progress bar reports. */
export function appliedCount(operation: RestoreOperation): number {
  return orderedActions(operation).filter(
    (action) => action.status === 'completed' || action.status === 'skipped',
  ).length;
}

/** 0..100, rounded, guarding an empty plan. */
export function progressPercent(operation: RestoreOperation): number {
  const total = orderedActions(operation).length;
  if (total === 0) {
    return operation.status === 'completed' ? 100 : 0;
  }
  return Math.round((100 * appliedCount(operation)) / total);
}

/** The first action the worker could not apply, or null. */
export function failedAction(operation: RestoreOperation): RestoreAction | null {
  return orderedActions(operation).find((action) => action.status === 'failed') ?? null;
}

/**
 * The short form the design prints in lists.
 *
 * A 24-character object identifier is cut to its leading block; anything
 * already short enough to read — a seeded `r-4471`, say — is left whole.
 */
export function shortOperationId(id: string): string {
  return id.length <= 12 ? id : id.slice(0, 8);
}

const APPROVAL_RULE_LABELS: Record<ApprovalRule, string> = {
  organization_scope: 'Organization-scoped objects',
  exact_mode_deletes: 'Exact mode deletes objects',
  object_count_threshold: 'Object count above the threshold',
  sensitive_object_type: 'Sensitive object type',
};

export function approvalRuleLabel(rule: ApprovalRule): string {
  return APPROVAL_RULE_LABELS[rule] ?? rule;
}

export function approvalStatusLabel(status: ApprovalStatus): string {
  return status.toUpperCase();
}

export function approvalStatusTone(status: ApprovalStatus): Tone {
  switch (status) {
    case 'approved':
      return 'ok';
    case 'rejected':
    case 'invalidated':
      return 'crit';
    case 'expired':
      return 'warn';
    default:
      return 'info';
  }
}

/** An approval that exists and has not been granted blocks execution. */
export function blocksExecution(approval: ApprovalRequest | null | undefined): boolean {
  return approval != null && approval.status !== 'approved';
}
