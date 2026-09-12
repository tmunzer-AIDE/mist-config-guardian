import { ChangeDetectionStrategy, Component, computed, input, output } from '@angular/core';

import { formatInstant } from '../../core/format';
import { Tone } from '../../core/tone';
import {
  actionKindLabel,
  actionKindTone,
  actionStatusLabel,
  actionStatusTone,
  orderedActions,
  RestoreAction,
  RestoreMode,
  restoreModeLabel,
  RestoreOperation,
  shortOperationId,
} from './restore.model';

/** One row of the ordered action list, shared by step 2 and step 4. */
export interface ActionRow {
  key: string;
  index: string;
  op: string;
  opTone: Tone;
  name: string;
  detail: string;
  kind: string;
  status: string;
  statusTone: Tone;
  error: string | null;
  running: boolean;
  failed: boolean;
  comparisonUrl: string | null;
}

/** Build the ordered action rows for one operation, in dependency order. */
export function actionRows(operation: RestoreOperation): ActionRow[] {
  return orderedActions(operation).map((action, index) => ({
    key: `${action.logical_object_id}·${action.order}`,
    index: String(index + 1).padStart(2, '0'),
    op: actionKindLabel(action.action),
    opTone: actionKindTone(action.action),
    name: action.object_name,
    detail: detailOf(action),
    kind: kindOf(action),
    status: actionStatusLabel(action, operation.status),
    statusTone: actionStatusTone(action.status),
    error: action.error,
    running: action.status === 'executing',
    failed: action.status === 'failed',
    comparisonUrl: action.baseline_version_id ? '/history?' + new URLSearchParams({
      object: action.logical_object_id, a: action.baseline_version_id, b: action.source_version_id,
    }).toString() : null,
  }));
}

function detailOf(action: RestoreAction): string {
  const parts: string[] = [];
  if (action.action === 'delete') {
    parts.push('Deleted — absent at the target moment');
  } else if (action.action === 'create') {
    parts.push(`Recreated from version ${shortOperationId(action.source_version_id)}`);
  } else {
    parts.push(`Updated to version ${shortOperationId(action.source_version_id)}`);
  }
  const dependencies = action.depends_on.length;
  if (dependencies > 0) {
    parts.push(`after ${dependencies} ${dependencies === 1 ? 'dependency' : 'dependencies'}`);
  }
  return parts.join(' · ');
}

function kindOf(action: RestoreAction): string {
  const type = action.object_type.toUpperCase();
  if (action.scope === 'org') {
    return `${type} · ORG`;
  }
  return action.site_mist_id ? `${type} · SITE ${action.site_mist_id}` : `${type} · SITE`;
}

/**
 * Step 2 — review the ordered plan.
 *
 * Nothing here writes. Preflight errors are the one thing that stops the flow:
 * they are rendered above the action list and hold step 3 closed until the plan
 * is rebuilt without them.
 */
@Component({
  selector: 'app-restore-step-plan',
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './restore-step-plan.html',
  styleUrl: './restore-step-plan.scss',
})
export class RestoreStepPlan {
  readonly operation = input.required<RestoreOperation>();
  readonly mode = input.required<RestoreMode>();
  readonly readOnly = input.required<boolean>();
  readonly readOnlyNote = input.required<string>();
  readonly busy = input.required<boolean>();

  readonly authorizeRequested = output<void>();
  readonly backRequested = output<void>();

  protected readonly columns = ['#', 'OP', 'OBJECT', 'TYPE', 'STATUS'];

  protected readonly rows = computed(() => actionRows(this.operation()));
  protected readonly count = computed(() => this.rows().length);
  protected readonly deleteCount = computed(
    () => this.rows().filter((row) => row.op === 'DELETE').length,
  );

  protected readonly plannedAt = computed(() => {
    const at = new Date(this.operation().created_at);
    return Number.isNaN(at.getTime()) ? '' : `PLANNED ${formatInstant(at)}`;
  });

  protected readonly meta = computed(() => {
    const operation = this.operation();
    const dependencies = operation.include_dependencies
      ? 'dependencies included'
      : 'dependencies excluded';
    return operation.mode === 'exact'
      ? `${restoreModeLabel(operation.mode)} · deletions allowed · ${dependencies}`
      : `${restoreModeLabel(operation.mode)} · nothing unrelated is deleted · ${dependencies}`;
  });

  protected readonly warnings = computed(() => this.operation().warnings ?? []);
  protected readonly preflightErrors = computed(() => this.operation().preflight_errors ?? []);
  protected readonly blocked = computed(() => this.preflightErrors().length > 0);
  protected readonly canContinue = computed(
    () => !this.blocked() && !this.readOnly() && !this.busy() && this.count() > 0,
  );
}
