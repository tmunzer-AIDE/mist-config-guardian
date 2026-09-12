import { ChangeDetectionStrategy, Component, computed, input, output } from '@angular/core';

import { formatInstant } from '../../core/format';
import { Tone } from '../../core/tone';
import { actionRows } from './restore-step-plan';
import {
  appliedCount,
  failedAction,
  isRestoreInFlight,
  offersCompensation,
  progressPercent,
  RestoreOperation,
  restoreStatusLabel,
  restoreStatusTone,
  RestoreVerification,
  shortOperationId,
  VerificationCheckStatus,
} from './restore.model';

const CHECK_MARKS: Record<VerificationCheckStatus, string> = {
  ok: '✓',
  failed: '✕',
  skipped: '–',
};

const CHECK_TONES: Record<VerificationCheckStatus, Tone> = {
  ok: 'ok',
  failed: 'crit',
  skipped: 'none',
};

/**
 * Step 4 — watch the worker apply the plan, then read the outcome.
 *
 * The page above owns the poll; this component only renders what the last read
 * returned, which keeps the live region honest about the actual server state.
 */
@Component({
  selector: 'app-restore-step-execute',
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './restore-step-execute.html',
  styleUrl: './restore-step-execute.scss',
})
export class RestoreStepExecute {
  readonly operation = input.required<RestoreOperation>();
  readonly verification = input<RestoreVerification | null>(null);
  readonly polling = input.required<boolean>();
  readonly pollExhausted = input.required<boolean>();
  readonly canAuthorize = input.required<boolean>();
  readonly authorizeNote = input.required<string>();
  readonly busy = input.required<boolean>();

  readonly refreshRequested = output<void>();
  readonly restartRequested = output<void>();
  readonly compensationRequested = output<void>();
  readonly impactOpened = output<string>();
  readonly snapshotOpened = output<string>();

  protected readonly rows = computed(() => actionRows(this.operation()));
  protected readonly total = computed(() => this.rows().length);
  protected readonly applied = computed(() => appliedCount(this.operation()));
  protected readonly percent = computed(() => progressPercent(this.operation()));

  protected readonly inFlight = computed(() => isRestoreInFlight(this.operation().status));
  protected readonly status = computed(() => restoreStatusLabel(this.operation().status));
  protected readonly statusTone = computed(() => restoreStatusTone(this.operation().status));
  protected readonly succeeded = computed(
    () => this.operation().status === 'completed' || this.operation().status === 'compensated',
  );

  protected readonly failure = computed(() => {
    const operation = this.operation();
    if (operation.status !== 'failed' && operation.status !== 'compensation_available') {
      return null;
    }
    const action = failedAction(operation);
    return {
      label: action ? `${action.action.toUpperCase()} ${action.object_name}` : 'the restore run',
      error: action?.error || operation.preflight_errors.join('; ') || 'The worker recorded no error message for this run.',
      applied: this.applied(),
    };
  });

  protected readonly compensationOffered = computed(
    () => offersCompensation(this.operation()) && this.canAuthorize(),
  );

  /**
   * The one line a screen reader hears on every poll.
   *
   * It carries the counts itself so the live region says the whole thing once,
   * rather than announcing the progress and its total as two separate readings.
   */
  protected readonly progressLabel = computed(() => {
    const operation = this.operation();
    if (operation.status === 'queued') {
      return `Queued — waiting for a worker to take ${this.total()} actions`;
    }
    if (operation.status === 'running') {
      return `Applying action ${Math.min(this.applied() + 1, this.total())} of ${this.total()}`;
    }
    if (this.succeeded()) {
      return `${this.applied()} of ${this.total()} actions applied`;
    }
    return `Halted after ${this.applied()} of ${this.total()} actions`;
  });

  protected readonly reference = computed(() => {
    const operation = this.operation();
    const started = operation.started_at ? instant(operation.started_at) : null;
    const finished = operation.completed_at ? instant(operation.completed_at) : null;
    const window = [started, finished].filter((value) => value !== null).join(' → ');
    return {
      id: shortOperationId(operation.id),
      actor: operation.credential_actor ?? 'unattributed',
      window: window || 'not started',
    };
  });

  protected readonly checks = computed(() =>
    (this.verification()?.checks ?? []).map((check, index) => ({
      key: `${index}·${check.label}`,
      label: check.label,
      detail: check.detail ?? null,
      mark: CHECK_MARKS[check.status],
      tone: CHECK_TONES[check.status],
    })),
  );

  protected readonly snapshotId = computed(() => this.verification()?.post_snapshot_id ?? null);
  protected readonly sessionIds = computed(() => this.verification()?.monitoring_session_ids ?? []);
}

function instant(value: string): string {
  const at = new Date(value);
  return Number.isNaN(at.getTime()) ? value : formatInstant(at);
}
