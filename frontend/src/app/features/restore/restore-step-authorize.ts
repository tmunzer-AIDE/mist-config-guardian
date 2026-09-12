import { ChangeDetectionStrategy, Component, computed, input, output, signal } from '@angular/core';

import { formatInstant } from '../../core/format';
import { Tone } from '../../core/tone';
import {
  ApprovalRequest,
  RestoreCredential,
  approvalRuleLabel,
  approvalStatusLabel,
  approvalStatusTone,
  orderedActions,
  RestoreMode,
  restoreModeConsequence,
  restoreModeLabel,
  RestoreOperation,
} from './restore.model';

/** Mist administrator tokens are at least this long; shorter is a paste error. */
export const MIN_TOKEN_LENGTH = 20;

interface CredentialMethod {
  key: 'token' | 'password';
  label: string;
  sub: string;
  available: boolean;
}

const METHODS: CredentialMethod[] = [
  {
    key: 'token',
    label: 'Administrator API token',
    sub: 'Used once, then discarded',
    available: true,
  },
  {
    key: 'password',
    label: 'Mist login and password',
    sub: 'Multi-factor verification when required',
    available: true,
  },
];

/**
 * Step 3 — exchange a separate write credential for an execution.
 *
 * The token lives only in this component's signal: it is handed straight to the
 * request and cleared the moment it is submitted. It is never written to
 * storage, to the URL, or to any service field.
 */
@Component({
  selector: 'app-restore-step-authorize',
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './restore-step-authorize.html',
  styleUrl: './restore-step-authorize.scss',
})
export class RestoreStepAuthorize {
  readonly operation = input.required<RestoreOperation>();
  readonly mode = input.required<RestoreMode>();
  readonly canAuthorize = input.required<boolean>();
  readonly authorizeNote = input.required<string>();
  readonly readOnly = input.required<boolean>();
  readonly busy = input.required<boolean>();
  readonly approval = input<ApprovalRequest | null>(null);
  readonly blockedByApproval = input(false);
  /** Reverses an applied restore rather than authorizing a new one. */
  readonly compensation = input(false);

  readonly authorized = output<RestoreCredential>();
  readonly cancelled = output<void>();
  readonly modePicked = output<RestoreMode>();
  readonly approvalRequested = output<void>();
  readonly approvalRefreshed = output<void>();

  protected readonly methods = METHODS;
  protected readonly method = signal<'token' | 'password'>('token');
  protected readonly revealed = signal(false);

  /**
   * The credential, held for exactly as long as it takes to submit it.
   *
   * It is bound to the field so clearing the signal clears the DOM value too;
   * nothing else in the application ever reads it.
   */
  protected readonly token = signal('');
  protected readonly email = signal('');
  protected readonly password = signal('');

  protected readonly actions = computed(() => orderedActions(this.operation()));
  protected readonly count = computed(() => this.actions().length);
  protected readonly deleteCount = computed(
    () => this.actions().filter((action) => action.action === 'delete').length,
  );

  protected readonly title = computed(() =>
    this.compensation()
      ? `Authorize ${this.count()} compensating actions`
      : `Authorize ${this.count()} write actions`,
  );

  protected readonly modes = computed(() =>
    (['non_destructive', 'exact'] as RestoreMode[]).map((value) => ({
      value,
      label: restoreModeLabel(value),
      consequence: restoreModeConsequence(value),
      on: this.mode() === value,
    })),
  );

  protected readonly tokenValid = computed(() => this.token().trim().length >= MIN_TOKEN_LENGTH);
  protected readonly tokenEmpty = computed(() => this.token().length === 0);

  protected readonly tokenHint = computed(() => {
    if (this.tokenEmpty()) {
      return 'Paste a fresh administrator API token. It is encrypted, used once, and discarded.';
    }
    return this.tokenValid()
      ? 'Token accepted. Write scope is verified before the first action.'
      : `Token looks too short — Mist administrator tokens are at least ${MIN_TOKEN_LENGTH} characters.`;
  });

  protected readonly tokenTone = computed<Tone>(() => {
    if (this.tokenEmpty()) {
      return 'none';
    }
    return this.tokenValid() ? 'ok' : 'crit';
  });

  protected readonly canSubmit = computed(
    () =>
      (this.method() === 'token'
        ? this.tokenValid()
        : /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(this.email().trim()) && this.password().length > 0) &&
      this.canAuthorize() &&
      !this.busy() &&
      !this.blockedByApproval() &&
      this.count() > 0,
  );

  protected readonly review = computed(() => {
    const approval = this.approval();
    if (!approval) {
      return null;
    }
    return {
      status: approvalStatusLabel(approval.status),
      tone: approvalStatusTone(approval.status),
      pending: approval.status === 'pending',
      summary: approval.summary,
      requestedBy: approval.requested_by_email,
      decidedBy: approval.decided_by_email,
      decidedAt: approval.decided_at ? instant(approval.decided_at) : null,
      expiresAt: approval.expires_at ? instant(approval.expires_at) : null,
      reason: approval.decision_reason,
      counts: `${approval.object_count} objects · ${approval.delete_count} deletes`,
      rules: (approval.triggered_rules ?? []).map((rule) => ({
        key: rule.rule,
        label: approvalRuleLabel(rule.rule),
        detail: rule.detail,
      })),
    };
  });

  protected setMethod(key: 'token' | 'password'): void {
    if (METHODS.find((method) => method.key === key)?.available) {
      this.clearCredentials();
      this.method.set(key);
    }
  }

  protected setLoginField(field: 'email' | 'password', event: Event): void {
    this[field].set((event.target as HTMLInputElement).value);
  }

  protected setToken(event: Event): void {
    this.token.set((event.target as HTMLInputElement).value);
  }

  protected toggleReveal(): void {
    this.revealed.update((value) => !value);
  }

  /** Hand the token to the caller and forget it in the same turn. */
  protected submit(): void {
    if (!this.canSubmit()) {
      return;
    }
    const credential: RestoreCredential = this.method() === 'token' ? this.token().trim() : {
      mist_login: { email: this.email().trim(), password: this.password() },
    };
    this.clearCredentials();
    this.authorized.emit(credential);
  }

  private clearCredentials(): void {
    this.token.set('');
    this.email.set('');
    this.password.set('');
    this.revealed.set(false);
  }

  protected cancel(): void {
    this.clearCredentials();
    this.cancelled.emit();
  }
}

function instant(value: string): string {
  const at = new Date(value);
  return Number.isNaN(at.getTime()) ? value : formatInstant(at);
}
