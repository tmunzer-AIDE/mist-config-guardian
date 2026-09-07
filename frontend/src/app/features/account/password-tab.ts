import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';

import { AccountService, detailOf } from './account.service';

/** One rule in the validity indicator, and whether the current draft meets it. */
export interface PasswordCheck {
  key: string;
  label: string;
  ok: boolean;
}

/**
 * The rules the indicator lists, evaluated against a draft.
 *
 * Exported so the rules can be tested without a component: they are the
 * contract the "Update password" button is gated on, and the backend's own
 * minimum (twelve characters) is only the first of them.
 */
export function passwordChecks(
  current: string,
  next: string,
  confirmation: string,
): PasswordCheck[] {
  return [
    { key: 'length', label: 'At least 12 characters', ok: next.length >= 12 },
    { key: 'case', label: 'Upper and lower case', ok: /[a-z]/.test(next) && /[A-Z]/.test(next) },
    { key: 'digit', label: 'A number', ok: /\d/.test(next) },
    { key: 'symbol', label: 'A symbol', ok: /[^A-Za-z0-9]/.test(next) },
    { key: 'match', label: 'Both new fields match', ok: next.length > 0 && next === confirmation },
    {
      key: 'distinct',
      label: 'Different from your current password',
      ok: next.length > 0 && next !== current,
    },
  ];
}

/** True when every rule passes and a current password has been entered. */
export function passwordValid(current: string, next: string, confirmation: string): boolean {
  return current.length > 0 && passwordChecks(current, next, confirmation).every((c) => c.ok);
}

@Component({
  selector: 'app-password-tab',
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './password-tab.html',
  styleUrl: './password-tab.scss',
})
export class PasswordTab {
  private readonly account = inject(AccountService);

  // Held in component state only: never persisted, never put on the URL, and
  // cleared the moment the change succeeds.
  private readonly current = signal('');
  private readonly next = signal('');
  private readonly confirmation = signal('');

  protected readonly currentValue = this.current.asReadonly();
  protected readonly nextValue = this.next.asReadonly();
  protected readonly confirmationValue = this.confirmation.asReadonly();

  protected readonly saving = signal(false);
  protected readonly error = signal('');
  protected readonly revoked = signal<number | null>(null);

  protected readonly checks = computed(() =>
    passwordChecks(this.current(), this.next(), this.confirmation()),
  );

  protected readonly valid = computed(() =>
    passwordValid(this.current(), this.next(), this.confirmation()),
  );

  protected readonly savedMessage = computed(() => {
    const count = this.revoked();
    if (count === null) {
      return '';
    }
    return count === 0
      ? 'Password updated. No other sessions were signed in.'
      : `Password updated. ${count} other session${count === 1 ? '' : 's'} signed out.`;
  });

  protected setCurrent(event: Event): void {
    this.current.set(valueOf(event));
    this.touched();
  }

  protected setNext(event: Event): void {
    this.next.set(valueOf(event));
    this.touched();
  }

  protected setConfirmation(event: Event): void {
    this.confirmation.set(valueOf(event));
    this.touched();
  }

  private touched(): void {
    this.revoked.set(null);
    this.error.set('');
  }

  protected async submit(): Promise<void> {
    if (!this.valid() || this.saving()) {
      return;
    }
    this.saving.set(true);
    this.error.set('');
    try {
      const result = await this.account.changePassword(this.current(), this.next());
      this.clear();
      this.revoked.set(result.revoked_sessions);
    } catch (cause) {
      this.error.set(detailOf(cause));
    } finally {
      this.saving.set(false);
    }
  }

  /** Drop every draft password from component state. */
  private clear(): void {
    this.current.set('');
    this.next.set('');
    this.confirmation.set('');
  }
}

function valueOf(event: Event): string {
  return (event.target as HTMLInputElement).value;
}
