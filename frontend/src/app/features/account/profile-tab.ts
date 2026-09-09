import { ChangeDetectionStrategy, Component, computed, effect, inject, signal, untracked } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';

import { AuthService, ClockFormat, LandingPage } from '../../core/auth.service';
import { formatInstant } from '../../core/format';
import { AccountService, detailOf } from './account.service';

interface Option {
  value: string;
  label: string;
}

const LANDING_OPTIONS: { value: LandingPage; label: string }[] = [
  { value: 'overview', label: 'Overview — change timeline' },
  { value: 'changes', label: 'Changes' },
  { value: 'history', label: 'History' },
  { value: 'restore', label: 'Restore' },
  { value: 'impact', label: 'Impact monitoring' },
];

@Component({
  selector: 'app-profile-tab',
  imports: [ReactiveFormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './profile-tab.html',
  styleUrl: './profile-tab.scss',
})
export class ProfileTab {
  private readonly auth = inject(AuthService);
  private readonly account = inject(AccountService);

  protected readonly landingOptions = LANDING_OPTIONS;
  protected readonly timezones = timezoneOptions();

  protected readonly email = computed(
    () => this.account.profile()?.email ?? this.auth.user()?.email ?? '',
  );

  protected readonly saving = signal(false);
  protected readonly saved = signal(false);
  protected readonly error = signal('');

  protected readonly form = new FormGroup({
    display_name: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
    timezone: new FormControl('UTC', { nonNullable: true }),
    clock: new FormControl<ClockFormat>('24h', { nonNullable: true }),
    landing_page: new FormControl<LandingPage>('overview', { nonNullable: true }),
  });

  // ------------------------------------------------------------ email change
  protected readonly emailFormOpen = signal(false);
  protected readonly emailBusy = signal(false);
  protected readonly emailError = signal('');
  protected readonly emailConfirmed = signal(false);

  /**
   * The confirmation token, held only between the request that produced it and
   * the confirmation that spends it. The backend has no mail transport, so
   * outside production it hands the token straight back; nothing was sent, and
   * the panel says so rather than pretending otherwise.
   */
  private readonly inlineToken = signal('');
  protected readonly hasInlineToken = computed(() => this.inlineToken() !== '');

  protected readonly pendingEmail = computed(() => this.account.profile()?.pending_email ?? '');

  protected readonly pendingExpiry = computed(() => {
    const expires = this.account.profile()?.pending_email_expires_at;
    return expires ? formatInstant(new Date(expires), this.account.clock()) : '';
  });

  protected readonly emailForm = new FormGroup({
    new_email: new FormControl('', {
      nonNullable: true,
      validators: [Validators.required, Validators.email],
    }),
    password: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
  });

  private syncedFor = '';

  constructor() {
    effect(() => {
      const user = this.auth.user();
      if (!user) {
        return;
      }
      untracked(() => {
        // Re-seeding on every emission would fight the operator's typing, so the
        // form is filled once per identity and left alone after that.
        if (this.syncedFor === user.id) {
          return;
        }
        this.syncedFor = user.id;
        this.form.setValue({
          display_name: user.display_name,
          timezone: user.preferences.timezone,
          clock: user.preferences.clock,
          landing_page: user.preferences.landing_page,
        });
      });
    });
  }

  /** Any edit invalidates the "saved" confirmation still on screen. */
  protected touched(): void {
    this.saved.set(false);
    this.error.set('');
  }

  protected setClock(clock: ClockFormat): void {
    this.form.controls.clock.setValue(clock);
    this.touched();
  }

  protected async save(): Promise<void> {
    if (this.form.invalid || this.saving()) {
      this.form.markAllAsTouched();
      return;
    }
    this.saving.set(true);
    this.error.set('');
    const value = this.form.getRawValue();
    try {
      await this.account.updateProfile({
        display_name: value.display_name.trim(),
        timezone: value.timezone,
        clock: value.clock,
        landing_page: value.landing_page,
      });
      this.saved.set(true);
    } catch (cause) {
      this.error.set(detailOf(cause));
    } finally {
      this.saving.set(false);
    }
  }

  protected openEmailForm(): void {
    this.emailFormOpen.set(true);
    this.emailError.set('');
    this.emailConfirmed.set(false);
    this.emailForm.reset({ new_email: '', password: '' });
  }

  protected closeEmailForm(): void {
    this.emailFormOpen.set(false);
    // The password is only ever needed for the request that just ran.
    this.emailForm.reset({ new_email: '', password: '' });
  }

  protected async requestEmailChange(): Promise<void> {
    if (this.emailForm.invalid || this.emailBusy()) {
      this.emailForm.markAllAsTouched();
      return;
    }
    this.emailBusy.set(true);
    this.emailError.set('');
    const { new_email, password } = this.emailForm.getRawValue();
    try {
      const pending = await this.account.requestEmailChange(new_email.trim(), password);
      this.inlineToken.set(pending.confirmation_token ?? '');
      await this.account.loadProfile();
      this.closeEmailForm();
    } catch (cause) {
      this.emailError.set(detailOf(cause));
    } finally {
      this.emailBusy.set(false);
      this.emailForm.controls.password.reset('');
    }
  }

  protected async confirmEmailChange(): Promise<void> {
    const token = this.inlineToken();
    if (!token || this.emailBusy()) {
      return;
    }
    this.emailBusy.set(true);
    this.emailError.set('');
    try {
      await this.account.confirmEmailChange(token);
      this.inlineToken.set('');
      this.emailConfirmed.set(true);
    } catch (cause) {
      this.emailError.set(detailOf(cause));
    } finally {
      this.emailBusy.set(false);
    }
  }

  protected async cancelPending(): Promise<void> {
    if (this.emailBusy()) {
      return;
    }
    this.emailBusy.set(true);
    this.emailError.set('');
    try {
      await this.account.cancelEmailChange();
      this.inlineToken.set('');
    } catch (cause) {
      this.emailError.set(detailOf(cause));
    } finally {
      this.emailBusy.set(false);
    }
  }
}

/**
 * Every zone the runtime knows, UTC first.
 *
 * Audit correlation is easier when everyone reads the same clock, so UTC leads
 * the list and carries the explanation; older runtimes without
 * `supportedValuesOf` fall back to UTC alone rather than to a hand-kept list
 * that would drift from the platform database.
 */
export function timezoneOptions(): Option[] {
  let zones: string[] = [];
  try {
    zones = Intl.supportedValuesOf('timeZone');
  } catch {
    zones = [];
  }
  const rest = zones.filter((zone) => zone !== 'UTC').map((zone) => ({ value: zone, label: zone }));
  return [{ value: 'UTC', label: 'UTC — matches every timestamp in the app' }, ...rest];
}
