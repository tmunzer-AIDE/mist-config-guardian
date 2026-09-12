import { HttpErrorResponse } from '@angular/common/http';
import { ChangeDetectionStrategy, Component, computed, effect, inject, signal, untracked } from '@angular/core';

import { AuthService } from '../../core/auth.service';
import { formatInstant } from '../../core/format';
import { SmtpSecurity, SmtpSettings, SmtpSettingsUpdate, SmtpService } from './smtp.service';

type TestState = 'idle' | 'testing' | 'ok' | 'failed';

/**
 * The email delivery panel: SMTP settings used to send invitation mail.
 *
 * The password is write-only by design: the API returns only its last four
 * characters, and sends a typed password only in the update body. A blank
 * field is therefore not "no password", it means "keep the stored one",
 * which is why the password control loads empty and is omitted from the
 * update unless the operator explicitly typed a replacement or asked to
 * clear it.
 *
 * `last_test_detail` (and any other server-supplied text) is rendered only
 * through interpolation — never `[innerHTML]` — because it is free text a
 * remote mail server chose, not markup this application produced.
 */
@Component({
  selector: 'app-email-tab',
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './email-tab.html',
  styleUrl: './email-tab.scss',
})
export class EmailTab {
  private readonly smtp = inject(SmtpService);
  private readonly auth = inject(AuthService);

  protected readonly canManage = computed(() => {
    this.auth.user();
    return this.auth.can('administrator');
  });

  protected readonly settings = this.smtp.settings;

  protected readonly enabled = signal(false);
  protected readonly host = signal('');
  protected readonly port = signal(587);
  protected readonly security = signal<SmtpSecurity>('starttls');
  protected readonly username = signal('');
  protected readonly fromAddress = signal('');
  protected readonly fromName = signal('');

  protected readonly passwordDraft = signal('');
  protected readonly clearPassword = signal(false);

  protected readonly testState = signal<TestState>('idle');
  protected readonly testDetail = signal('');
  protected readonly saving = signal(false);
  protected readonly notice = signal('');
  protected readonly error = signal('');

  private syncedFrom = '';

  protected readonly passwordHint = computed(() => {
    const current = this.settings();
    if (!current?.password_set) {
      return 'No password stored.';
    }
    return `A password is stored, ending in ${current.password_last_four ?? ''}.`;
  });

  protected readonly dirty = computed(() => {
    const current = this.settings();
    if (!current) {
      return false;
    }
    return (
      this.enabled() !== current.enabled ||
      this.host().trim() !== current.host ||
      this.port() !== current.port ||
      this.security() !== current.security ||
      this.username().trim() !== current.username ||
      this.fromAddress().trim() !== current.from_address ||
      this.fromName().trim() !== current.from_name ||
      this.passwordDraft().trim() !== '' ||
      this.clearPassword()
    );
  });

  protected readonly incomplete = computed(
    () => this.enabled() && (this.host().trim() === '' || this.fromAddress().trim() === ''),
  );

  protected readonly lastTest = computed(() => {
    const current = this.settings();
    if (!current?.last_test_at) {
      return '';
    }
    const outcome = current.last_test_ok === true ? 'succeeded' : 'failed';
    return `Last checked ${formatInstant(new Date(current.last_test_at))} · ${outcome}${
      current.last_test_detail ? ` · ${current.last_test_detail}` : ''
    }`;
  });

  constructor() {
    effect(() => {
      const current = this.settings();
      if (!current) {
        return;
      }
      untracked(() => this.adopt(current));
    });
  }

  private adopt(settings: SmtpSettings): void {
    const stamp = JSON.stringify([
      settings.enabled,
      settings.host,
      settings.port,
      settings.security,
      settings.username,
      settings.from_address,
      settings.from_name,
    ]);
    if (this.syncedFrom === stamp) {
      return;
    }
    this.syncedFrom = stamp;
    this.enabled.set(settings.enabled);
    this.host.set(settings.host);
    this.port.set(settings.port);
    this.security.set(settings.security);
    this.username.set(settings.username);
    this.fromAddress.set(settings.from_address);
    this.fromName.set(settings.from_name);
  }

  // ------------------------------------------------------------------ edits
  protected toggleEnabled(): void {
    this.enabled.update((value) => !value);
    this.touched();
  }

  protected setHost(event: Event): void {
    this.host.set((event.target as HTMLInputElement).value);
    this.touched();
  }

  protected setPort(event: Event): void {
    const value = Number((event.target as HTMLInputElement).value);
    if (!Number.isFinite(value)) {
      return;
    }
    this.port.set(Math.min(65535, Math.max(1, Math.round(value))));
    this.touched();
  }

  protected setSecurity(event: Event): void {
    this.security.set((event.target as HTMLSelectElement).value as SmtpSecurity);
    this.touched();
  }

  protected setUsername(event: Event): void {
    this.username.set((event.target as HTMLInputElement).value);
    this.touched();
  }

  protected setFromAddress(event: Event): void {
    this.fromAddress.set((event.target as HTMLInputElement).value);
    this.touched();
  }

  protected setFromName(event: Event): void {
    this.fromName.set((event.target as HTMLInputElement).value);
    this.touched();
  }

  protected setPasswordDraft(event: Event): void {
    const value = (event.target as HTMLInputElement).value;
    this.passwordDraft.set(value);
    if (value) {
      // Typing a replacement supersedes an in-flight request to clear it.
      this.clearPassword.set(false);
    }
    this.touched();
  }

  protected toggleClearPassword(): void {
    this.clearPassword.update((value) => !value);
    if (this.clearPassword()) {
      this.passwordDraft.set('');
    }
    this.touched();
  }

  private touched(): void {
    this.notice.set('');
    this.error.set('');
  }

  // ---------------------------------------------------------------- actions
  /** Save the complete draft; an untouched password field keeps the stored one. */
  protected async saveSettings(): Promise<void> {
    // Passwords are opaque byte strings: trimming would silently store a
    // different password than the operator typed. The raw length, not the
    // trimmed value, decides whether a replacement was entered, so an
    // all-whitespace password is still sent rather than mistaken for "blank".
    const password = this.passwordDraft();
    const body: SmtpSettingsUpdate = {
      ...this.updateBody(),
      ...(this.clearPassword() ? { clear_password: true } : password.length > 0 ? { password } : {}),
    };
    const saved = await this.persist(body, 'SMTP settings saved.');
    if (saved) {
      this.passwordDraft.set('');
      this.clearPassword.set(false);
    }
  }

  /** Probe the stored server. There is no draft form to send: the test always checks what was saved. */
  protected async test(): Promise<void> {
    if (this.testState() === 'testing') {
      return;
    }
    this.testState.set('testing');
    this.testDetail.set('');
    try {
      const result = await this.smtp.test();
      this.testState.set(result.ok ? 'ok' : 'failed');
      this.testDetail.set(result.detail);
    } catch (cause) {
      this.testState.set('failed');
      this.testDetail.set(detailOf(cause));
    }
  }

  private updateBody(): SmtpSettingsUpdate {
    return {
      enabled: this.enabled(),
      host: this.host().trim(),
      port: this.port(),
      security: this.security(),
      username: this.username().trim(),
      from_address: this.fromAddress().trim(),
      from_name: this.fromName().trim(),
    };
  }

  private async persist(body: SmtpSettingsUpdate, success: string): Promise<boolean> {
    if (this.saving()) {
      return false;
    }
    this.saving.set(true);
    this.error.set('');
    this.notice.set('');
    try {
      await this.smtp.update(body);
      this.notice.set(success);
      return true;
    } catch (cause) {
      this.error.set(detailOf(cause));
      return false;
    } finally {
      this.saving.set(false);
    }
  }
}

function detailOf(cause: unknown): string {
  if (cause instanceof HttpErrorResponse) {
    const detail: unknown = (cause.error as { detail?: unknown } | null)?.detail;
    if (typeof detail === 'string') {
      return detail;
    }
  }
  return 'The request could not be completed.';
}
