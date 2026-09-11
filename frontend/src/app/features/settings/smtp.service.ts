import { HttpClient } from '@angular/common/http';
import { inject, Injectable, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { API_ROOT } from '../../core/api';

export type SmtpSecurity = 'starttls' | 'tls' | 'none';

/**
 * Safe SMTP settings.
 *
 * The API never returns the stored password; only `password_last_four` is
 * ever displayed, and only when `password_set` is true.
 */
export interface SmtpSettings {
  enabled: boolean;
  host: string;
  port: number;
  security: SmtpSecurity;
  username: string;
  password_set: boolean;
  password_last_four: string | null;
  from_address: string;
  from_name: string;
  last_test_at: string | null;
  last_test_ok: boolean | null;
  last_test_detail: string | null;
}

/**
 * An SMTP settings update. `password` is omitted when the operator did not
 * type a new one, which is what tells the API to keep the stored password
 * untouched; `clear_password` removes it instead.
 */
export interface SmtpSettingsUpdate {
  enabled: boolean;
  host: string;
  port: number;
  security: SmtpSecurity;
  username: string;
  from_address: string;
  from_name: string;
  password?: string;
  clear_password?: boolean;
}

export interface SmtpConnectionTest {
  ok: boolean;
  detail: string;
  checked_at: string;
}

/** Administrator-managed SMTP delivery configuration. */
@Injectable({ providedIn: 'root' })
export class SmtpService {
  private readonly http = inject(HttpClient);

  private readonly settingsState = signal<SmtpSettings | null>(null);

  readonly settings = this.settingsState.asReadonly();

  async load(): Promise<SmtpSettings> {
    const settings = await firstValueFrom(this.http.get<SmtpSettings>(`${API_ROOT}/settings/smtp`));
    this.settingsState.set(settings);
    return settings;
  }

  async update(update: SmtpSettingsUpdate): Promise<SmtpSettings> {
    const settings = await firstValueFrom(this.http.put<SmtpSettings>(`${API_ROOT}/settings/smtp`, update));
    this.settingsState.set(settings);
    return settings;
  }

  /** Probe the stored server; there is no draft form, so nothing is sent to test. */
  async test(): Promise<SmtpConnectionTest> {
    const result = await firstValueFrom(
      this.http.post<SmtpConnectionTest>(`${API_ROOT}/settings/smtp/test`, {}),
    );
    this.settingsState.update((current) =>
      current === null
        ? current
        : {
            ...current,
            last_test_at: result.checked_at,
            last_test_ok: result.ok,
            last_test_detail: result.detail,
          },
    );
    return result;
  }
}
