import { HttpClient } from '@angular/common/http';
import { inject, Injectable, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { API_ROOT } from '../../core/api';

/**
 * Safe AI provider settings.
 *
 * The API never returns the stored key; only `api_key_last_four` is ever
 * displayed, and the plaintext key exists in this application for the single
 * turn of a save request.
 */
export interface AiSettings {
  enabled: boolean;
  base_url: string;
  model: string;
  api_key_set: boolean;
  api_key_last_four: string | null;
  max_response_tokens: number;
  automatic_summaries: boolean;
  last_test_at: string | null;
  last_test_ok: boolean | null;
  last_test_detail: string | null;
}

/**
 * A settings update. `api_key` is omitted when the operator did not type a new
 * one, which is what tells the API to keep the stored key untouched.
 */
export interface AiSettingsUpdate {
  enabled: boolean;
  base_url: string;
  model: string;
  max_response_tokens: number;
  automatic_summaries: boolean;
  api_key?: string;
  clear_api_key?: boolean;
}

export interface AiConnectionTest {
  ok: boolean;
  detail: string;
  checked_at: string;
}

/** One model the configured provider advertises. */
export interface AiModel {
  id: string;
  owned_by: string | null;
  context_window: number | null;
}

interface AiModelList {
  items: AiModel[];
}

/** Administrator-managed AI Assist provider configuration. */
@Injectable({ providedIn: 'root' })
export class AiSettingsService {
  private readonly http = inject(HttpClient);

  private readonly settingsState = signal<AiSettings | null>(null);
  private readonly modelsState = signal<AiModel[] | null>(null);

  readonly settings = this.settingsState.asReadonly();
  /** Null until models were fetched from the provider at least once. */
  readonly models = this.modelsState.asReadonly();

  async load(): Promise<AiSettings> {
    const settings = await firstValueFrom(this.http.get<AiSettings>(`${API_ROOT}/ai/settings`));
    this.settingsState.set(settings);
    return settings;
  }

  async save(update: AiSettingsUpdate): Promise<AiSettings> {
    const settings = await firstValueFrom(this.http.put<AiSettings>(`${API_ROOT}/ai/settings`, update));
    this.settingsState.set(settings);
    return settings;
  }

  async test(): Promise<AiConnectionTest> {
    const result = await firstValueFrom(
      this.http.post<AiConnectionTest>(`${API_ROOT}/ai/settings/test`, {}),
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

  /** Read the models the configured provider actually advertises. */
  async fetchModels(): Promise<AiModel[]> {
    const response = await firstValueFrom(this.http.get<AiModelList>(`${API_ROOT}/ai/models`));
    const items = response.items.filter((item) => Boolean(item.id));
    this.modelsState.set(items);
    return items;
  }

  /** Drop a stale model list, e.g. after the endpoint or key changed. */
  forgetModels(): void {
    this.modelsState.set(null);
  }
}
