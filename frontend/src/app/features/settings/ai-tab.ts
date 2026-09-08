import { HttpErrorResponse } from '@angular/common/http';
import { ChangeDetectionStrategy, Component, computed, effect, inject, signal, untracked } from '@angular/core';

import { AuthService } from '../../core/auth.service';
import { formatInstant } from '../../core/format';
import { AiSettings, AiSettingsService, AiSettingsUpdate } from './ai-settings.service';

type TestState = 'idle' | 'testing' | 'ok' | 'failed';

/**
 * The AI Assist panel.
 *
 * The API key is write-only by design: the API returns only its last four
 * characters, and this panel never puts a typed key anywhere but the body of
 * the request that stores it. A blank key field is therefore not "no key" — it
 * means "keep the stored one", which is why the key is omitted from the update
 * unless the operator explicitly typed a replacement.
 */
@Component({
  selector: 'app-ai-tab',
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './ai-tab.html',
  styleUrl: './ai-tab.scss',
})
export class AiTab {
  private readonly ai = inject(AiSettingsService);
  private readonly auth = inject(AuthService);

  protected readonly canManage = computed(() => {
    this.auth.user();
    return this.auth.can('administrator');
  });

  protected readonly settings = this.ai.settings;
  protected readonly models = this.ai.models;

  protected readonly enabled = signal(false);
  protected readonly baseUrl = signal('');
  protected readonly model = signal('');
  protected readonly maxTokens = signal(1500);
  protected readonly automaticSummaries = signal(false);

  /** These settings hold a provider key, so saving them confirms who is asking. */
  protected readonly password = signal('');
  protected readonly setPassword = (event: Event): void =>
    this.password.set((event.target as HTMLInputElement).value);

  protected readonly keyEditing = signal(false);
  protected readonly keyDraft = signal('');

  protected readonly fetching = signal(false);
  protected readonly fetchError = signal('');
  protected readonly testState = signal<TestState>('idle');
  protected readonly testDetail = signal('');
  protected readonly saving = signal('');
  protected readonly notice = signal('');
  protected readonly error = signal('');

  private syncedFrom = '';

  protected readonly keyMasked = computed(() => {
    const current = this.settings();
    if (!current?.api_key_set) {
      return 'No key stored';
    }
    return `••••••••••••${current.api_key_last_four ?? ''}`;
  });

  protected readonly modelState = computed<'loading' | 'fetched' | 'unfetched'>(() => {
    if (this.fetching()) {
      return 'loading';
    }
    return this.models() === null ? 'unfetched' : 'fetched';
  });

  protected readonly modelOptions = computed(() => {
    const fetched = this.models() ?? [];
    const current = this.model();
    const options = fetched.map((item) => ({
      id: item.id,
      label: item.id,
      detail: modelDetail(item.owned_by, item.context_window),
    }));
    // Keep the stored model selectable even when the provider stopped listing it.
    if (current && !options.some((option) => option.id === current)) {
      options.unshift({ id: current, label: current, detail: 'currently configured' });
    }
    return options;
  });

  protected readonly dirty = computed(() => {
    const current = this.settings();
    if (!current) {
      return false;
    }
    return (
      this.enabled() !== current.enabled ||
      this.baseUrl().trim() !== current.base_url ||
      this.model() !== current.model ||
      this.maxTokens() !== current.max_response_tokens ||
      this.automaticSummaries() !== current.automatic_summaries
    );
  });

  protected readonly incomplete = computed(
    () => this.enabled() && (this.baseUrl().trim() === '' || this.model().trim() === ''),
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

  private adopt(settings: AiSettings): void {
    const stamp = JSON.stringify([
      settings.enabled,
      settings.base_url,
      settings.model,
      settings.max_response_tokens,
      settings.automatic_summaries,
    ]);
    if (this.syncedFrom === stamp) {
      return;
    }
    this.syncedFrom = stamp;
    this.enabled.set(settings.enabled);
    this.baseUrl.set(settings.base_url);
    this.model.set(settings.model);
    this.maxTokens.set(settings.max_response_tokens);
    this.automaticSummaries.set(settings.automatic_summaries);
  }

  // ------------------------------------------------------------------ edits
  protected toggleEnabled(): void {
    this.enabled.update((value) => !value);
    this.touched();
  }

  protected toggleAutomatic(): void {
    this.automaticSummaries.update((value) => !value);
    this.touched();
  }

  protected setBaseUrl(event: Event): void {
    this.baseUrl.set((event.target as HTMLInputElement).value);
    // A different endpoint serves a different catalogue.
    this.ai.forgetModels();
    this.testState.set('idle');
    this.touched();
  }

  protected setModel(event: Event): void {
    this.model.set((event.target as HTMLSelectElement).value);
    this.touched();
  }

  protected setMaxTokens(event: Event): void {
    const value = Number((event.target as HTMLInputElement).value);
    if (!Number.isFinite(value)) {
      return;
    }
    this.maxTokens.set(Math.min(32000, Math.max(256, Math.round(value))));
    this.touched();
  }

  protected setKeyDraft(event: Event): void {
    this.keyDraft.set((event.target as HTMLInputElement).value);
  }

  protected editKey(): void {
    this.keyEditing.set(true);
    this.keyDraft.set('');
    this.notice.set('');
    this.error.set('');
  }

  protected cancelKey(): void {
    this.keyEditing.set(false);
    // The plaintext key lives no longer than the edit that produced it.
    this.keyDraft.set('');
  }

  private touched(): void {
    this.notice.set('');
    this.error.set('');
  }

  // ---------------------------------------------------------------- actions
  /** Persist everything except the key, which a blank field must never clear. */
  protected async saveSettings(): Promise<void> {
    await this.persist('settings', this.updateBody(), 'Provider settings saved.');
  }

  protected async saveKey(): Promise<void> {
    const key = this.keyDraft().trim();
    if (!key) {
      return;
    }
    await this.persist('key', { ...this.updateBody(), api_key: key }, 'API key stored.');
    this.keyDraft.set('');
    this.keyEditing.set(false);
    this.ai.forgetModels();
    this.testState.set('idle');
  }

  protected async clearKey(): Promise<void> {
    await this.persist('key', { ...this.updateBody(), clear_api_key: true }, 'API key removed.');
    this.keyEditing.set(false);
    this.keyDraft.set('');
  }

  protected async fetchModels(): Promise<void> {
    if (this.fetching()) {
      return;
    }
    this.fetching.set(true);
    this.fetchError.set('');
    try {
      const items = await this.ai.fetchModels();
      if (items.length === 0) {
        this.fetchError.set('The endpoint returned no models for this key.');
      }
    } catch (cause) {
      this.fetchError.set(detailOf(cause));
    } finally {
      this.fetching.set(false);
    }
  }

  protected async test(): Promise<void> {
    if (this.testState() === 'testing') {
      return;
    }
    this.testState.set('testing');
    this.testDetail.set('');
    try {
      const result = await this.ai.test();
      this.testState.set(result.ok ? 'ok' : 'failed');
      this.testDetail.set(result.detail);
    } catch (cause) {
      this.testState.set('failed');
      this.testDetail.set(detailOf(cause));
    }
  }

  private updateBody(): AiSettingsUpdate {
    return {
      password: this.password(),
      enabled: this.enabled(),
      base_url: this.baseUrl().trim(),
      model: this.model().trim(),
      max_response_tokens: this.maxTokens(),
      automatic_summaries: this.automaticSummaries(),
    };
  }

  private async persist(key: string, body: AiSettingsUpdate, success: string): Promise<void> {
    if (this.saving()) {
      return;
    }
    this.saving.set(key);
    this.error.set('');
    this.notice.set('');
    try {
      await this.ai.save(body);
      this.notice.set(success);
    } catch (cause) {
      this.error.set(detailOf(cause));
    } finally {
      this.saving.set('');
    }
  }

  protected isSaving(key: string): boolean {
    return this.saving() === key;
  }
}

function modelDetail(ownedBy: string | null, contextWindow: number | null): string {
  const parts: string[] = [];
  if (ownedBy) {
    parts.push(`served by ${ownedBy}`);
  }
  if (contextWindow) {
    parts.push(`${Math.round(contextWindow / 1000)}k context`);
  }
  return parts.join(' · ');
}

function detailOf(cause: unknown): string {
  if (cause instanceof HttpErrorResponse) {
    const detail: unknown = (cause.error as { detail?: unknown } | null)?.detail;
    if (typeof detail === 'string') {
      return detail;
    }
    if (cause.status === 502) {
      return 'The provider endpoint could not be reached.';
    }
  }
  return 'The request could not be completed.';
}
