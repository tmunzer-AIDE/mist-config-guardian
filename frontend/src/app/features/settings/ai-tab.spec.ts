import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import { AuthService, CurrentUser, UserRole } from '../../core/auth.service';
import { AiSettings, AiSettingsService } from './ai-settings.service';
import { AiTab } from './ai-tab';

interface TabInternals {
  saveSettings(): Promise<void>;
  test(): Promise<void>;
  baseUrl: { set(value: string): void };
  model: { set(value: string): void };
  keyEditing(): boolean;
  saveKey(): Promise<void>;
  clearKey(): Promise<void>;
  editKey(): void;
  keyDraft: { set(value: string): void };
  keyMasked(): string;
  toggleAutomatic(): void;
  fetchModels(): Promise<void>;
  modelState(): string;
  modelOptions(): { id: string; detail: string }[];
}

const STORED: AiSettings = {
  enabled: true,
  base_url: 'https://api.openai.com/v1',
  model: 'gpt-4o-mini',
  api_key_set: true,
  api_key_last_four: '7Qd3',
  max_response_tokens: 1500,
  automatic_summaries: false,
  last_test_at: null,
  last_test_ok: null,
  last_test_detail: null,
};

function signedIn(role: UserRole): CurrentUser {
  return {
    id: 'u1',
    email: 'a.osei@northwind.example',
    display_name: 'A. Osei',
    role,
    is_active: true,
    status: 'active',
    preferences: { timezone: 'UTC', clock: '24h', landing_page: 'overview' },
    mfa_enabled: true,
    passkey_count: 0,
  };
}

describe('AiTab', () => {
  let http: HttpTestingController;

  async function render(role: UserRole, loaded = true): Promise<ComponentFixture<AiTab>> {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    TestBed.inject(AuthService).applyUser(signedIn(role));
    http = TestBed.inject(HttpTestingController);
    if (loaded) {
      const service = TestBed.inject(AiSettingsService);
      const pending = service.load();
      http.expectOne('/api/v1/ai/settings').flush(STORED);
      await pending;
    }
    const fixture = TestBed.createComponent(AiTab);
    await fixture.whenStable();
    return fixture;
  }

  afterEach(() => {
    TestBed.resetTestingModule();
  });

  it('gives a viewer a read-only panel with no key field', async () => {
    const fixture = await render('viewer', false);
    const element = fixture.nativeElement as HTMLElement;

    http.expectNone((request) => request.url.startsWith('/api/v1/ai'));
    expect(element.textContent).toContain('configured by an administrator');
    expect(element.querySelector('input')).toBeNull();
    expect(element.querySelector('[role="switch"]')).toBeNull();
  });

  it('shows only the last four characters of the stored key', async () => {
    const fixture = await render('administrator');
    const tab = fixture.componentInstance as unknown as TabInternals;

    expect(tab.keyMasked()).toBe('••••••••••••7Qd3');
    expect(tab.keyMasked()).not.toContain('sk-');
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('7Qd3');
  });

  it('keeps the stored key when other settings are saved with a blank key field', async () => {
    const fixture = await render('administrator');
    const tab = fixture.componentInstance as unknown as TabInternals;

    tab.toggleAutomatic();
    const saving = tab.saveSettings();
    const request = http.expectOne('/api/v1/ai/settings');

    // A blank field means "keep the stored key": the field must be absent, not
    // an empty string, so the API never treats it as a replacement.
    expect(request.request.method).toBe('PUT');
    expect(Object.keys(request.request.body as object)).not.toContain('api_key');
    expect(request.request.body).toMatchObject({
      enabled: true,
      base_url: 'https://api.openai.com/v1',
      model: 'gpt-4o-mini',
      max_response_tokens: 1500,
      automatic_summaries: true,
    });
    request.flush({ ...STORED, automatic_summaries: true });
    await saving;
  });

  it('sends a typed key exactly once and forgets the draft', async () => {
    const fixture = await render('administrator');
    const tab = fixture.componentInstance as unknown as TabInternals;

    tab.editKey();
    tab.keyDraft.set('sk-live-abcdefghijkl');
    const saving = tab.saveKey();
    const request = http.expectOne('/api/v1/ai/settings');

    expect((request.request.body as { api_key?: string }).api_key).toBe('sk-live-abcdefghijkl');
    request.flush({ ...STORED, api_key_last_four: 'ijkl' });
    await saving;
    await fixture.whenStable();

    expect((fixture.nativeElement as HTMLElement).textContent).not.toContain('sk-live-abcdefghijkl');
    expect((fixture.nativeElement as HTMLElement).innerHTML).not.toContain('sk-live');
  });

  it('saves provider settings using the admin session without a password', async () => {
    const fixture = await render('administrator');
    const tab = fixture.componentInstance as unknown as TabInternals;
    tab.toggleAutomatic();
    const saving = tab.saveSettings();
    const request = http.expectOne('/api/v1/ai/settings');
    expect(request.request.body.password).toBeUndefined();
    request.flush({ ...STORED, automatic_summaries: true });
    await saving;
    expect(fixture.nativeElement.querySelector('#ai-password')).toBeNull();
  });

  it('asks for the key to be cleared explicitly rather than by blanking it', async () => {
    const fixture = await render('administrator');
    const tab = fixture.componentInstance as unknown as TabInternals;

    const clearing = tab.clearKey();
    const request = http.expectOne('/api/v1/ai/settings');

    expect((request.request.body as { clear_api_key?: boolean }).clear_api_key).toBe(true);
    expect(Object.keys(request.request.body as object)).not.toContain('api_key');
    request.flush({ ...STORED, api_key_set: false, api_key_last_four: null });
    await clearing;
  });

  it('reads models from the provider as objects, not strings', async () => {
    const fixture = await render('administrator');
    const tab = fixture.componentInstance as unknown as TabInternals;

    expect(tab.modelState()).toBe('unfetched');
    const fetching = tab.fetchModels();
    http.expectOne('/api/v1/ai/models').flush({
      items: [
        { id: 'gpt-4o-mini', owned_by: 'openai', context_window: 128000 },
        { id: 'llama-3.3-70b-instruct', owned_by: null, context_window: null },
      ],
    });
    await fetching;
    await fixture.whenStable();

    expect(tab.modelState()).toBe('fetched');
    expect(tab.modelOptions().map((option) => option.id)).toEqual([
      'gpt-4o-mini',
      'llama-3.3-70b-instruct',
    ]);
    expect(tab.modelOptions()[0].detail).toBe('served by openai · 128k context');
    expect((fixture.nativeElement as HTMLElement).querySelector('select#ai-model')).not.toBeNull();
  });
  it('tests the unsaved endpoint and key without saving settings', async () => {
    const fixture = await render('administrator');
    const tab = fixture.componentInstance as unknown as TabInternals;
    tab.baseUrl.set('http://oracle.example.test:8000/v1');
    tab.model.set('');
    tab.editKey();
    tab.keyDraft.set('draft-key');
    const pending = tab.test();
    const request = http.expectOne('/api/v1/ai/settings/test');
    expect(request.request.body).toEqual({
      base_url: 'http://oracle.example.test:8000/v1', model: '', api_key: 'draft-key',
    });
    http.expectNone((request) => request.method === 'PUT');
    request.flush({ ok: true, detail: 'Connected. Select a model.', checked_at: '2026-09-09T12:00:00Z' });
    await pending;
    expect(TestBed.inject(AiSettingsService).settings()?.last_test_at).toBeNull();
  });

  it('discovers models from the unsaved endpoint', async () => {
    const fixture = await render('administrator');
    const tab = fixture.componentInstance as unknown as TabInternals;
    tab.baseUrl.set('http://oracle.example.test:8000/v1');
    tab.model.set('');
    const pending = tab.fetchModels();
    const request = http.expectOne('/api/v1/ai/models');
    expect(request.request.method).toBe('POST');
    expect(request.request.body).toEqual({ base_url: 'http://oracle.example.test:8000/v1', model: '' });
    request.flush({ items: [{ id: 'local-model', owned_by: null, context_window: null }] });
    await pending;
    expect(tab.modelOptions().map((item) => item.id)).toEqual(['local-model']);
  });

  it('keeps an edited key after a failed save and saves it with the complete form', async () => {
    const fixture = await render('administrator');
    const tab = fixture.componentInstance as unknown as TabInternals;
    tab.editKey();
    tab.keyDraft.set('draft-key');
    const failed = tab.saveKey();
    http.expectOne('/api/v1/ai/settings').flush({ detail: 'Provider unavailable' }, { status: 502, statusText: 'Bad gateway' });
    await failed;
    expect(tab.keyEditing()).toBe(true);
    const saved = tab.saveSettings();
    const request = http.expectOne('/api/v1/ai/settings');
    expect(request.request.body.api_key).toBe('draft-key');
    request.flush({ ...STORED, api_key_last_four: '-key' });
    await saved;
    expect(tab.keyEditing()).toBe(false);
  });

});
