import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import { AuthService, CurrentUser, UserRole } from '../../core/auth.service';
import { AiSettings, AiSettingsService } from './ai-settings.service';
import { AiTab } from './ai-tab';

interface TabInternals {
  saveSettings(): Promise<void>;
  saveKey(): Promise<void>;
  clearKey(): Promise<void>;
  editKey(): void;
  keyDraft: { set(value: string): void };
  keyMasked(): string;
  toggleAutomatic(): void;
  fetchModels(): Promise<void>;
  modelState(): string;
  modelOptions(): { id: string; detail: string }[];
  password: { (): string; set(value: string): void };
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

  it('forgets the password once the change it authorised has been made', async () => {
    const fixture = await render('administrator');
    const tab = fixture.componentInstance as unknown as TabInternals;

    tab.password.set('the-account-password');
    tab.toggleAutomatic();
    const saving = tab.saveSettings();
    const request = http.expectOne('/api/v1/ai/settings');

    expect((request.request.body as { password: string }).password).toBe('the-account-password');
    request.flush({ ...STORED, automatic_summaries: true });
    await saving;
    await fixture.whenStable();

    // A password left in the field authorises the next change too, for whoever
    // reaches the unlocked session next.
    expect(tab.password()).toBe('');
    expect((fixture.nativeElement as HTMLElement).innerHTML).not.toContain('the-account-password');
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
});
