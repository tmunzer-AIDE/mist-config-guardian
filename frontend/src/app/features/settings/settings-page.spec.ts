import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';

import { AuthService, CurrentUser, UserRole } from '../../core/auth.service';
import {
  ConfirmRequest,
  matchSettingsTab,
  resolveSettingsTab,
  SecretReveal,
  SettingsPage,
  settingsTabFromUrl,
} from './settings-page';

/** The protected surface the specs drive directly. */
interface PageInternals {
  active(): string;
  select(tab: string): void;
  openSecret(request: SecretReveal): void;
  openConfirm(request: ConfirmRequest): void;
  runConfirmed(): Promise<void>;
  closeDialogs(): void;
  secret(): SecretReveal | null;
}

/** Let the page's own `await` chain run before asserting on its requests. */
async function tick(fixture: ComponentFixture<SettingsPage>): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
  await fixture.whenStable();
}

function user(role: UserRole): CurrentUser {
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

describe('settings tab deep links', () => {
  it('accepts every canonical tab name', () => {
    expect(matchSettingsTab('organizations')).toBe('organizations');
    expect(matchSettingsTab('users')).toBe('users');
    expect(matchSettingsTab('ai')).toBe('ai');
    expect(matchSettingsTab('email')).toBe('email');
    expect(matchSettingsTab('health')).toBe('health');
  });

  it('ignores an unknown tab name rather than guessing', () => {
    expect(matchSettingsTab('billing')).toBeNull();
    expect(matchSettingsTab('')).toBeNull();
    expect(matchSettingsTab(undefined)).toBeNull();
  });

  it('reads a trailing path segment, because the shell links to /settings/health', () => {
    expect(settingsTabFromUrl('/settings/health')).toBe('health');
    expect(settingsTabFromUrl('/settings/organizations?x=1')).toBe('organizations');
    expect(settingsTabFromUrl('/settings')).toBeNull();
    expect(settingsTabFromUrl('/settings/nonsense')).toBeNull();
  });

  it('prefers the query parameter over the path, and defaults to organizations', () => {
    expect(resolveSettingsTab('users', '/settings/health')).toBe('users');
    expect(resolveSettingsTab(undefined, '/settings/health')).toBe('health');
    expect(resolveSettingsTab(undefined, '/settings')).toBe('organizations');
    expect(resolveSettingsTab('billing', '/settings')).toBe('organizations');
  });
});

describe('SettingsPage', () => {
  let http: HttpTestingController;

  async function render(role: UserRole): Promise<ComponentFixture<SettingsPage>> {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    });
    TestBed.inject(AuthService).applyUser(user(role));
    http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(SettingsPage);
    await fixture.whenStable();
    return fixture;
  }

  afterEach(() => {
    TestBed.resetTestingModule();
  });

  it('never calls an administrator-only endpoint for a viewer', async () => {
    await render('viewer');

    // Health is viewer-readable; the other three would answer 403.
    http.expectOne('/api/v1/system/health');
    http.expectNone('/api/v1/users');
    http.expectNone('/api/v1/ai/settings');
    http.expectNone('/api/v1/settings/smtp');
    http.expectNone('/api/v1/organizations');
  });

  it('shows a viewer the settings content rather than an error', async () => {
    const fixture = await render('viewer');
    const element = fixture.nativeElement as HTMLElement;

    expect(element.querySelectorAll('[role="tab"]')).toHaveLength(5);
    expect(element.querySelector('[role="tabpanel"]')).not.toBeNull();
    expect(element.textContent).toContain('administrator-only');
  });

  it('loads the administrator-only endpoints for an administrator', async () => {
    const fixture = await render('administrator');

    http
      .expectOne('/api/v1/system/health')
      .flush({ status: 'ok', checked_at: new Date().toISOString(), components: [] });
    await tick(fixture);

    http.expectOne('/api/v1/organizations');
    http.expectOne((request) => request.url === '/api/v1/users');
    http.expectOne('/api/v1/ai/settings');
    http.expectOne('/api/v1/settings/smtp');
  });

  it('shows the one-time secret and forgets it when the dialog closes', async () => {
    const fixture = await render('administrator');
    const page = fixture.componentInstance as unknown as PageInternals;
    const secret = 'whsec_7Qd3xR8pLm2VaKt9YbN4CzE6HfJ1sW0u';

    page.openSecret({
      title: 'New webhook secret',
      body: 'Copy this now.',
      value: secret,
      endpoint: '/api/v1/webhooks/mist/org-1',
    });
    await fixture.whenStable();

    const element = fixture.nativeElement as HTMLElement;
    const dialog = element.querySelector('[role="dialog"]');
    expect(dialog).not.toBeNull();
    expect(dialog?.getAttribute('aria-modal')).toBe('true');
    expect(dialog?.textContent).toContain('SHOWN ONCE');
    expect(dialog?.textContent).toContain(secret);

    page.closeDialogs();
    await fixture.whenStable();

    expect(page.secret()).toBeNull();
    expect(element.querySelector('[role="dialog"]')).toBeNull();
    // The value must not survive anywhere the next page load could read it.
    expect((fixture.nativeElement as HTMLElement).textContent).not.toContain(secret);
    expect(window.location.href).not.toContain('whsec_');
  });

  it('keeps a secret the confirmed action opened, because rotation shows it once', async () => {
    const fixture = await render('administrator');
    const page = fixture.componentInstance as unknown as PageInternals;
    const secret = 'whsec_7Qd3xR8pLm2VaKt9YbN4CzE6HfJ1sW0u';

    // Rotation is confirmed in one dialog and answered in another: the run
    // opens the secret dialog itself, the way the organizations tab does.
    page.openConfirm({
      title: 'Rotate the webhook secret?',
      body: 'Mist will reject events signed with the old secret.',
      confirmLabel: 'Rotate secret',
      danger: false,
      run: async () => {
        page.openSecret({
          title: 'New webhook secret',
          body: 'Copy this now.',
          value: secret,
          endpoint: '/api/v1/webhooks/mist/org-1',
        });
      },
    });
    await fixture.whenStable();

    await page.runConfirmed();
    await fixture.whenStable();

    expect(page.secret()?.value).toBe(secret);
    const element = fixture.nativeElement as HTMLElement;
    expect(element.querySelector('[role="dialog"]')?.textContent).toContain(secret);
  });

  it('reflects the selected tab back into the URL without stacking history', async () => {
    const fixture = await render('administrator');
    const page = fixture.componentInstance as unknown as PageInternals;
    const navigate = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);

    page.select('health');
    await fixture.whenStable();

    expect(page.active()).toBe('health');
    // Absolute: a `/settings/<tab>` path segment must not survive the switch.
    expect(navigate).toHaveBeenCalledWith(
      ['/settings'],
      expect.objectContaining({
        queryParams: { tab: 'health' },
        replaceUrl: true,
      }),
    );
  });

  it('honours ?tab= on load', async () => {
    const fixture = await render('administrator');

    fixture.componentRef.setInput('tab', 'ai');
    await fixture.whenStable();

    expect((fixture.componentInstance as unknown as PageInternals).active()).toBe('ai');
  });
});
