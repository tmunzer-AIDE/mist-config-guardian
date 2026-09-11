import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import { AuthService, CurrentUser, UserRole } from '../../core/auth.service';
import { EmailTab } from './email-tab';
import { SETTINGS_TABS } from './settings-page';
import { SmtpService, SmtpSettings } from './smtp.service';

interface TabInternals {
  saveSettings(): Promise<void>;
  test(): Promise<void>;
  host: { set(value: string): void };
  passwordDraft: { set(value: string): void };
  toggleClearPassword(): void;
}

const STORED: SmtpSettings = {
  enabled: true,
  host: 'mail.example.com',
  port: 587,
  security: 'starttls',
  username: 'svc-mailer',
  password_set: true,
  password_last_four: '**r2',
  from_address: 'noreply@example.com',
  from_name: 'Mist Config Guardian',
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

describe('EmailTab', () => {
  let http: HttpTestingController;

  async function render(
    role: UserRole,
    overrides: Partial<SmtpSettings> = {},
    loaded = true,
  ): Promise<ComponentFixture<EmailTab>> {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    TestBed.inject(AuthService).applyUser(signedIn(role));
    http = TestBed.inject(HttpTestingController);
    if (loaded) {
      const service = TestBed.inject(SmtpService);
      const pending = service.load();
      http.expectOne('/api/v1/settings/smtp').flush({ ...STORED, ...overrides });
      await pending;
    }
    const fixture = TestBed.createComponent(EmailTab);
    await fixture.whenStable();
    return fixture;
  }

  afterEach(() => {
    TestBed.resetTestingModule();
  });

  it('is one of the settings tabs', () => {
    expect(SETTINGS_TABS).toContain('email');
  });

  it('gives a viewer a read-only panel with no server fields', async () => {
    const fixture = await render('viewer', {}, false);
    const element = fixture.nativeElement as HTMLElement;

    http.expectNone((request) => request.url.startsWith('/api/v1/settings/smtp'));
    expect(element.textContent).toContain('configured by an administrator');
    expect(element.querySelector('input')).toBeNull();
  });

  it('loads and shows the stored settings', async () => {
    const fixture = await render('administrator', { host: 'mail.example.com', port: 587, security: 'starttls' });
    const host = fixture.nativeElement.querySelector('#smtp-host') as HTMLInputElement;
    expect(host.value).toBe('mail.example.com');
  });

  it('shows the last test outcome', async () => {
    const fixture = await render('administrator', {
      last_test_at: '2026-09-09T12:00:00Z',
      last_test_ok: false,
      last_test_detail: 'Connection refused',
    });
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('Connection refused');
  });

  it('renders a hostile last_test_detail as text, never as markup', async () => {
    const hostile = '<img src=x onerror="window.__cg_smtp_pwned = true">';
    const fixture = await render('administrator', {
      last_test_at: '2026-09-09T12:00:00Z',
      last_test_ok: false,
      last_test_detail: hostile,
    });
    const element = fixture.nativeElement as HTMLElement;

    // The literal text must reach the page...
    expect(element.textContent).toContain(hostile);
    // ...but only ever as escaped text, never as a parsed element.
    expect(element.querySelector('img')).toBeNull();
    expect(element.innerHTML).not.toContain('<img src=x');
    expect((globalThis as { __cg_smtp_pwned?: boolean }).__cg_smtp_pwned).toBeUndefined();
  });

  it('surfaces a rejected configuration', async () => {
    const fixture = await render('administrator');
    const tab = fixture.componentInstance as unknown as TabInternals;

    const saving = tab.saveSettings();
    const request = http.expectOne('/api/v1/settings/smtp');
    request.flush(
      { detail: 'An SMTP host is required to enable email' },
      { status: 422, statusText: 'Unprocessable Content' },
    );
    await saving;
    await fixture.whenStable();

    expect((fixture.nativeElement as HTMLElement).textContent).toContain(
      'An SMTP host is required to enable email',
    );
  });

  it('does not send the password back when it was left blank', async () => {
    const fixture = await render('administrator', { password_set: true, password_last_four: '**r2' });
    const tab = fixture.componentInstance as unknown as TabInternals;

    const saving = tab.saveSettings();
    const request = http.expectOne('/api/v1/settings/smtp');

    // A blank field means "keep the stored password": the field must be absent,
    // not an empty string, so the API never treats it as a replacement.
    expect(request.request.method).toBe('PUT');
    expect(Object.keys(request.request.body as object)).not.toContain('password');
    request.flush({ ...STORED, password_set: true, password_last_four: '**r2' });
    await saving;
  });

  it('sends a typed password exactly once and forgets the draft', async () => {
    const fixture = await render('administrator');
    const tab = fixture.componentInstance as unknown as TabInternals;

    tab.passwordDraft.set('s3cr3t-pass');
    const saving = tab.saveSettings();
    const request = http.expectOne('/api/v1/settings/smtp');

    expect((request.request.body as { password?: string }).password).toBe('s3cr3t-pass');
    expect((request.request.body as { clear_password?: boolean }).clear_password).toBeUndefined();
    request.flush({ ...STORED, password_set: true, password_last_four: 'pass' });
    await saving;
    await fixture.whenStable();

    const element = fixture.nativeElement as HTMLElement;
    expect(element.textContent).not.toContain('s3cr3t-pass');
    expect(element.innerHTML).not.toContain('s3cr3t-pass');
  });

  it('clears the stored password and omits password when asked to clear it', async () => {
    const fixture = await render('administrator', { password_set: true, password_last_four: '**r2' });
    const tab = fixture.componentInstance as unknown as TabInternals;

    tab.toggleClearPassword();
    const saving = tab.saveSettings();
    const request = http.expectOne('/api/v1/settings/smtp');

    expect((request.request.body as { clear_password?: boolean }).clear_password).toBe(true);
    expect(Object.keys(request.request.body as object)).not.toContain('password');
    request.flush({ ...STORED, password_set: false, password_last_four: null });
    await saving;
  });

  it('never renders the stored password, only its last four characters', async () => {
    const fixture = await render('administrator', { password_set: true, password_last_four: '**r2' });
    const element = fixture.nativeElement as HTMLElement;

    expect(element.textContent).toContain('**r2');
    expect(element.querySelector('#smtp-password')?.getAttribute('value')).toBeFalsy();
  });

  it('tests the stored server without sending a draft body', async () => {
    const fixture = await render('administrator', { host: 'mail.example.com' });
    const tab = fixture.componentInstance as unknown as TabInternals;

    const pending = tab.test();
    const request = http.expectOne('/api/v1/settings/smtp/test');
    expect(request.request.method).toBe('POST');
    expect(request.request.body).toEqual({});
    request.flush({ ok: true, detail: 'Connected as svc-mailer', checked_at: '2026-09-09T12:00:00Z' });
    await pending;
    await fixture.whenStable();

    expect((fixture.nativeElement as HTMLElement).textContent).toContain('Connected as svc-mailer');
  });

  it('disables the test button until a host is stored', async () => {
    const fixture = await render('administrator', { host: '' });
    await fixture.whenStable();

    const buttons = [...(fixture.nativeElement as HTMLElement).querySelectorAll('button')];
    const button = buttons.find((candidate) => candidate.textContent?.includes('Test connection'));
    expect(button?.disabled).toBe(true);
  });
});
