import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import { AuthService, CurrentUser } from '../../core/auth.service';
import { AccountProfile } from './account.model';
import { ProfileTab, timezoneOptions } from './profile-tab';

const USER: CurrentUser = {
  id: 'u1',
  email: 's.kaur@northwind.example',
  display_name: 'S. Kaur',
  role: 'administrator',
  is_active: true,
  status: 'active',
  preferences: { timezone: 'UTC', clock: '24h', landing_page: 'overview' },
  mfa_enabled: false,
  passkey_count: 0,
};

const PROFILE: AccountProfile = {
  id: 'u1',
  email: USER.email,
  display_name: USER.display_name,
  preferences: USER.preferences,
  pending_email: null,
  pending_email_expires_at: null,
  password_changed_at: null,
};

describe('timezoneOptions', () => {
  it('leads with UTC and its reason, then every zone the runtime knows', () => {
    const options = timezoneOptions();
    expect(options[0].value).toBe('UTC');
    expect(options[0].label).toContain('matches every timestamp');
    expect(options.filter((option) => option.value === 'UTC').length).toBe(1);
    expect(options.length).toBeGreaterThan(1);
  });
});

describe('ProfileTab', () => {
  let fixture: ComponentFixture<ProfileTab>;
  let auth: AuthService;
  let http: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ProfileTab],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();

    auth = TestBed.inject(AuthService);
    auth.applyUser(USER);
    http = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(ProfileTab);
    fixture.detectChanges();
  });

  function element(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function button(text: string): HTMLButtonElement {
    const match = Array.from(element().querySelectorAll('button')).find((candidate) =>
      candidate.textContent?.trim().startsWith(text),
    );
    if (!match) {
      throw new Error(`No button labelled "${text}"`);
    }
    return match;
  }

  it('seeds the form from the signed-in user and explains the UTC default', () => {
    expect(element().querySelector<HTMLInputElement>('#account-display-name')!.value).toBe('S. Kaur');
    expect(element().querySelector<HTMLSelectElement>('#account-timezone')!.value).toBe('UTC');
    expect(element().textContent).toContain(
      'Audit correlation is easier when everyone reads the same clock',
    );
  });

  it('sends only the profile fields and hands the result back to the session', async () => {
    const input = element().querySelector<HTMLInputElement>('#account-display-name')!;
    input.value = '  Simran Kaur  ';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();

    button('Save changes').click();
    const request = http.expectOne('/api/v1/account/profile');
    expect(request.request.method).toBe('PATCH');
    expect(request.request.body).toEqual({
      display_name: 'Simran Kaur',
      timezone: 'UTC',
      clock: '24h',
      landing_page: 'overview',
    });
    request.flush({ ...PROFILE, display_name: 'Simran Kaur' });
    await fixture.whenStable();
    fixture.detectChanges();

    // The shell header reads the session user, so it has to see the new name —
    // and must keep the role the narrower profile response does not carry.
    expect(auth.user()?.display_name).toBe('Simran Kaur');
    expect(auth.user()?.role).toBe('administrator');
    expect(element().querySelector('.actions [role="status"]')?.textContent).toContain('Saved');
    http.verify();
  });

  it('never claims a confirmation email was delivered', async () => {
    button('Change email').click();
    fixture.detectChanges();

    for (const [id, value] of [
      ['account-new-email', 's.kaur@northwind.test'],
      ['account-email-password', 'old-password'],
    ]) {
      const field = element().querySelector<HTMLInputElement>(`#${id}`)!;
      field.value = value;
      field.dispatchEvent(new Event('input'));
    }
    fixture.detectChanges();

    button('Request change').click();
    http.expectOne('/api/v1/account/email-change').flush({
      pending_email: 's.kaur@northwind.test',
      expires_at: '2026-09-08T14:22:00Z',
      confirmation_token: 'tok-123',
      delivery: 'not_implemented',
    });
    // The panel reloads the profile once the request resolves, so let that
    // continuation run before expecting it.
    await fixture.whenStable();
    http.expectOne('/api/v1/account/profile').flush({
      ...PROFILE,
      pending_email: 's.kaur@northwind.test',
      pending_email_expires_at: '2026-09-08T14:22:00Z',
    });
    await fixture.whenStable();
    fixture.detectChanges();

    const pending = element().querySelector('.pending')!;
    expect(pending.textContent).toContain('No email was sent');
    expect(pending.textContent).toContain('no mail transport');
    expect(pending.textContent).not.toMatch(/we (?:have )?sent|check your inbox/i);
    expect(button('Confirm new address')).toBeDefined();
    http.verify();
  });

  it('offers no inline confirmation when the token was withheld', async () => {
    button('Change email').click();
    fixture.detectChanges();
    for (const [id, value] of [
      ['account-new-email', 's.kaur@northwind.test'],
      ['account-email-password', 'old-password'],
    ]) {
      const field = element().querySelector<HTMLInputElement>(`#${id}`)!;
      field.value = value;
      field.dispatchEvent(new Event('input'));
    }
    fixture.detectChanges();

    button('Request change').click();
    http.expectOne('/api/v1/account/email-change').flush({
      pending_email: 's.kaur@northwind.test',
      expires_at: '2026-09-08T14:22:00Z',
      confirmation_token: null,
      delivery: 'not_implemented',
    });
    // The panel reloads the profile once the request resolves, so let that
    // continuation run before expecting it.
    await fixture.whenStable();
    http.expectOne('/api/v1/account/profile').flush({
      ...PROFILE,
      pending_email: 's.kaur@northwind.test',
      pending_email_expires_at: '2026-09-08T14:22:00Z',
    });
    await fixture.whenStable();
    fixture.detectChanges();

    const pending = element().querySelector('.pending')!;
    expect(pending.textContent).toContain('delivered out of band');
    expect(
      Array.from(element().querySelectorAll('button')).some((candidate) =>
        candidate.textContent?.includes('Confirm new address'),
      ),
    ).toBe(false);
    http.verify();
  });
});
