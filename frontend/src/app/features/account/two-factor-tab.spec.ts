import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import { AuthService, CurrentUser } from '../../core/auth.service';
import { TwoFactorTab, groupSecret } from './two-factor-tab';

const CODES = ['4H7K-2QD9', '8XPM-3TVB', 'QW51-7NRC', 'ZK30-9DLF'];

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

describe('TwoFactorTab', () => {
  let fixture: ComponentFixture<TwoFactorTab>;
  let http: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TwoFactorTab],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();

    TestBed.inject(AuthService).applyUser(USER);
    http = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(TwoFactorTab);
    fixture.detectChanges();
  });

  function element(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function button(text: string, within = ':scope'): HTMLButtonElement {
    const scope = element().querySelector(within) ?? element();
    const match = Array.from(scope.querySelectorAll('button')).find((candidate) =>
      candidate.textContent?.trim().startsWith(text),
    );
    if (!match) {
      throw new Error(`No button labelled "${text}"`);
    }
    return match;
  }

  /** The confirm control inside the password prompt, not the link that opened it. */
  function promptButton(text: string): HTMLButtonElement {
    return button(text, '.card--prompt');
  }

  async function enrol(): Promise<void> {
    button('Set up authenticator').click();
    http.expectOne('/api/v1/account/totp/enroll').flush({
      secret: 'JBSWY3DPEHPK3PXPKLMN2QRS',
      otpauth_uri: 'otpauth://totp/Config%20Guardian:s.kaur@northwind.example?secret=JBSWY3DP',
      issuer: 'Config Guardian',
      qr_svg: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 25 25"><path d="M2 2.5h7"/></svg>',
    });
    await fixture.whenStable();
    fixture.detectChanges();
  }

  async function confirm(): Promise<void> {
    const input = element().querySelector<HTMLInputElement>('#totp-code')!;
    input.value = '123456';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();

    button('Verify and enable').click();
    http.expectOne('/api/v1/account/totp/confirm').flush({
      recovery_codes: CODES,
      generated_at: '2026-09-07T14:22:00Z',
    });
    await fixture.whenStable();
    fixture.detectChanges();
  }

  it('renders the scannable code the API supplies, plus the key and link', async () => {
    await enrol();

    // The API renders the code with a tested encoder, so the panel offers all
    // three routes an authenticator can take: scan, type, or follow the link.
    const qr = element().querySelector('.qr');
    expect(qr?.querySelector('svg')).not.toBeNull();
    expect(qr?.getAttribute('role')).toBe('img');
    expect(element().querySelector('.secret')?.textContent?.trim()).toBe('JBSW Y3DP EHPK 3PXP KLMN 2QRS');
    expect(element().querySelector('.uri')?.textContent).toContain('otpauth://totp/');
    expect(groupSecret('ABCDEFG')).toBe('ABCD EFG');
  });

  it('falls back to the key alone when the API sends no code', async () => {
    button('Set up authenticator').click();
    http.expectOne('/api/v1/account/totp/enroll').flush({
      secret: 'JBSWY3DPEHPK3PXPKLMN2QRS',
      otpauth_uri: 'otpauth://totp/Config%20Guardian:s.kaur@northwind.example?secret=JBSWY3DP',
      issuer: 'Config Guardian',
      qr_svg: '',
    });
    await fixture.whenStable();
    fixture.detectChanges();

    expect(element().querySelector('.qr')).toBeNull();
    expect(element().querySelector('.secret')?.textContent?.trim()).toBe('JBSW Y3DP EHPK 3PXP KLMN 2QRS');
  });

  it('keeps the verify control disabled until six digits are entered', async () => {
    await enrol();
    expect(button('Verify and enable').disabled).toBe(true);

    const input = element().querySelector<HTMLInputElement>('#totp-code')!;
    input.value = '12ab34';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    // Non-digits are dropped, so this is only four digits and still short.
    expect(button('Verify and enable').disabled).toBe(true);

    input.value = '123456';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    expect(button('Verify and enable').disabled).toBe(false);
  });

  it('drops the enrolment secret as soon as the code is confirmed', async () => {
    await enrol();
    await confirm();
    expect(element().querySelector('.secret')).toBeNull();
    expect(element().querySelector('.uri')).toBeNull();
    expect(element().textContent).not.toContain('JBSW Y3DP');
  });

  it('shows the recovery codes once and clears them when they are dismissed', async () => {
    await enrol();
    await confirm();

    const shown = Array.from(element().querySelectorAll('.code')).map((code) =>
      code.textContent?.trim(),
    );
    expect(shown).toEqual(CODES);
    expect(element().textContent).toContain('SHOWN ONCE');

    button('I have stored them').click();
    fixture.detectChanges();
    expect(element().querySelectorAll('.code').length).toBe(0);
    expect(element().textContent).not.toContain(CODES[0]);
  });

  it('does not put the codes anywhere they could be read back', async () => {
    await enrol();
    await confirm();

    // Whatever storage this runtime exposes, none of it holds a code, and none
    // of them reach the URL either.
    const stored = [
      dump(globalThis.localStorage),
      dump(globalThis.sessionStorage),
      window.location.href,
    ].join(' ');
    for (const code of CODES) {
      expect(stored).not.toContain(code);
    }

    // Once dismissed they are gone from the component too, with no service-level
    // copy to render them again.
    button('I have stored them').click();
    fixture.detectChanges();
    expect(element().textContent).not.toContain(CODES[0]);
  });

  it('requires the password before it will turn the second factor off', async () => {
    await enrol();
    await confirm();

    button('Turn off').click();
    fixture.detectChanges();
    expect(promptButton('Turn off').disabled).toBe(true);

    const password = element().querySelector<HTMLInputElement>('#totp-password')!;
    password.value = 'old-password';
    password.dispatchEvent(new Event('input'));
    fixture.detectChanges();

    promptButton('Turn off').click();
    const request = http.expectOne('/api/v1/account/totp');
    expect(request.request.method).toBe('DELETE');
    expect(request.request.body).toEqual({ password: 'old-password' });
    request.flush({
      id: 'u1',
      email: USER.email,
      display_name: USER.display_name,
      preferences: USER.preferences,
      pending_email: null,
      pending_email_expires_at: null,
      password_changed_at: null,
    });
    await fixture.whenStable();
    fixture.detectChanges();

    // The password is spent, and the panel is back to its unconfigured state.
    expect(element().querySelector('#totp-password')).toBeNull();
    expect(element().textContent).toContain('NOT CONFIGURED');
    http.verify();
  });
});

/** Every value in a Storage, or nothing when this runtime has no such storage. */
function dump(storage: Storage | undefined): string {
  if (!storage) {
    return '';
  }
  const values: string[] = [];
  for (let index = 0; index < storage.length; index += 1) {
    const key = storage.key(index);
    values.push(key ?? '', (key && storage.getItem(key)) ?? '');
  }
  return values.join(' ');
}
