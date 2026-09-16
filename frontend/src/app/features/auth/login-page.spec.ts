import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';

import { MistMfaService } from '../../core/mist-mfa.service';
import { LoginPage } from './login-page';

describe('LoginPage bootstrap gate', () => {
  let fixture: ComponentFixture<LoginPage>;
  let http: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [LoginPage],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();
    fixture = TestBed.createComponent(LoginPage);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify({ ignoreCancelled: true }));

  /**
   * Drain the microtask queue.
   *
   * The page awaits the gate and then writes two signals, and `whenStable`
   * only guarantees one turn, so the queue is drained before asserting.
   */
  async function drain(): Promise<void> {
    for (let turn = 0; turn < 12; turn += 1) {
      await Promise.resolve();
    }
    await fixture.whenStable();
    fixture.detectChanges();
    await fixture.whenStable();
  }

  /** Answer the version read the page issues before the gate. */
  function flushVersion(): void {
    http.expectOne('/api/v1/health').flush({ version: '1.0.0' });
  }

  async function render(available: boolean | 'fails'): Promise<HTMLElement> {
    fixture.detectChanges();
    flushVersion();
    const gate = http.expectOne('/api/v1/auth/bootstrap');
    expect(gate.request.method).toBe('GET');
    if (available === 'fails') {
      gate.flush('nope', { status: 500, statusText: 'Server Error' });
    } else {
      gate.flush({ available });
    }
    await drain();
    return fixture.nativeElement as HTMLElement;
  }

  it('sends Mist credentials and the selected region, then clears secrets on failure', async () => {
    const element = await render(false);
    const mist = Array.from(element.querySelectorAll('button')).find(button => button.textContent?.includes('Sign in with Mist'))!;
    mist.click();
    await drain();
    const email = element.querySelector<HTMLInputElement>('[formcontrolname="email"]')!;
    const password = element.querySelector<HTMLInputElement>('[formcontrolname="password"]')!;
    const region = element.querySelector<HTMLSelectElement>('select')!;
    email.value = 'admin@example.com';
    email.dispatchEvent(new Event('input'));
    password.value = ' mist password ';
    password.dispatchEvent(new Event('input'));
    region.value = 'emea_01';
    region.dispatchEvent(new Event('change'));
    element.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
    await drain();
    const request = http.expectOne('/api/v1/auth/login/mist');
    expect(request.request.body).toEqual({ email: 'admin@example.com', password: ' mist password ', region: 'emea_01' });
    expect(password.value).toBe('');
    expect(element.querySelector('[autocomplete="one-time-code"]')).toBeNull();
    expect(email.name).toBe('username');
    expect(password.name).toBe('password');
    request.flush({ detail: { code: 'mist_mfa_required' } }, { status: 409, statusText: 'Conflict' });
    await drain();
    TestBed.inject(MistMfaService).prompt()!.complete('123456');
    await drain();
    const retry = http.expectOne('/api/v1/auth/login/mist');
    expect(retry.request.body).toEqual({ email: 'admin@example.com', password: ' mist password ', region: 'emea_01', two_factor: '123456' });
    retry.flush({ detail: 'Mist rejected the login' }, { status: 401, statusText: 'Unauthorized' });
    await drain();
    expect(element.textContent).toContain('Mist rejected the login');
  });

  it('offers only the setup form while no administrator exists', async () => {
    const element = await render(true);
    const text = (element.textContent ?? '').replace(/\s+/g, ' ');

    expect(text).toContain('Create the first administrator');
    // There is nothing to sign in to yet, so sign-in is not offered at all.
    expect(element.querySelector('[formcontrolname="bootstrap_token"]')).not.toBeNull();
    expect(text).not.toContain('First-time setup');
    expect(element.querySelector('[role="tablist"]')).toBeNull();
  });

  it('offers only sign-in once an administrator exists', async () => {
    const element = await render(false);
    const text = (element.textContent ?? '').replace(/\s+/g, ' ');

    expect(text).toContain('Sign in');
    expect(text).not.toContain('First-time setup');
    expect(element.querySelector('[formcontrolname="bootstrap_token"]')).toBeNull();
    expect(element.querySelector('[role="tablist"]')).toBeNull();
  });

  it('falls back to sign-in when the gate cannot be read', async () => {
    const element = await render('fails');

    // The far more common case, and the one a returning administrator needs.
    expect(element.querySelector('[formcontrolname="password"]')).not.toBeNull();
    expect(element.querySelector('[formcontrolname="bootstrap_token"]')).toBeNull();
  });

  it('shows neither form until the gate has answered', async () => {
    fixture.detectChanges();
    flushVersion();
    http.expectOne('/api/v1/auth/bootstrap');
    await fixture.whenStable();
    fixture.detectChanges();

    const element = fixture.nativeElement as HTMLElement;
    expect(element.querySelector('[formcontrolname="password"]')).toBeNull();
    expect(element.querySelector('[formcontrolname="bootstrap_token"]')).toBeNull();
  });
});

describe('LoginPage passkey sign-in', () => {
  let fixture: ComponentFixture<LoginPage>;
  let http: HttpTestingController;
  let get: ReturnType<typeof vi.fn>;

  /** The options the API returns for an anonymous ceremony: no account is named. */
  const OPTIONS = {
    challenge_token: 'ct',
    options: { challenge: 'AQID', rpId: 'guardian.example.com', userVerification: 'preferred' },
  };

  const USER = {
    id: 'u1',
    email: 's.kaur@northwind.example',
    display_name: 'S. Kaur',
    role: 'administrator',
    is_active: true,
    status: 'active',
    preferences: { timezone: 'UTC', clock: '24h', landing_page: 'overview' },
    mfa_enabled: false,
    passkey_count: 1,
  };

  /** An assertion shaped like the one an authenticator returns. */
  function assertion(): unknown {
    return {
      id: 'cred-1',
      rawId: new Uint8Array([1, 2, 3]).buffer,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      getClientExtensionResults: () => ({}),
      response: {
        clientDataJSON: new Uint8Array([4, 5, 6]).buffer,
        authenticatorData: new Uint8Array([7, 8, 9]).buffer,
        signature: new Uint8Array([10, 11, 12]).buffer,
        userHandle: null,
      },
    };
  }

  async function build(): Promise<HTMLElement> {
    await TestBed.configureTestingModule({
      imports: [LoginPage],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();
    fixture = TestBed.createComponent(LoginPage);
    http = TestBed.inject(HttpTestingController);
    fixture.detectChanges();
    http.expectOne('/api/v1/health').flush({ version: '1.0.0' });
    http.expectOne('/api/v1/auth/bootstrap').flush({ available: false });
    await settle();
    return fixture.nativeElement as HTMLElement;
  }

  async function settle(): Promise<void> {
    for (let turn = 0; turn < 12; turn += 1) {
      await Promise.resolve();
    }
    await fixture.whenStable();
    fixture.detectChanges();
    await fixture.whenStable();
  }

  function passkeyButton(): HTMLButtonElement {
    return Array.from(
      (fixture.nativeElement as HTMLElement).querySelectorAll('button'),
    ).find((candidate) => candidate.textContent?.trim().startsWith('Use a passkey'))!;
  }

  function banner(role: 'alert' | 'status'): string {
    const element = fixture.nativeElement as HTMLElement;
    return element.querySelector(`[role="${role}"]`)?.textContent?.trim() ?? '';
  }

  beforeEach(() => {
    get = vi.fn().mockResolvedValue(assertion());
    vi.stubGlobal('PublicKeyCredential', class {});
    Object.defineProperty(window.navigator, 'credentials', { value: { get }, configurable: true });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    Reflect.deleteProperty(window.navigator, 'credentials');
    http.verify({ ignoreCancelled: true });
  });

  it('signs in without asking for an account, and sends the assertion base64url-encoded', async () => {
    await build();
    expect(passkeyButton().disabled).toBe(false);

    passkeyButton().click();
    const started = http.expectOne('/api/v1/auth/passkey/options');
    expect(started.request.method).toBe('POST');
    started.flush(OPTIONS);
    await settle();

    // The challenge reaches the authenticator as bytes, not as the base64url
    // string it travelled in.
    const requested = get.mock.calls[0][0].publicKey as PublicKeyCredentialRequestOptions;
    expect(Array.from(new Uint8Array(requested.challenge as ArrayBuffer))).toEqual([1, 2, 3]);
    expect(requested.rpId).toBe('guardian.example.com');
    // No account was named, so the authenticator chooses among its own
    // discoverable credentials.
    expect(requested.allowCredentials).toBeUndefined();

    const verified = http.expectOne('/api/v1/auth/passkey/verify');
    expect(verified.request.method).toBe('POST');
    expect(verified.request.body.challenge_token).toBe('ct');
    expect(verified.request.body.credential.response).toEqual({
      clientDataJSON: 'BAUG',
      authenticatorData: 'BwgJ',
      signature: 'CgsM',
    });
    verified.flush({ mfa_required: false, user: USER });
    await settle();

    expect(banner('alert')).toBe('');
  });

  it('asks for the second factor when the device only proved possession', async () => {
    const element = await build();

    passkeyButton().click();
    http.expectOne('/api/v1/auth/passkey/options').flush(OPTIONS);
    await settle();
    http.expectOne('/api/v1/auth/passkey/verify').flush({
      mfa_required: true,
      challenge_token: 'mfa-token',
      methods: ['totp'],
    });
    await settle();

    // The same second-factor form the password flow lands on.
    expect(element.querySelector('[formcontrolname="code"]')).not.toBeNull();
    expect(banner('alert')).toBe('');

    const input = element.querySelector<HTMLInputElement>('[formcontrolname="code"]')!;
    input.value = '123456';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    element.querySelector('form')!.dispatchEvent(new Event('submit'));
    const completed = http.expectOne('/api/v1/auth/login/mfa');
    expect(completed.request.body).toEqual({ challenge_token: 'mfa-token', code: '123456' });
    completed.flush({ mfa_required: false, user: USER });
    await settle();
  });

  it('treats a dismissed ceremony as a note rather than an error', async () => {
    get.mockRejectedValue(new DOMException('The operation was aborted', 'NotAllowedError'));
    await build();

    passkeyButton().click();
    http.expectOne('/api/v1/auth/passkey/options').flush(OPTIONS);
    await settle();

    // Nothing is verified, and the page stays where it is.
    http.expectNone('/api/v1/auth/passkey/verify');
    expect(banner('status')).toContain('dismissed on your device');
    expect(banner('alert')).toBe('');
  });

  it('reports a rejected assertion as an error', async () => {
    await build();

    passkeyButton().click();
    http.expectOne('/api/v1/auth/passkey/options').flush(OPTIONS);
    await settle();
    http
      .expectOne('/api/v1/auth/passkey/verify')
      .flush({ detail: 'That passkey could not be verified' }, { status: 401, statusText: 'Unauthorized' });
    await settle();

    expect(banner('alert')).toBe('That passkey could not be verified');
  });
});

describe('LoginPage without WebAuthn', () => {
  it('disables the passkey control and says so, without raising an error', async () => {
    await TestBed.configureTestingModule({
      imports: [LoginPage],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();
    const fixture = TestBed.createComponent(LoginPage);
    const http = TestBed.inject(HttpTestingController);
    fixture.detectChanges();
    http.expectOne('/api/v1/health').flush({ version: '1.0.0' });
    http.expectOne('/api/v1/auth/bootstrap').flush({ available: false });
    // The gate is awaited before either form is offered, so the queue is
    // drained rather than given a single turn.
    for (let turn = 0; turn < 12; turn += 1) {
      await Promise.resolve();
    }
    await fixture.whenStable();
    fixture.detectChanges();

    // jsdom exposes no authenticator, which is also the case for any
    // deployment served outside a secure context.
    const element = fixture.nativeElement as HTMLElement;
    const button = Array.from(element.querySelectorAll('button')).find((candidate) =>
      candidate.textContent?.trim().startsWith('Use a passkey'),
    )!;
    expect(button.disabled).toBe(true);
    expect(element.textContent).toContain('This browser cannot use passkeys');
    expect(element.querySelector('[role="alert"]')).toBeNull();
    http.verify();
  });
});
