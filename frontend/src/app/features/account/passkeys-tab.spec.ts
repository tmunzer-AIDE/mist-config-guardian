import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import { AuthService, CurrentUser } from '../../core/auth.service';
import { Passkey } from './account.model';
import { AccountService, base64UrlToBytes, webauthnAvailable } from './account.service';
import { PasskeysTab } from './passkeys-tab';

const USER: CurrentUser = {
  id: 'u1',
  email: 's.kaur@northwind.example',
  display_name: 'S. Kaur',
  role: 'administrator',
  is_active: true,
  status: 'active',
  preferences: { timezone: 'UTC', clock: '24h', landing_page: 'overview' },
  mfa_enabled: false,
  passkey_count: 2,
};

const PASSKEYS: Passkey[] = [
  {
    id: 'pk1',
    name: 'MacBook Pro · Touch ID',
    device_kind: 'platform',
    transports: ['internal'],
    backed_up: true,
    created_at: '2026-08-12T09:00:00Z',
    last_used_at: '2026-09-07T14:20:00Z',
  },
  {
    id: 'pk2',
    name: 'YubiKey 5C',
    device_kind: 'security_key',
    transports: ['usb'],
    backed_up: false,
    created_at: '2026-07-03T09:00:00Z',
    last_used_at: null,
  },
];

describe('PasskeysTab', () => {
  let fixture: ComponentFixture<PasskeysTab>;
  let account: AccountService;
  let http: HttpTestingController;

  async function build(): Promise<void> {
    await TestBed.configureTestingModule({
      imports: [PasskeysTab],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();

    TestBed.inject(AuthService).applyUser(USER);
    account = TestBed.inject(AccountService);
    account.passkeys.set([...PASSKEYS]);
    http = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(PasskeysTab);
    fixture.detectChanges();
  }

  function element(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function button(text: string): HTMLButtonElement | undefined {
    return Array.from(element().querySelectorAll('button')).find((candidate) =>
      candidate.textContent?.trim().startsWith(text),
    );
  }

  function typePassword(value: string): void {
    const input = element().querySelector<HTMLInputElement>('#passkey-password')!;
    input.value = value;
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
  }

  describe('without WebAuthn', () => {
    beforeEach(async () => {
      // jsdom exposes no authenticator, which is exactly the case the panel has
      // to degrade for.
      expect(webauthnAvailable()).toBe(false);
      await build();
    });

    it('explains the limitation in place of the add control, not as an error', () => {
      expect(button('Add a passkey')).toBeUndefined();
      const note = element().querySelector('.unsupported');
      expect(note?.textContent).toContain('cannot register a passkey');
      expect(element().querySelector('[role="alert"]')?.textContent?.trim()).toBe('');
    });

    it('still lists the credentials registered elsewhere, with rename and remove', () => {
      const names = Array.from(element().querySelectorAll('.entry-name')).map((node) =>
        node.textContent?.trim(),
      );
      expect(names).toEqual(['MacBook Pro · Touch ID', 'YubiKey 5C']);

      const kinds = Array.from(element().querySelectorAll('.cg-badge')).map((node) =>
        node.textContent?.trim(),
      );
      expect(kinds).toEqual(['PLATFORM', 'SECURITY KEY']);

      const meta = Array.from(element().querySelectorAll('.entry-meta')).map((node) =>
        node.textContent?.trim(),
      );
      expect(meta[0]).toBe('ADDED 12 Aug 2026 · LAST USED 07 SEP 14:20Z');
      expect(meta[1]).toContain('LAST USED NEVER');

      expect(button('Rename')).toBeDefined();
      expect(button('Remove')).toBeDefined();
    });

    it('renames a credential in place', async () => {
      button('Rename')!.click();
      fixture.detectChanges();

      const input = element().querySelector<HTMLInputElement>('#passkey-name-pk1')!;
      input.value = 'Work laptop';
      input.dispatchEvent(new Event('input'));
      fixture.detectChanges();

      button('Save')!.click();
      const request = http.expectOne('/api/v1/account/passkeys/pk1');
      expect(request.request.method).toBe('PATCH');
      expect(request.request.body).toEqual({ name: 'Work laptop' });
      request.flush({ ...PASSKEYS[0], name: 'Work laptop' });
      await fixture.whenStable();
      fixture.detectChanges();

      expect(element().querySelector('.entry-name')?.textContent?.trim()).toBe('Work laptop');
      http.verify();
    });

    it('removes a credential only after re-checking the password', async () => {
      // Without the password the request is not even made: a stolen session
      // must not be able to strip the account of its strongest credential.
      button('Remove')!.click();
      fixture.detectChanges();
      http.expectNone('/api/v1/account/passkeys/pk1');
      expect(element().querySelector('[role="alert"]')?.textContent).toContain('current password');

      typePassword('correct horse');
      button('Remove')!.click();
      const request = http.expectOne('/api/v1/account/passkeys/pk1');
      expect(request.request.method).toBe('DELETE');
      expect(request.request.body).toEqual({ password: 'correct horse' });
      request.flush(null, { status: 204, statusText: 'No Content' });
      await fixture.whenStable();
      fixture.detectChanges();

      expect(account.passkeys().map((item) => item.id)).toEqual(['pk2']);
      // The password is spent by the request and never lingers in the field.
      expect(element().querySelector<HTMLInputElement>('#passkey-password')!.value).toBe('');
      http.verify();
    });

    it('reports an empty list as a state, not a failure', async () => {
      account.passkeys.set([]);
      fixture.detectChanges();
      expect(element().querySelector('.entry-empty')?.textContent).toContain(
        'No passkeys registered',
      );
    });
  });

  describe('with WebAuthn', () => {
    let create: ReturnType<typeof vi.fn>;

    beforeEach(() => {
      // Feature detection reads these at construction time, so the browser has
      // to look capable before the component exists.
      create = vi.fn();
      vi.stubGlobal('PublicKeyCredential', class {});
      Object.defineProperty(window.navigator, 'credentials', {
        value: { create },
        configurable: true,
      });
    });

    afterEach(() => {
      vi.unstubAllGlobals();
      Reflect.deleteProperty(window.navigator, 'credentials');
    });

    it('offers the add control once the browser exposes an authenticator', async () => {
      expect(webauthnAvailable()).toBe(true);
      await build();
      expect(button('Add a passkey')).toBeDefined();
      expect(element().querySelector('.unsupported')).toBeNull();
    });

    it('asks for the password before it asks the browser for anything', async () => {
      await build();

      expect(button('Add a passkey')!.disabled).toBe(true);
      typePassword('correct horse');
      expect(button('Add a passkey')!.disabled).toBe(false);
    });

    it('treats a dismissed ceremony as a note rather than an error', async () => {
      create.mockRejectedValue(new DOMException('The operation was aborted', 'NotAllowedError'));
      await build();
      typePassword('correct horse');
      button('Add a passkey')!.click();
      const options = http.expectOne('/api/v1/account/passkeys/options');
      expect(options.request.body).toEqual({ password: 'correct horse' });
      options.flush({
        challenge_token: 'ct',
        options: {
          challenge: 'AAAA',
          rp: { id: 'localhost', name: 'Config Guardian' },
          user: { id: 'dTE', name: USER.email, displayName: USER.display_name },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        },
      });
      await fixture.whenStable();
      fixture.detectChanges();

      expect(element().querySelector('[role="alert"]')?.textContent?.trim()).toBe('');
      expect(element().querySelector('[role="status"]')?.textContent).toContain(
        'No passkey was added',
      );
      // Nothing was registered, so the list is untouched.
      expect(account.passkeys().length).toBe(2);
      http.verify();
    });
  });
});

describe('WebAuthn transport encoding', () => {
  it('decodes base64url into a buffer the authenticator API accepts', () => {
    const bytes = base64UrlToBytes('AQID');
    expect(Array.from(bytes)).toEqual([1, 2, 3]);
    // A plain ArrayBuffer, not a SharedArrayBuffer: only the former is a
    // BufferSource, which is what `credentials.create()` requires.
    expect(bytes.buffer).toBeInstanceOf(ArrayBuffer);
    expect(Array.from(base64UrlToBytes('_-8'))).toEqual([255, 239]);
  });
});
