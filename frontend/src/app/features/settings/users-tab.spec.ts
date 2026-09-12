import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import { AuthService, CurrentUser, UserRole } from '../../core/auth.service';
import { ManagedUser, UserInviteResult, UsersService } from './users.service';
import { demotionGuard, UsersTab } from './users-tab';

interface TabInternals {
  rows(): {
    id: string;
    guard: string;
    canDeactivate: boolean;
    canActivate: boolean;
    roleLabel: string;
  }[];
  canManage(): boolean;
}

function managed(patch: Partial<ManagedUser> & { id: string }): ManagedUser {
  return {
    email: `${patch.id}@northwind.example`,
    display_name: patch.id,
    role: 'viewer',
    status: 'active',
    is_active: true,
    mfa_enabled: false,
    invitation_expires_at: null,
    last_login_at: null,
    created_at: '2026-09-01T00:00:00Z',
    ...patch,
  };
}

function signedIn(id: string, role: UserRole): CurrentUser {
  return {
    id,
    email: `${id}@northwind.example`,
    display_name: id,
    role,
    is_active: true,
    status: 'active',
    preferences: { timezone: 'UTC', clock: '24h', landing_page: 'overview' },
    mfa_enabled: true,
    passkey_count: 0,
  };
}

describe('demotionGuard', () => {
  const administrator = managed({ id: 'admin', role: 'administrator' });

  it('leaves non-administrators unguarded', () => {
    expect(demotionGuard(managed({ id: 'viewer' }), false, true)).toBe('');
  });

  it('stops an administrator from demoting or deactivating themselves', () => {
    expect(demotionGuard(administrator, true, false)).toContain('your own administrator role');
  });

  it('stops the last active administrator from being demoted', () => {
    expect(demotionGuard(administrator, false, true)).toContain('last active administrator');
  });

  it('allows one of several administrators to be changed', () => {
    expect(demotionGuard(administrator, false, false)).toBe('');
  });

  it('does not guard an administrator who is already deactivated', () => {
    const inactive = managed({ id: 'admin', role: 'administrator', is_active: false });
    expect(demotionGuard(inactive, false, true)).toBe('');
  });
});

describe('UsersTab', () => {
  let http: HttpTestingController;

  async function render(role: UserRole, users: ManagedUser[] = []): Promise<ComponentFixture<UsersTab>> {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    TestBed.inject(AuthService).applyUser(signedIn('admin', role));
    http = TestBed.inject(HttpTestingController);
    if (users.length > 0) {
      const service = TestBed.inject(UsersService);
      const loaded = service.load();
      http.expectOne((request) => request.url === '/api/v1/users').flush({
        items: users,
        total: users.length,
      });
      await loaded;
    }
    const fixture = TestBed.createComponent(UsersTab);
    await fixture.whenStable();
    return fixture;
  }

  afterEach(() => {
    TestBed.resetTestingModule();
  });

  it('gives a viewer a read-only panel instead of a request that would 403', async () => {
    const fixture = await render('viewer');

    http.expectNone((request) => request.url.startsWith('/api/v1/users'));
    const element = fixture.nativeElement as HTMLElement;
    expect(element.textContent).toContain('administrator-only');
    expect(element.querySelector('table')).toBeNull();
    expect(element.querySelector('select')).toBeNull();
  });

  it('locks the row of the signed-in administrator', async () => {
    const fixture = await render('administrator', [
      managed({ id: 'admin', role: 'administrator' }),
      managed({ id: 'other', role: 'administrator' }),
      managed({ id: 'reader' }),
    ]);
    const rows = (fixture.componentInstance as unknown as TabInternals).rows();

    const self = rows.find((row) => row.id === 'admin');
    expect(self?.guard).toContain('your own administrator role');
    expect(self?.canDeactivate).toBe(false);

    // With two administrators the other one is still changeable.
    expect(rows.find((row) => row.id === 'other')?.guard).toBe('');
    expect(rows.find((row) => row.id === 'other')?.canDeactivate).toBe(true);
  });

  it('locks the last remaining administrator', async () => {
    const fixture = await render('administrator', [
      managed({ id: 'sole', role: 'administrator' }),
      managed({ id: 'reader' }),
    ]);
    const rows = (fixture.componentInstance as unknown as TabInternals).rows();

    expect(rows.find((row) => row.id === 'sole')?.guard).toContain('last active administrator');
    expect(rows.find((row) => row.id === 'sole')?.canDeactivate).toBe(false);
    expect(rows.find((row) => row.id === 'reader')?.canDeactivate).toBe(true);
  });

  it('renders a locked role as text with the reason in its title', async () => {
    const fixture = await render('administrator', [managed({ id: 'sole', role: 'administrator' })]);
    const element = fixture.nativeElement as HTMLElement;

    const badge = element.querySelector('tbody .cg-badge');
    expect(badge?.textContent?.trim()).toBe('ADMINISTRATOR');
    expect(badge?.getAttribute('title')).toContain('last active administrator');
    // No editable control exists for a row the API would refuse to change.
    expect(element.querySelector('tbody select')).toBeNull();
  });

  it('offers a role select for a row the API would accept', async () => {
    const fixture = await render('administrator', [
      managed({ id: 'admin', role: 'administrator' }),
      managed({ id: 'reader' }),
    ]);
    const element = fixture.nativeElement as HTMLElement;

    const selects = element.querySelectorAll('tbody select');
    expect(selects).toHaveLength(1);
    expect(selects[0].getAttribute('aria-label')).toBe('Role for reader');
  });
});

describe('UsersTab invitation link', () => {
  let http: HttpTestingController;

  async function render(): Promise<ComponentFixture<UsersTab>> {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    TestBed.inject(AuthService).applyUser(signedIn('admin', 'administrator'));
    http = TestBed.inject(HttpTestingController);
    const fixture = TestBed.createComponent(UsersTab);
    await fixture.whenStable();
    return fixture;
  }

  afterEach(() => {
    TestBed.resetTestingModule();
  });

  function element(fixture: ComponentFixture<UsersTab>): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  /** Opens the invite form via the same button an administrator would click. */
  function openInviteForm(fixture: ComponentFixture<UsersTab>): void {
    const openButton = [...element(fixture).querySelectorAll('button')].find(
      (button) => button.textContent?.trim() === 'Invite user',
    );
    if (!openButton) {
      throw new Error('missing the "Invite user" button');
    }
    (openButton as HTMLButtonElement).click();
    fixture.detectChanges();
  }

  function fillInviteForm(fixture: ComponentFixture<UsersTab>, email: string): void {
    const emailInput = element(fixture).querySelector<HTMLInputElement>('#invite-email');
    const nameInput = element(fixture).querySelector<HTMLInputElement>('#invite-name');
    if (!emailInput || !nameInput) {
      throw new Error('invite form is not open');
    }
    emailInput.value = email;
    emailInput.dispatchEvent(new Event('input'));
    nameInput.value = 'New user';
    nameInput.dispatchEvent(new Event('input'));
    fixture.detectChanges();
  }

  /** Submits the open invite form and resolves the mocked POST with `result`. */
  async function submitInvite(fixture: ComponentFixture<UsersTab>, result: UserInviteResult): Promise<void> {
    const form = element(fixture).querySelector('form');
    if (!form) {
      throw new Error('invite form is not open');
    }
    form.dispatchEvent(new Event('submit', { cancelable: true }));
    http.expectOne((request) => request.url === '/api/v1/users' && request.method === 'POST').flush(result);
    await fixture.whenStable();
    fixture.detectChanges();
  }

  function inviteResult(patch: Partial<UserInviteResult> & { user: ManagedUser }): UserInviteResult {
    return {
      invitation_expires_at: null,
      delivery: 'not_configured',
      invitation_token: null,
      invitation_url: null,
      delivery_detail: null,
      ...patch,
    };
  }

  it('shows the backend link when one is returned', async () => {
    const fixture = await render();
    openInviteForm(fixture);
    fillInviteForm(fixture, 'a@example.com');
    await submitInvite(
      fixture,
      inviteResult({
        user: managed({ id: 'new', email: 'a@example.com' }),
        delivery: 'not_configured',
        invitation_token: 'abc',
        invitation_url: 'https://guardian.example.com/accept-invitation#token=abc',
      }),
    );

    expect(element(fixture).textContent).toContain(
      'https://guardian.example.com/accept-invitation#token=abc',
    );
    const link = element(fixture).querySelector<HTMLAnchorElement>('a.token-value');
    expect(link?.getAttribute('href')).toBe('https://guardian.example.com/accept-invitation#token=abc');
  });

  it('builds a link from the document base when the backend could not', async () => {
    const fixture = await render();
    openInviteForm(fixture);
    fillInviteForm(fixture, 'a@example.com');
    await submitInvite(
      fixture,
      inviteResult({
        user: managed({ id: 'new', email: 'a@example.com' }),
        delivery: 'not_configured',
        invitation_token: 'abc',
        invitation_url: null,
      }),
    );

    const expected = `${document.baseURI.replace(/\/$/, '')}/accept-invitation#token=abc`;
    expect(element(fixture).textContent).toContain(expected);
    const link = element(fixture).querySelector<HTMLAnchorElement>('a.token-value');
    expect(link?.getAttribute('href')).toBe(expected);
  });

  it('never shows a bare token with no link', async () => {
    const fixture = await render();
    openInviteForm(fixture);
    fillInviteForm(fixture, 'a@example.com');
    await submitInvite(
      fixture,
      inviteResult({
        user: managed({ id: 'new', email: 'a@example.com' }),
        delivery: 'failed',
        invitation_token: 'abc',
        invitation_url: null,
        delivery_detail: 'The server refused the message',
      }),
    );

    // The token only ever appears as part of a complete, clickable link.
    expect(element(fixture).textContent).toContain('/accept-invitation#token=abc');
    const link = element(fixture).querySelector<HTMLAnchorElement>('a.token-value');
    expect(link).not.toBeNull();
    expect(link?.getAttribute('href')).toContain('/accept-invitation#token=abc');
    expect(link?.textContent).toContain('/accept-invitation#token=abc');
  });

  it('shows no link at all when the invitation was emailed', async () => {
    const fixture = await render();
    openInviteForm(fixture);
    fillInviteForm(fixture, 'a@example.com');
    await submitInvite(
      fixture,
      inviteResult({
        user: managed({ id: 'new', email: 'a@example.com' }),
        delivery: 'sent',
        invitation_token: null,
        invitation_url: null,
      }),
    );

    expect(element(fixture).textContent).toContain('Invitation emailed to a@example.com');
    expect(element(fixture).textContent).not.toContain('accept-invitation#');
    expect(element(fixture).querySelector('.token')).toBeNull();
  });

  it('names the failure reason', async () => {
    const fixture = await render();
    openInviteForm(fixture);
    fillInviteForm(fixture, 'a@example.com');
    await submitInvite(
      fixture,
      inviteResult({
        user: managed({ id: 'new', email: 'a@example.com' }),
        delivery: 'failed',
        invitation_token: 'abc',
        invitation_url: 'https://g.example.com/accept-invitation#token=abc',
        delivery_detail: 'The server refused the message',
      }),
    );

    expect(element(fixture).textContent).toContain('The server refused the message');
  });

  it('labels the submit control "Invite user", not a delivery promise it cannot keep', async () => {
    const fixture = await render();
    openInviteForm(fixture);

    const submit = [...element(fixture).querySelectorAll('button[type="submit"]')].find((button) =>
      button.textContent?.includes('Invite user'),
    );
    expect(submit).toBeTruthy();
    expect(element(fixture).textContent).not.toContain('Send invitation');
  });

  it('renders a hostile delivery_detail as text, never as markup', async () => {
    const fixture = await render();
    openInviteForm(fixture);
    fillInviteForm(fixture, 'a@example.com');
    const hostileDetail = '<img src=x onerror="window.__cg_pwned = true">';
    await submitInvite(
      fixture,
      inviteResult({
        user: managed({ id: 'new', email: 'a@example.com' }),
        delivery: 'failed',
        invitation_token: 'abc',
        invitation_url: 'https://g.example.com/accept-invitation#token=abc',
        delivery_detail: hostileDetail,
      }),
    );

    // The literal text must reach the page...
    expect(element(fixture).textContent).toContain(hostileDetail);
    // ...but only ever as escaped text, never as a parsed element.
    expect(element(fixture).querySelector('img')).toBeNull();
    expect(element(fixture).innerHTML).not.toContain('<img src=x');
    expect((globalThis as { __cg_pwned?: boolean }).__cg_pwned).toBeUndefined();
  });

  it('renders a hostile invitation_url as text and as an href only, never as markup', async () => {
    const fixture = await render();
    openInviteForm(fixture);
    fillInviteForm(fixture, 'a@example.com');
    const hostileUrl =
      'https://guardian.example.com/accept-invitation#token=abc"><img src=x onerror="window.__cg_pwned = true">';
    await submitInvite(
      fixture,
      inviteResult({
        user: managed({ id: 'new', email: 'a@example.com' }),
        delivery: 'not_configured',
        invitation_token: 'abc',
        invitation_url: hostileUrl,
      }),
    );

    expect(element(fixture).querySelector('img')).toBeNull();
    const link = element(fixture).querySelector<HTMLAnchorElement>('a.token-value');
    expect(link?.getAttribute('href')).toBe(hostileUrl);
    expect((globalThis as { __cg_pwned?: boolean }).__cg_pwned).toBeUndefined();
  });
});
