import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import { AuthService, CurrentUser, UserRole } from '../../core/auth.service';
import { ManagedUser, UsersService } from './users.service';
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
