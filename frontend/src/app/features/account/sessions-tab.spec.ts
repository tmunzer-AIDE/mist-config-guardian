import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import { AuthService, CurrentUser } from '../../core/auth.service';
import { AccountSession } from './account.model';
import { AccountService } from './account.service';
import { SessionsTab } from './sessions-tab';

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

function session(overrides: Partial<AccountSession> & { id: string }): AccountSession {
  return {
    label: 'Chrome on Windows',
    ip_address: '10.10.4.22',
    location: 'Portland, US',
    created_at: '2026-09-01T09:00:00Z',
    last_seen_at: '2026-09-06T18:02:00Z',
    expires_at: '2026-09-14T09:00:00Z',
    mfa_verified_at: null,
    current: false,
    ...overrides,
  };
}

const SESSIONS: AccountSession[] = [
  session({
    id: 's1',
    label: 'This browser · Firefox on macOS',
    location: 'Seattle, US',
    current: true,
  }),
  session({ id: 's2' }),
  session({ id: 's3', label: 'CLI · mcg-cli 0.4', location: null, ip_address: '10.10.4.22' }),
];

describe('SessionsTab', () => {
  let fixture: ComponentFixture<SessionsTab>;
  let account: AccountService;
  let http: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SessionsTab],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();

    TestBed.inject(AuthService).applyUser(USER);
    account = TestBed.inject(AccountService);
    account.sessions.set([...SESSIONS]);
    http = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(SessionsTab);
    fixture.detectChanges();
  });

  function element(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function rows(): HTMLElement[] {
    return Array.from(element().querySelectorAll<HTMLElement>('.entry'));
  }

  it('marks the current session and offers it no revoke control', () => {
    const [current, ...others] = rows();
    expect(current.textContent).toContain('THIS SESSION');
    expect(current.querySelector('button')).toBeNull();

    for (const other of others) {
      expect(other.textContent).not.toContain('THIS SESSION');
      expect(other.querySelector('button')?.textContent?.trim()).toBe('Revoke');
    }
  });

  it('shows where and when each session was last seen, falling back to the address', () => {
    const meta = rows().map((row) => row.querySelector('.entry-meta')?.textContent?.trim());
    expect(meta[0]).toBe('SEATTLE, US · ACTIVE NOW');
    expect(meta[1]).toBe('PORTLAND, US · 06 SEP 18:02Z');
    expect(meta[2]).toBe('10.10.4.22 · 06 SEP 18:02Z');
  });

  it('revokes one session and drops it from the list', async () => {
    rows()[1].querySelector('button')!.click();
    const request = http.expectOne('/api/v1/account/sessions/s2');
    expect(request.request.method).toBe('DELETE');
    request.flush({ revoked_sessions: 1 });
    await fixture.whenStable();
    fixture.detectChanges();

    expect(rows().length).toBe(2);
    expect(element().querySelector('[role="status"]')?.textContent).toContain(
      'Signed out Chrome on Windows',
    );
    http.verify();
  });

  it('signs out everywhere else and then hides the control', async () => {
    const everywhere = Array.from(element().querySelectorAll('button')).find((candidate) =>
      candidate.textContent?.trim().startsWith('Sign out everywhere else'),
    )!;
    everywhere.click();
    http.expectOne('/api/v1/account/sessions/revoke-others').flush({ revoked_sessions: 2 });
    await fixture.whenStable();
    fixture.detectChanges();

    expect(rows().length).toBe(1);
    expect(rows()[0].textContent).toContain('THIS SESSION');
    // Nothing left to sign out of, so the control goes away rather than lying.
    expect(
      Array.from(element().querySelectorAll('button')).some((candidate) =>
        candidate.textContent?.includes('Sign out everywhere else'),
      ),
    ).toBe(false);
    http.verify();
  });
});
