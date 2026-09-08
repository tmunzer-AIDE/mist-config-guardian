import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';

import { AuthService, CurrentUser } from './auth.service';
import { sessionInterceptor } from './session.interceptor';

const USER: CurrentUser = {
  id: 'user-1',
  email: 's.kaur@northwind.example',
  display_name: 'Simran Kaur',
  role: 'operator',
  is_active: true,
  status: 'active',
  preferences: { timezone: 'Europe/Paris', clock: '24h', landing_page: 'overview' },
  mfa_enabled: false,
  passkey_count: 0,
};

describe('sessionInterceptor', () => {
  let http: HttpClient;
  let httpMock: HttpTestingController;
  let auth: AuthService;
  let navigations: { commands: unknown[]; extras?: Record<string, unknown> }[];

  beforeEach(() => {
    navigations = [];
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([sessionInterceptor])),
        provideHttpClientTesting(),
        {
          provide: Router,
          useValue: {
            url: '/changes',
            navigate: (commands: unknown[], extras?: Record<string, unknown>) => {
              navigations.push({ commands, extras });
              return Promise.resolve(true);
            },
          },
        },
      ],
    });
    http = TestBed.inject(HttpClient);
    httpMock = TestBed.inject(HttpTestingController);
    auth = TestBed.inject(AuthService);
  });

  afterEach(() => httpMock.verify());

  /** Issue a request and swallow the rejection the caller would see. */
  function request(url: string): Promise<unknown> {
    return new Promise((resolve) => http.get(url).subscribe({ next: resolve, error: resolve }));
  }

  async function fail(url: string, status = 401): Promise<void> {
    const pending = request(url);
    httpMock.expectOne(url).flush({ detail: 'Not authenticated' }, { status, statusText: 'Unauthorized' });
    await pending;
  }

  it('returns a signed-in user to sign-in when their session is gone', async () => {
    auth.applyUser(USER);

    await fail('/api/v1/organizations/org-1/overview');

    expect(auth.isAuthenticated()).toBe(false);
    expect(navigations).toEqual([{ commands: ['/login'], extras: { queryParams: { next: '/changes' } } }]);
  });

  it('does that once, however many requests fail', async () => {
    // Every page issues several reads; a revoked session fails all of them.
    auth.applyUser(USER);

    await fail('/api/v1/organizations/org-1/overview');
    await fail('/api/v1/organizations/org-1/notifications');
    await fail('/api/v1/organizations/org-1/change-groups');

    expect(navigations.length).toBe(1);
  });

  it('leaves the sign-in endpoints to answer for themselves', async () => {
    // A wrong password is answered by the sign-in page, and the redirect
    // target itself calls these: acting here could loop.
    auth.applyUser(USER);

    await fail('/api/v1/auth/login');
    await fail('/api/v1/auth/me');

    expect(auth.isAuthenticated()).toBe(true);
    expect(navigations).toEqual([]);
  });

  it('does nothing during start-up, when no session is believed in yet', async () => {
    await fail('/api/v1/organizations/org-1/overview');

    expect(navigations).toEqual([]);
  });

  it('passes other failures through untouched', async () => {
    auth.applyUser(USER);

    await fail('/api/v1/organizations/org-1/overview', 403);

    expect(auth.isAuthenticated()).toBe(true);
    expect(navigations).toEqual([]);
  });
});
