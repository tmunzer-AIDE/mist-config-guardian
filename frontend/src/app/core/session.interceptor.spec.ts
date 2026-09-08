import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';

import { AuthService, CurrentUser } from './auth.service';
import { NotificationService } from './notification.service';
import { OrganizationContextService } from './organization-context.service';
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

  it('does not evict a session that started after the failing request', async () => {
    // The old session's read answers after someone has signed in again. It
    // says nothing about the new session and must not end it.
    auth.applyUser(USER);
    const pending = request('/api/v1/organizations/org-1/overview');
    const stale = httpMock.expectOne('/api/v1/organizations/org-1/overview');

    // A new session begins while that read is in flight.
    const signIn = auth.login(USER.email, 'correct horse');
    httpMock.expectOne('/api/v1/auth/login').flush({ mfa_required: false, user: USER });
    await signIn;

    stale.flush({ detail: 'Not authenticated' }, { status: 401, statusText: 'Unauthorized' });
    await pending;

    expect(auth.isAuthenticated()).toBe(true);
    expect(navigations).toEqual([]);
  });

  it('forgets what the signed-out session owned, not just its authentication', async () => {
    // The organization list and the notification feed were read as that user,
    // for organizations the next one may not be able to see.
    const organizations = TestBed.inject(OrganizationContextService);
    const notifications = TestBed.inject(NotificationService);
    auth.applyUser(USER);
    const loaded = organizations.load();
    httpMock.expectOne('/api/v1/organizations').flush({
      items: [{ id: 'org-1', name: 'Northwind Retail' }],
      total: 1,
    });
    await loaded;
    const feed = notifications.load('org-1');
    httpMock
      .expectOne((candidate) => candidate.url === '/api/v1/organizations/org-1/notifications')
      .flush({ items: [{ id: 'n1', read_at: null }], total: 1, unread: 1 });
    await feed;
    expect(organizations.all().length).toBe(1);
    expect(notifications.items().length).toBe(1);

    await fail('/api/v1/organizations/org-1/overview');

    expect(organizations.all()).toEqual([]);
    expect(notifications.items()).toEqual([]);
    expect(notifications.unread()).toBe(0);
  });

  it('passes other failures through untouched', async () => {
    auth.applyUser(USER);

    await fail('/api/v1/organizations/org-1/overview', 403);

    expect(auth.isAuthenticated()).toBe(true);
    expect(navigations).toEqual([]);
  });
});
