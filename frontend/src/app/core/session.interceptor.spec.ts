import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';

import { AuthService, CurrentUser } from './auth.service';
import { NotificationService } from './notification.service';
import { OrganizationContextService } from './organization-context.service';
import { sessionInterceptor } from './session.interceptor';
import { StepUpService } from './step-up.service';

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

  it('discards a read that answers after the session it belonged to ended', async () => {
    // Clearing the signals is not enough: a successful read still in flight
    // would repopulate them, possibly under whoever signs in next.
    const organizations = TestBed.inject(OrganizationContextService);
    auth.applyUser(USER);
    const loading = organizations.load();
    const inFlight = httpMock.expectOne('/api/v1/organizations');

    await fail('/api/v1/organizations/org-1/overview');
    expect(organizations.all()).toEqual([]);

    inFlight.flush({ items: [{ id: 'org-1', name: 'Northwind Retail' }], total: 1 });
    await loading;

    expect(organizations.all()).toEqual([]);
  });

  it('passes other failures through untouched', async () => {
    auth.applyUser(USER);

    await fail('/api/v1/organizations/org-1/overview', 403);

    expect(auth.isAuthenticated()).toBe(true);
    expect(navigations).toEqual([]);
  });

  // ------------------------------------------------------------- step-up

  const STEP_UP_DETAIL = 'Confirm your authenticator code again before continuing';

  /** Let the promises the interceptor is waiting on settle. */
  async function settle(): Promise<void> {
    for (let turn = 0; turn < 8; turn += 1) {
      await Promise.resolve();
    }
  }

  it('collects a code and sends the refused request again', async () => {
    auth.applyUser(USER);
    const stepUp = TestBed.inject(StepUpService);
    const url = '/api/v1/organizations';
    const answered = new Promise((resolve) => http.post(url, {}).subscribe({ next: resolve, error: resolve }));

    httpMock
      .expectOne(url)
      .flush({ detail: STEP_UP_DETAIL }, { status: 403, statusText: 'Forbidden' });
    await settle();

    // The session is still good; it just has not confirmed a code recently.
    expect(stepUp.asking()).toBe(true);
    expect(auth.isAuthenticated()).toBe(true);
    expect(navigations).toEqual([]);

    const confirming = stepUp.submit('123456');
    httpMock.expectOne('/api/v1/account/mfa/step-up').flush({
      verified_at: '2026-09-08T12:00:00Z',
      expires_at: '2026-09-08T12:10:00Z',
    });
    await confirming;
    await settle();

    // The request the person actually made is retried, not abandoned.
    httpMock.expectOne(url).flush({ id: 'org-1' });
    expect(await answered).toEqual({ id: 'org-1' });
    expect(stepUp.asking()).toBe(false);
  });

  it('asks once when several requests are refused together', async () => {
    auth.applyUser(USER);
    const stepUp = TestBed.inject(StepUpService);
    const first = new Promise((r) => http.post('/api/v1/ai/settings', {}).subscribe({ next: r, error: r }));
    const second = new Promise((r) => http.post('/api/v1/organizations', {}).subscribe({ next: r, error: r }));

    httpMock
      .expectOne('/api/v1/ai/settings')
      .flush({ detail: STEP_UP_DETAIL }, { status: 403, statusText: 'Forbidden' });
    httpMock
      .expectOne('/api/v1/organizations')
      .flush({ detail: STEP_UP_DETAIL }, { status: 403, statusText: 'Forbidden' });
    await settle();

    expect(stepUp.asking()).toBe(true);

    const confirming = stepUp.submit('123456');
    httpMock.expectOne('/api/v1/account/mfa/step-up').flush({
      verified_at: '2026-09-08T12:00:00Z',
      expires_at: '2026-09-08T12:10:00Z',
    });
    await confirming;
    await settle();

    // One code, both requests continue.
    httpMock.expectOne('/api/v1/ai/settings').flush({});
    httpMock.expectOne('/api/v1/organizations').flush({});
    await first;
    await second;
  });

  it('gives the caller its refusal when the prompt is dismissed', async () => {
    auth.applyUser(USER);
    const stepUp = TestBed.inject(StepUpService);
    const answered = request('/api/v1/organizations');

    httpMock
      .expectOne('/api/v1/organizations')
      .flush({ detail: STEP_UP_DETAIL }, { status: 403, statusText: 'Forbidden' });
    await settle();

    stepUp.dismiss();

    expect((await answered as { status: number }).status).toBe(403);
  });

  it('leaves other refusals alone', async () => {
    // 403 is also how a role, a wrong password and a historical write are
    // refused, and a code helps with none of them.
    auth.applyUser(USER);
    const stepUp = TestBed.inject(StepUpService);
    const pending = request('/api/v1/organizations');

    httpMock
      .expectOne('/api/v1/organizations')
      .flush({ detail: 'Administrator role required' }, { status: 403, statusText: 'Forbidden' });
    await pending;
    await settle();

    expect(stepUp.asking()).toBe(false);
  });

  it('does not hold a request across a session boundary', async () => {
    // The prompt and the request behind it belong to the session that is
    // ending. Left waiting, the prompt would come back for whoever signs in
    // next and replay this request on their code.
    auth.applyUser(USER);
    const stepUp = TestBed.inject(StepUpService);
    const answered = request('/api/v1/organizations');

    httpMock
      .expectOne('/api/v1/organizations')
      .flush({ detail: STEP_UP_DETAIL }, { status: 403, statusText: 'Forbidden' });
    await settle();
    expect(stepUp.asking()).toBe(true);

    // A 401 anywhere signs the session out, and the reset runs.
    await fail('/api/v1/organizations/org-1/overview');
    await settle();

    expect(stepUp.asking()).toBe(false);
    expect((await answered as { status: number }).status).toBe(403);
    // Nothing is left to replay: the retry never happens.
    httpMock.verify();
  });

  it('does not put a previous session refusal in front of the next one', async () => {
    // A refusal can arrive long after the session that asked for it has ended.
    // Prompting then asks whoever signed in since for a code, to release a
    // request that was never theirs.
    auth.applyUser(USER);
    const abandoned = request('/api/v1/organizations');
    const refused = httpMock.expectOne('/api/v1/organizations');

    // The session ends and another begins while the request is in flight.
    await fail('/api/v1/organizations/org-1/overview');
    auth.applyUser(USER);
    await settle();

    refused.flush({ detail: STEP_UP_DETAIL }, { status: 403, statusText: 'Forbidden' });
    await settle();

    expect(TestBed.inject(StepUpService).asking()).toBe(false);
    expect((await abandoned as { status: number }).status).toBe(403);
  });
});
