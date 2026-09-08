import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';

import { AccountService } from '../features/account/account.service';
import { AuthService, CurrentUser } from '../core/auth.service';
import { NotificationService } from '../core/notification.service';
import { OrganizationContextService } from '../core/organization-context.service';
import { TimeContextService } from '../core/time-context.service';
import { AppHeader } from './app-header';

const USER: CurrentUser = {
  id: 'user-a',
  email: 'a.osei@northwind.example',
  display_name: 'Ama Osei',
  role: 'administrator',
  is_active: true,
  status: 'active',
  preferences: { timezone: 'UTC', clock: '24h', landing_page: 'overview' },
  mfa_enabled: false,
  passkey_count: 0,
};

describe('AppHeader sign-out', () => {
  let fixture: ComponentFixture<AppHeader>;
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AppHeader],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        {
          provide: Router,
          useValue: { url: '/changes', navigate: () => Promise.resolve(true) },
        },
      ],
    }).compileComponents();
    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(AppHeader);
    fixture.detectChanges();
  });

  afterEach(() => httpMock.verify());

  it('forgets everything the signed-out session owned, not only the organizations', async () => {
    // User A's notifications are per-user. After they sign out, user B signing
    // into the same organization must not see them in the drawer.
    const auth = TestBed.inject(AuthService);
    const organizations = TestBed.inject(OrganizationContextService);
    const notifications = TestBed.inject(NotificationService);
    const time = TestBed.inject(TimeContextService);
    auth.applyUser(USER);
    const loaded = organizations.load();
    httpMock.expectOne('/api/v1/organizations').flush({
      items: [{ id: 'org-1', name: 'Northwind Retail' }],
      total: 1,
    });
    await loaded;
    const feed = notifications.load('org-1');
    httpMock
      .expectOne((request) => request.url === '/api/v1/organizations/org-1/notifications')
      .flush({ items: [{ id: 'n-a', read_at: null }], total: 1, unread: 1 });
    await feed;
    time.setAsOf(new Date('2026-09-01T00:00:00Z'));

    const signOut = (fixture.componentInstance as unknown as { signOut: () => Promise<void> }).signOut();
    httpMock.expectOne('/api/v1/auth/logout').flush({});
    await signOut;

    expect(auth.isAuthenticated()).toBe(false);
    expect(organizations.all()).toEqual([]);
    expect(notifications.items()).toEqual([]);
    expect(notifications.unread()).toBe(0);
    // Historical mode belonged to that session too.
    expect(time.isHistorical()).toBe(false);
  });

  it('forgets the session even when the server cannot be told', async () => {
    // The logout request can fail — offline, or refused. The session is over on
    // this device either way, and leaving the user in a shell full of their
    // caches is the worse outcome.
    const auth = TestBed.inject(AuthService);
    const organizations = TestBed.inject(OrganizationContextService);
    auth.applyUser(USER);
    const loaded = organizations.load();
    httpMock.expectOne('/api/v1/organizations').flush({
      items: [{ id: 'org-1', name: 'Northwind Retail' }],
      total: 1,
    });
    await loaded;

    const signOut = (fixture.componentInstance as unknown as { signOut: () => Promise<void> }).signOut();
    httpMock.expectOne('/api/v1/auth/logout').flush({ detail: 'boom' }, { status: 500, statusText: 'Server Error' });
    await signOut;

    expect(auth.isAuthenticated()).toBe(false);
    expect(organizations.all()).toEqual([]);
  });

  it('discards an account response that outlived the session that asked', async () => {
    // A profile update from the user leaving would otherwise be merged into
    // whoever signs in next: their name, their email, their preferences.
    const auth = TestBed.inject(AuthService);
    const account = TestBed.inject(AccountService);
    auth.applyUser(USER);
    const updating = account.updateProfile({ display_name: 'Ama Osei' });
    const inFlight = httpMock.expectOne('/api/v1/account/profile');

    const signOut = (fixture.componentInstance as unknown as { signOut: () => Promise<void> }).signOut();
    httpMock.expectOne('/api/v1/auth/logout').flush({});
    await signOut;

    // User B signs in, and only now does user A's update answer.
    auth.applyUser({ ...USER, id: 'user-b', email: 'b@northwind.example', display_name: 'Bea' });
    inFlight.flush({
      id: USER.id,
      email: USER.email,
      display_name: 'Ama Osei',
      role: 'administrator',
      is_active: true,
      status: 'active',
      preferences: { timezone: 'UTC', clock: '24h', landing_page: 'overview' },
      mfa_enabled: false,
      passkey_count: 0,
      pending_email_change: null,
      password_changed_at: null,
      last_login_at: null,
    });
    await updating;

    expect(auth.user()?.email).toBe('b@northwind.example');
    expect(auth.user()?.display_name).toBe('Bea');
  });
});
