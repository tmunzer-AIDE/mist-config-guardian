import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';

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
});
