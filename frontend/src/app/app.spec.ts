import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';

import { AuthService, CurrentUser } from './core/auth.service';
import { OrganizationContextService } from './core/organization-context.service';
import { OverviewService } from './core/overview.service';
import { TimeContextService } from './core/time-context.service';
import { TimelineService } from './core/timeline.service';

const USER: CurrentUser = {
  id: 'user-1',
  email: 'j.mercer@northwind.example',
  display_name: 'Jo Mercer',
  role: 'operator',
  is_active: true,
  status: 'active',
  preferences: { timezone: 'UTC', clock: '24h', landing_page: 'overview' },
  mfa_enabled: false,
  passkey_count: 0,
};

import { App } from './app';

describe('App shell', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [App],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    }).compileComponents();
  });

  it('creates', () => {
    expect(TestBed.createComponent(App).componentInstance).toBeTruthy();
  });

  it('hides the application chrome until a session is resolved', async () => {
    const fixture = TestBed.createComponent(App);
    await fixture.whenStable();
    const element = fixture.nativeElement as HTMLElement;
    expect(element.querySelector('app-sidebar')).toBeNull();
    expect(element.querySelector('app-header')).toBeNull();
  });

  describe('outcome data on the shell', () => {
    let httpMock: HttpTestingController;
    let timeline: TimelineService;
    let overview: OverviewService;
    let time: TimeContextService;
    let fixture: ComponentFixture<App>;

    /**
     * Drain the promise chain a response starts, then render what it produced.
     *
     * The shell's reads are wrapped in `Promise.allSettled` inside an effect,
     * so a flushed answer lands several turns later.
     */
    async function settle(): Promise<void> {
      for (let turn = 0; turn < 12; turn += 1) {
        await Promise.resolve();
      }
      fixture.detectChanges();
      await fixture.whenStable();
    }

    /** Answer whatever the shell asks for, and report the marker read. */
    function answer(organizationId: string, unrecovered: number): void {
      for (const request of httpMock.match(() => true)) {
        const { url } = request.request;
        if (url.endsWith('/point-in-time/markers')) {
          request.flush({
            items: [
              {
                at: '2026-09-08T09:00:00Z',
                severity: 'critical',
                impact_known: true,
                change_group_id: 'g1',
                label: 'RF template reassigned',
              },
            ],
            range_start: '2026-09-07T09:00:00Z',
            range_end: '2026-09-08T09:00:00Z',
          });
        } else if (url === `/api/v1/organizations/${organizationId}/overview`) {
          request.flush({ counts: { unrecovered } });
        } else {
          request.flush({});
        }
      }
    }

    beforeEach(async () => {
      httpMock = TestBed.inject(HttpTestingController);
      timeline = TestBed.inject(TimelineService);
      overview = TestBed.inject(OverviewService);
      time = TestBed.inject(TimeContextService);
      time.returnToNow();
      time.setRange('24h');
      TestBed.inject(AuthService).applyUser(USER);

      fixture = TestBed.createComponent(App);
      fixture.detectChanges();
      await fixture.whenStable();
      httpMock.expectOne('/api/v1/organizations').flush({
        items: [
          { id: 'org-1', name: 'Northwind Retail' },
          { id: 'org-2', name: 'Contoso' },
        ],
        total: 2,
      });
      // The organization list resolves a few turns after its flush, and the
      // scope effect only issues its reads once a selection exists.
      await settle();
      answer('org-1', 4);
      await settle();
      expect(timeline.markers().length).toBe(1);
      expect(overview.unrecovered()).toBe(4);
    });

    afterEach(() => {
      for (const request of httpMock.match(() => true)) {
        request.flush({});
      }
    });

    it('drops the previous window as soon as the range moves', async () => {
      // The old markers describe a track that is about to be rescaled, and
      // the badge counted a window nobody is looking at any more.
      time.setRange('7d');
      fixture.detectChanges();

      expect(timeline.markers()).toEqual([]);
      expect(overview.unrecovered()).toBe(0);
    });

    it('drops the previous organization the moment it changes', async () => {
      TestBed.inject(OrganizationContextService).select('org-2');
      fixture.detectChanges();

      expect(timeline.markers()).toEqual([]);
      expect(overview.unrecovered()).toBe(0);
    });

    it('reads the badge over the window the Changes link shows', async () => {
      time.setRange('7d');
      fixture.detectChanges();
      await settle();

      const badge = httpMock.match(
        (request) => request.url === '/api/v1/organizations/org-1/overview',
      )[0];
      expect(badge.request.params.get('range')).toBe('7d');
    });
  });
});
