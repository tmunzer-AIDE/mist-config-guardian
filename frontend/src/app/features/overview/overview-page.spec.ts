import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';

import { AuthService } from '../../core/auth.service';
import { OrganizationContextService } from '../../core/organization-context.service';
import { OrganizationOverview } from '../../core/overview.service';
import { TimeContextService } from '../../core/time-context.service';
import { OverviewPage } from './overview-page';

const ORGANIZATION_ID = 'org-1';
const OVERVIEW_URL = `/api/v1/organizations/${ORGANIZATION_ID}/overview`;

const organizationStub = {
  selected: signal({ id: ORGANIZATION_ID, name: 'Northwind Retail', status: 'verified' }),
};

function overview(overrides: Partial<OrganizationOverview> = {}): OrganizationOverview {
  return {
    generated_at: '2026-09-08T09:00:00Z',
    range_start: '2026-09-07T09:00:00Z',
    range_end: '2026-09-08T09:00:00Z',
    counts: {
      change_groups: 0,
      impacting: 0,
      mine: 0,
      unrecovered: 0,
      pending_approvals: 0,
      failed_restores: 0,
    },
    change_groups: [],
    safety_net: [{ key: 'backup', label: 'Backup 4m behind', status: 'ok', detail: '14:18Z' }],
    pending_approvals: [],
    failed_restores: [],
    latest_snapshot_at: null,
    latest_snapshot_objects: null,
    ...overrides,
  };
}

describe('OverviewPage under time travel', () => {
  let fixture: ComponentFixture<OverviewPage>;
  let httpMock: HttpTestingController;
  let time: TimeContextService;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [OverviewPage],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: OrganizationContextService, useValue: organizationStub as unknown as OrganizationContextService },
        { provide: AuthService, useValue: { can: () => true } },
      ],
    }).compileComponents();
    httpMock = TestBed.inject(HttpTestingController);
    time = TestBed.inject(TimeContextService);
    time.returnToNow();
    fixture = TestBed.createComponent(OverviewPage);
  });

  afterEach(() => {
    time.returnToNow();
    httpMock.verify();
  });

  function text(selector: string): string[] {
    return Array.from((fixture.nativeElement as HTMLElement).querySelectorAll(selector)).map((node) =>
      (node.textContent ?? '').replace(/\s+/g, ' ').trim(),
    );
  }

  it('reads live state at now, safety net included', async () => {
    fixture.detectChanges();
    await fixture.whenStable();
    const request = httpMock.expectOne((candidate) => candidate.url === OVERVIEW_URL);
    expect(request.request.params.has('as_of')).toBe(false);
    request.flush(overview());
    await fixture.whenStable();
    fixture.detectChanges();

    expect(text('.safety-row')).toEqual(['Backup 4m behind 14:18Z']);
    expect(text('.panel-note')).toEqual([]);
  });

  it('asks the server for the past and shows nothing that only has a present', async () => {
    // The banner alone is not time travel: the read has to end at the instant,
    // and today's approvals, failures and safety net must not sit under a
    // past date as if they were its.
    const instant = new Date('2026-09-01T12:00:00Z');
    time.setAsOf(instant);
    fixture.detectChanges();
    await fixture.whenStable();
    const request = httpMock.expectOne((candidate) => candidate.url === OVERVIEW_URL);
    expect(request.request.params.get('as_of')).toBe(instant.toISOString());
    request.flush(overview({ safety_net: [], historical: true }));
    await fixture.whenStable();
    fixture.detectChanges();

    expect(text('.safety-row')).toEqual([]);
    expect(text('.panel-note')[0]).toContain('live and has no past');
  });

  it('re-reads when the instant moves', async () => {
    fixture.detectChanges();
    await fixture.whenStable();
    httpMock.expectOne((candidate) => candidate.url === OVERVIEW_URL).flush(overview());
    await fixture.whenStable();

    time.setAsOf(new Date('2026-09-02T12:00:00Z'));
    fixture.detectChanges();
    await fixture.whenStable();

    const again = httpMock.expectOne((candidate) => candidate.url === OVERVIEW_URL);
    expect(again.request.params.get('as_of')).toBe('2026-09-02T12:00:00.000Z');
    again.flush(overview({ historical: true }));
    await fixture.whenStable();
  });
});
