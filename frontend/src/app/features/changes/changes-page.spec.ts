import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting, TestRequest } from '@angular/common/http/testing';
import { signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';

import { ChangeGroupDetail, ChangeGroupSummary, ImpactSeverity } from '../../core/change-group.model';
import { OrganizationContextService } from '../../core/organization-context.service';
import { ChangesPage } from './changes-page';

const ORGANIZATION_ID = 'org-1';
const INDEX_URL = `/api/v1/organizations/${ORGANIZATION_ID}/change-groups`;

/** Only `selected()` is read by the page, so the context is stubbed rather than
 *  driven through the organization list endpoint. */
const organizationStub = {
  selected: signal<{ id: string; name: string; status: string } | null>({
    id: ORGANIZATION_ID,
    name: 'Northwind Retail',
    status: 'verified',
  }),
};

function summary(
  id: string,
  occurredAt: string,
  severity: ImpactSeverity,
  overrides: Partial<ChangeGroupSummary> = {},
): ChangeGroupSummary {
  return {
    id,
    audit_id: `9f2a0000-0000-0000-0000-0000000000${id.slice(-2)}`,
    actor: 'j.mercer',
    source: 'webhook',
    occurred_at: occurredAt,
    title: `Change ${id}`,
    summary: 'Summary line',
    object_count: 2,
    device_count: 6,
    affected_site_ids: ['site-1'],
    devices_label: '6 APs · Seattle-DC',
    impact_severity: severity,
    recovery_state: severity === 'critical' ? 'unrecovered' : 'completed',
    impact_label: severity === 'critical' ? 'CRITICAL −29' : 'NO IMPACT',
    degraded_metrics: [],
    metrics: [],
    monitoring_session_ids: ['session-1'],
    is_mine: false,
    ...overrides,
  };
}

function detail(base: ChangeGroupSummary): ChangeGroupDetail {
  return {
    ...base,
    message: null,
    method: 'PUT',
    baseline_confidence: 'high',
    deterministic_assessment: 'Capacity fell 29 points across 6 of 6 monitored APs.',
    evidence: [{ label: 'Degraded metrics: capacity', severity: 'critical' }],
    changed_objects: [
      {
        logical_object_id: 'obj-1',
        object_type: 'wlan',
        object_name: 'NW-Corp',
        scope: 'org',
        site_mist_id: null,
        event: 'updated',
        before_version_id: 'v14',
        after_version_id: 'v15',
        before_version: 14,
        after_version: 15,
        changed_fields: ['rf_template_id', 'band_steer'],
      },
    ],
    affected_devices: [],
    competing_change_group_ids: [],
  };
}

/** Monday 07 Sep and Sunday 06 Sep 2026, the two days the design shows. */
const MONDAY_CRITICAL = summary('cg1', '2026-09-07T09:12:00Z', 'critical');
const MONDAY_WARNING = summary('cg2', '2026-09-07T05:41:00Z', 'warning');
const SUNDAY_NONE = summary('cg3', '2026-09-06T22:03:00Z', 'none');

describe('ChangesPage', () => {
  let fixture: ComponentFixture<ChangesPage>;
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    // The stub is shared across tests; one that switches organization must not
    // leak that into the next.
    organizationStub.selected.set({ id: ORGANIZATION_ID, name: 'Northwind Retail', status: 'verified' });
    await TestBed.configureTestingModule({
      imports: [ChangesPage],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        {
          provide: OrganizationContextService,
          useValue: organizationStub as unknown as OrganizationContextService,
        },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(ChangesPage);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  /** Run the page's initial fetch and answer it with `items`. */
  async function load(items: ChangeGroupSummary[]): Promise<TestRequest> {
    fixture.detectChanges();
    await fixture.whenStable();
    const request = httpMock.expectOne((candidate) => candidate.url === INDEX_URL);
    request.flush({ items, total: items.length });
    await fixture.whenStable();
    fixture.detectChanges();
    return request;
  }

  function text(selector: string): string[] {
    const element = fixture.nativeElement as HTMLElement;
    return Array.from(element.querySelectorAll(selector)).map((node) => (node.textContent ?? '').trim());
  }

  it('groups rows under a day separator that counts the day and its criticals', async () => {
    await load([MONDAY_CRITICAL, MONDAY_WARNING, SUNDAY_NONE]);

    expect(text('.day')).toEqual(['MON 07 SEP · 2 GROUPS · 1 CRITICAL', 'SUN 06 SEP · 1 GROUP']);
    expect(text('.row--group').length).toBe(3);
  });

  it('sends the range and the default impact filter with the initial fetch', async () => {
    const request = await load([MONDAY_CRITICAL]);

    expect(request.request.params.get('range')).toBe('24h');
    expect(request.request.params.get('severity')).toBe('any');
    // Not historical, so no point-in-time reconstruction is requested.
    expect(request.request.params.has('as_of')).toBe(false);
  });

  it('refetches server-side when an impact chip is chosen and marks it pressed', async () => {
    await load([MONDAY_CRITICAL, MONDAY_WARNING, SUNDAY_NONE]);

    const element = fixture.nativeElement as HTMLElement;
    const chips = Array.from(element.querySelectorAll<HTMLButtonElement>('.head-filters .cg-chip'));
    expect(chips.map((chip) => chip.textContent?.trim())).toEqual([
      'Impact: any',
      'Critical',
      'Warning',
      'No impact',
    ]);

    chips[1].click();
    await fixture.whenStable();

    const refetch = httpMock.expectOne((candidate) => candidate.url === INDEX_URL);
    expect(refetch.request.params.get('severity')).toBe('critical');
    refetch.flush({ items: [MONDAY_CRITICAL], total: 3 });
    await fixture.whenStable();
    fixture.detectChanges();

    expect(chips[1].getAttribute('aria-pressed')).toBe('true');
    expect(chips[0].getAttribute('aria-pressed')).toBe('false');
    expect(text('.row--group').length).toBe(1);
    expect(text('.table-foot')).toEqual(['Showing 1 of 3 · click a row for evidence']);
  });

  it('pre-selects the row named by ?group= and opens its detail panel', async () => {
    fixture.componentRef.setInput('group', MONDAY_WARNING.id);
    await load([MONDAY_CRITICAL, MONDAY_WARNING, SUNDAY_NONE]);

    const detailRequest = httpMock.expectOne(`${INDEX_URL}/${MONDAY_WARNING.id}`);
    detailRequest.flush(detail(MONDAY_WARNING));
    await fixture.whenStable();
    fixture.detectChanges();

    const element = fixture.nativeElement as HTMLElement;
    const selected = element.querySelectorAll('.row--group.row--on');
    expect(selected.length).toBe(1);
    expect(selected[0].getAttribute('aria-expanded')).toBe('true');
    expect(text('.panel-title')).toEqual([MONDAY_WARNING.title]);
    expect(text('.object-name')).toEqual(['NW-Corp']);
    expect(text('.object-versions')).toEqual(['v14 → v15']);
  });

  it('shows the organization empty state when nothing matches an unfiltered window', async () => {
    await load([]);

    expect(text('.empty-title')).toEqual(['No changes in this window']);
    expect(text('.table-foot')).toEqual(['No change groups in this window']);
  });

  it('keeps a group linked before any organization was established', async () => {
    // A bookmarked, searched or notified link opens cold: the query parameter
    // is bound before the organization list has loaded. The organization that
    // then loads is the one the link was written under.
    organizationStub.selected.set(null);
    fixture.componentRef.setInput('group', MONDAY_WARNING.id);
    fixture.detectChanges();
    await fixture.whenStable();
    httpMock.expectNone((candidate) => candidate.url.startsWith('/api/v1/organizations/'));

    organizationStub.selected.set({ id: ORGANIZATION_ID, name: 'Northwind Retail', status: 'verified' });
    await load([MONDAY_CRITICAL, MONDAY_WARNING]);
    httpMock.expectOne(`${INDEX_URL}/${MONDAY_WARNING.id}`).flush(detail(MONDAY_WARNING));
    await fixture.whenStable();
    fixture.detectChanges();

    expect(text('.panel-title')).toEqual([MONDAY_WARNING.title]);
  });

  it('drops a selected group, and its parameter, when the organization changes', async () => {
    // The group belongs to the organization it was selected under. Under
    // another it would show cached detail and issue a read that can only fail.
    const router = TestBed.inject(Router);
    const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true);
    fixture.componentRef.setInput('group', MONDAY_WARNING.id);
    await load([MONDAY_CRITICAL, MONDAY_WARNING]);
    httpMock.expectOne(`${INDEX_URL}/${MONDAY_WARNING.id}`).flush(detail(MONDAY_WARNING));
    await fixture.whenStable();
    fixture.detectChanges();
    expect(text('.panel-title')).toEqual([MONDAY_WARNING.title]);

    organizationStub.selected.set({ id: 'org-2', name: 'Contoso', status: 'verified' });
    fixture.detectChanges();
    await fixture.whenStable();
    httpMock
      .expectOne((candidate) => candidate.url === '/api/v1/organizations/org-2/change-groups')
      .flush({ items: [], total: 0 });
    await fixture.whenStable();
    fixture.detectChanges();

    httpMock.expectNone(`/api/v1/organizations/org-2/change-groups/${MONDAY_WARNING.id}`);
    expect(text('.panel-title')).toEqual([]);
    expect(navigate).toHaveBeenCalledWith([], {
      queryParams: { group: null },
      queryParamsHandling: 'merge',
      replaceUrl: true,
    });
  });

  it('opens the selected change in site Impact without the legacy session parameter', async () => {
    const navigate = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    fixture.componentRef.setInput('group', MONDAY_WARNING.id);
    await load([MONDAY_WARNING]);
    httpMock.expectOne(`${INDEX_URL}/${MONDAY_WARNING.id}`).flush(detail(MONDAY_WARNING));
    await fixture.whenStable();
    fixture.detectChanges();

    const button = fixture.nativeElement.querySelector('.panel-actions .cg-btn--primary') as HTMLButtonElement;
    expect(button.textContent).toContain('Open site impact');
    button.click();
    expect(navigate).toHaveBeenCalledWith(['/impact'], {
      queryParams: { site: 'site-1', change: MONDAY_WARNING.id },
    });
  });

  it('offers each affected site once, including changes without a monitoring session', async () => {
    const navigate = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    fixture.componentRef.setInput('group', MONDAY_WARNING.id);
    await load([MONDAY_WARNING]);
    const group = detail({ ...MONDAY_WARNING, affected_site_ids: ['site-1', 'site-2', 'site-1'], monitoring_session_ids: [] });
    httpMock.expectOne(`${INDEX_URL}/${MONDAY_WARNING.id}`).flush(group);
    await fixture.whenStable();
    fixture.detectChanges();

    const buttons = fixture.nativeElement.querySelectorAll('.panel-actions .cg-btn--primary') as NodeListOf<HTMLButtonElement>;
    expect(buttons.length).toBe(2);
    expect(buttons[1].textContent).toContain('site-2');
    buttons[1].click();
    expect(navigate).toHaveBeenCalledWith(['/impact'], {
      queryParams: { site: 'site-2', change: MONDAY_WARNING.id },
    });
  });

  it('compares a changed object under the slot names History reads', async () => {
    const router = TestBed.inject(Router);
    const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true);
    fixture.componentRef.setInput('group', MONDAY_WARNING.id);
    await load([MONDAY_WARNING]);
    httpMock.expectOne(`${INDEX_URL}/${MONDAY_WARNING.id}`).flush(detail(MONDAY_WARNING));
    await fixture.whenStable();
    fixture.detectChanges();

    const element = fixture.nativeElement as HTMLElement;
    element.querySelector<HTMLButtonElement>('.object-compare')?.click();

    // History names its two slots `a` and `b`, with A the earlier side; sending
    // `before` and `after` would open an unselected comparison.
    expect(navigate).toHaveBeenCalledWith(['/history'], {
      queryParams: { object: 'obj-1', a: 'v14', b: 'v15' },
    });
  });

  it('narrows the fetch to the actor named by ?actor= and offers a way out', async () => {
    const router = TestBed.inject(Router);
    const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true);
    fixture.componentRef.setInput('actor', 'j.mercer');

    const request = await load([MONDAY_CRITICAL]);

    expect(request.request.params.get('actor')).toBe('j.mercer');
    const chip = (fixture.nativeElement as HTMLElement).querySelector<HTMLButtonElement>(
      '.head-filters .cg-chip:last-child',
    );
    expect(chip?.textContent?.trim().startsWith('Actor: j.mercer')).toBe(true);

    chip?.click();

    expect(navigate).toHaveBeenCalledWith([], {
      queryParams: { actor: null },
      queryParamsHandling: 'merge',
      replaceUrl: true,
    });
  });

  it('does not offer an actor chip when no actor is named', async () => {
    await load([MONDAY_CRITICAL]);

    expect(text('.head-filters .cg-chip')).toEqual([
      'Impact: any',
      'Critical',
      'Warning',
      'No impact',
    ]);
  });
  it('shows the shadow projection alongside the production badge without changing its filter', async () => {
    const request = await load([{ ...MONDAY_CRITICAL, impact_source: 'legacy', shadow_impact: {
      mode: 'shadow', assessment_source: 'audit_investigation', result: 'insufficient_evidence',
      investigation_id: 'i1', report_id: 'r3', revision: 3, status: 'monitoring', stop_reason: '',
      policy_version: 'wlan-removal.v1', evaluated_at: '2026-09-07T09:22:00Z',
      impact: 'info', confidence: 'low', coverage: 'partial', gap_count: 1, unmapped_count: 2,
    } }]);
    expect(text('.cell-impact .cg-badge')).toEqual(['CRITICAL −29']);
    expect(text('app-audit-impact-summary')[0]).toContain('Shadow · Insufficient evidence');
    expect(text('app-audit-impact-summary')[0]).toContain('Confidence: low');
    expect(text('app-audit-impact-summary')[0]).toContain('Revision 3');
    expect(request.request.params.get('severity')).toBe('any');
    expect(text('.head-sub').join(' ')).toContain('filters and alerts still use the legacy assessment');
  });

});
