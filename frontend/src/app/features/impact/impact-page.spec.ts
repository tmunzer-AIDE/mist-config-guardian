import { signal } from '@angular/core';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ActivatedRoute, Router } from '@angular/router';

import { AuthService } from '../../core/auth.service';
import { OrganizationContextService } from '../../core/organization-context.service';
import { TimeContextService } from '../../core/time-context.service';
import { ImpactPage } from './impact-page';
import {
  MonitoringSession,
  changeMarkerPercent,
  filterSessions,
  metricDeltas,
  primaryMetric,
  readAiAssessment,
  sleSeries,
  axisFor,
} from './monitoring.model';
import { MonitoringService } from './monitoring.service';

interface Navigation {
  commands: unknown[];
  extras: Record<string, unknown> | undefined;
}

function session(overrides: Partial<MonitoringSession> = {}): MonitoringSession {
  return {
    id: 's1',
    audit_ids: ['9f2a1111-2222-3333-4444-555566667c41'],
    site_id: 'Seattle-DC',
    device_mac: '5c:5b:35:1a:2b:a1',
    device_name: 'SEA-AP-101',
    device_type: 'AP45',
    status: 'monitoring',
    baseline: null,
    observations: [],
    incidents: [],
    config_applied_at: '2026-09-07T09:14:00Z',
    monitoring_started_at: '2026-09-07T09:14:00Z',
    monitoring_ends_at: null,
    impact_severity: 'none',
    deterministic_summary: null,
    degraded_metrics: [],
    ai_assessment: null,
    ai_assessment_error: null,
    warnings: [],
    created_at: '2026-09-07T09:14:00Z',
    completed_at: null,
    ...overrides,
  };
}

it('uses stored selected comparisons instead of recomputing unrelated raw SLEs', () => {
  const value = session({
    baseline: { captured_at: '', values: { 'ap-health': 99 }, errors: [] },
    observations: [{ captured_at: '', values: { 'ap-health': 0 }, errors: [] }],
    assessment: { severity: 'none', summary: 'Selected evidence stable', coverage: 'complete', metrics: [
      { name: 'ap-health', baseline: 99, latest: 0, delta: -99, selected: false, comparable: true },
      { name: 'successful-connect', baseline: 99, latest: 99, delta: 0, selected: true, comparable: true },
    ] },
  });
  expect(metricDeltas(value).map((metric) => metric.key)).toEqual(['successful-connect']);
  expect(primaryMetric(value)).toBe('successful-connect');
  value.assessment!.metrics = [];
  expect(metricDeltas(value)).toEqual([]);
  expect(primaryMetric(value)).toBeNull();
});

/** A critical session with a baseline, two pre-change and two post-change samples. */
const CRITICAL = session({
  id: 's1',
  impact_severity: 'critical',
  status: 'monitoring',
  degraded_metrics: ['capacity'],
  deterministic_summary: 'Capacity fell 28 points immediately after the RF template reassignment.',
  change_group_id: 'cg1',
  baseline_confidence: 'high',
  baseline: {
    captured_at: '2026-09-07T08:14:00Z',
    values: { capacity: 41, coverage: 95 },
    errors: [],
  },
  observations: [
    { captured_at: '2026-09-07T08:44:00Z', values: { capacity: 40, coverage: 95 }, errors: [] },
    { captured_at: '2026-09-07T09:44:00Z', values: { capacity: 12, coverage: 94 }, errors: [] },
    { captured_at: '2026-09-07T10:14:00Z', values: { capacity: 13, coverage: 94 }, errors: [] },
  ],
  ai_assessment: { explanation: 'Four usable 5 GHz channels for six co-located APs.' },
});

/** A quiet completed session that never had an AI assessment. */
const QUIET = session({
  id: 's2',
  device_name: 'SEA-AP-114',
  device_mac: '5c:5b:35:1a:2b:c4',
  status: 'completed',
  impact_severity: 'none',
  baseline_confidence: 'high',
  change_group_id: 'cg3',
  deterministic_summary: 'No monitored metric moved beyond the noise band during the window.',
  completed_at: '2026-09-07T06:18:00Z',
  monitoring_ends_at: '2026-09-07T06:18:00Z',
  baseline: {
    captured_at: '2026-09-07T02:18:00Z',
    values: { 'time-to-connect': 91 },
    errors: [],
  },
  observations: [
    { captured_at: '2026-09-07T05:18:00Z', values: { 'time-to-connect': 91 }, errors: [] },
  ],
  ai_assessment: null,
});

/** A failed session that never produced a single observation. */
const BLANK = session({
  id: 's3',
  device_name: 'SEA-AP-118',
  device_mac: '5c:5b:35:1a:2b:cc',
  status: 'failed',
  impact_severity: 'info',
  deterministic_summary:
    'Monitoring aborted: the device went offline 13 minutes into the window.',
  change_group_id: 'cg4',
  monitoring_ends_at: '2026-09-07T09:27:00Z',
  observations: [],
  baseline: null,
  incidents: [
    {
      event_type: 'AP_UNREACHABLE',
      occurred_at: '2026-09-07T09:27:00Z',
      severity: 'warning',
      resolved: false,
      resolved_at: null,
    },
  ],
});

describe('monitoring.model', () => {
  it('narrows a session list by status and by severity independently', () => {
    const items = [CRITICAL, QUIET, BLANK];

    expect(filterSessions(items, 'all').length).toBe(3);
    expect(filterSessions(items, 'failed').map((item) => item.id)).toEqual(['s3']);
    expect(filterSessions(items, 'all', 'critical').map((item) => item.id)).toEqual(['s1']);
    // Both predicates apply at once: a failed session is never also critical here.
    expect(filterSessions(items, 'failed', 'critical')).toEqual([]);
    expect(filterSessions(items, 'completed', 'none').map((item) => item.id)).toEqual(['s2']);
  });

  it('splits the SLE series on config_applied_at, baseline included', () => {
    const bars = sleSeries(CRITICAL, 'capacity');

    expect(bars.map((bar) => bar.preChange)).toEqual([true, true, false, false]);
    expect(bars.map((bar) => bar.value)).toEqual([41, 40, 12, 13]);
    // Samples arrive out of order from the API; the series is sorted by time.
    expect(bars[0].at).toBe('2026-09-07T08:14:00Z');
    expect(changeMarkerPercent(bars)).toBe(50);
  });

  it('expands the baseline trend into one bar per sampled bucket', () => {
    // Four hourly buckets; the second carried no traffic and invents no value.
    const withTrend = session({
      ...CRITICAL,
      baseline: {
        captured_at: '2026-09-07T08:14:00Z',
        window_start: '2026-09-07T04:14:00Z',
        window_end: '2026-09-07T08:14:00Z',
        values: { capacity: 41 },
        trend: { capacity: [50, null, 90, 95] },
        baseline_window: 'last-hour',
        errors: [],
      },
    });

    const bars = sleSeries(withTrend, 'capacity');

    expect(bars.map((bar) => bar.value)).toEqual([50, 90, 95, 40, 12, 13]);
    // The 08:44 observation also precedes the 09:14 change, so four bars are pre.
    expect(bars.map((bar) => bar.preChange)).toEqual([true, true, true, true, false, false]);
    // Each bucket is placed at the instant it ends, not at the capture time.
    expect(bars[0].at).toBe('2026-09-07T05:14:00.000Z');
    expect(bars[2].at).toBe('2026-09-07T08:14:00.000Z');
  });

  it('keeps the historical baseline before the change when the configured event is missing', () => {
    const bars = sleSeries(session({ ...CRITICAL, config_applied_at: null }), 'capacity');

    expect(bars.map((bar) => bar.preChange)).toEqual([true, false, false, false]);
    expect(changeMarkerPercent(bars)).toBe(25);
  });

  it('labels the axis from the bars actually plotted, not a assumed midpoint', () => {
    // Bars: 05:14, 07:14, 08:14 (baseline buckets), 08:44, 09:44, 10:14.
    const withTrend = session({
      ...CRITICAL,
      baseline: {
        captured_at: '2026-09-07T08:14:00Z',
        window_start: '2026-09-07T04:14:00Z',
        window_end: '2026-09-07T08:14:00Z',
        values: { capacity: 41 },
        trend: { capacity: [50, null, 90, 95] },
        errors: [],
      },
    });
    const bars = sleSeries(withTrend, 'capacity');

    // The change sits two thirds along, so no axis slot may claim it is halfway.
    expect(axisFor(bars, withTrend)).toEqual(['−4H', '−2H', '−30M', '+30M', 'NOW']);
  });

  it('plots the degraded metric and ranks the deltas worst first', () => {
    expect(primaryMetric(CRITICAL)).toBe('capacity');

    const deltas = metricDeltas(CRITICAL);
    expect(deltas.map((metric) => metric.key)).toEqual(['capacity', 'coverage']);
    expect(deltas[0].deltaLabel).toBe('−28');
    expect(deltas[0].tone).toBe('crit');
    expect(deltas[1].deltaLabel).toBe('−1');
    expect(deltas[1].tone).toBe('none');
  });

  it('reads a null or unusable assessment as no assessment at all', () => {
    expect(readAiAssessment(null)).toBeNull();
    expect(readAiAssessment({ severity: 'critical' })).toBeNull();
    expect(readAiAssessment({ explanation: ' text ' })?.explanation).toBe('text');
  });
});

describe('ImpactPage', () => {
  let fixture: ComponentFixture<ImpactPage>;
  let http: HttpTestingController;
  let navigations: Navigation[];
  const org = signal<{ id: string } | null>({ id: 'org-1' });
  const historical = signal(false);
  let role = true;
  function text() { return fixture.nativeElement.textContent as string; }
  function all(selector: string): HTMLElement[] { return Array.from(fixture.nativeElement.querySelectorAll(selector)); }
  async function render(item: MonitoringSession) {
    fixture.componentRef.setInput('session', item.id);
    fixture.detectChanges();
    http.expectOne('/api/v1/organizations/org-1/monitoring/' + item.id).flush(item);
    fixture.detectChanges();
    await fixture.whenStable();
  }
  beforeEach(async () => {
    org.set({ id: 'org-1' }); historical.set(false); role = true; navigations = [];
    await TestBed.configureTestingModule({
      imports: [ImpactPage],
      providers: [provideHttpClient(), provideHttpClientTesting(),
        { provide: Router, useValue: { navigate: (commands: unknown[], extras?: Record<string, unknown>) => {
          navigations.push({ commands, extras }); return Promise.resolve(true);
        } } },
        { provide: ActivatedRoute, useValue: {} },
        { provide: OrganizationContextService, useValue: { selected: org, revision: signal(0) } },
        { provide: AuthService, useValue: { can: () => role } },
        { provide: TimeContextService, useValue: { isHistorical: historical } },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(ImpactPage); http = TestBed.inject(HttpTestingController);
  });
  afterEach(() => { fixture.destroy(); http.verify(); });

  it('loads only the requested session, without a changes list or arbitrary fallback', async () => {
    TestBed.inject(MonitoringService).sessions.set([QUIET, BLANK]);
    await render(CRITICAL);
    expect(text()).toContain('SEA-AP-101');
    expect(text()).not.toContain('SEA-AP-114');
    expect(all('.rail, .row, .change-event').length).toBe(0);
    http.expectNone('/api/v1/organizations/org-1/monitoring');
    expect(navigations.length).toBe(0);
  });
  it('does not fetch or pick a session without a session link', () => {
    fixture.detectChanges();
    expect(text()).toContain('Select a device in site impact');
    http.expectNone((r) => r.url.includes('/monitoring'));
  });
  it('shows a load failure and retries the exact session', () => {
    fixture.componentRef.setInput('session', 'missing'); fixture.detectChanges();
    expect(text()).toContain('Loading device evidence');
    http.expectOne('/api/v1/organizations/org-1/monitoring/missing').flush({}, { status: 404, statusText: 'Not found' });
    fixture.detectChanges();
    expect(text()).toContain('could not be loaded');
    (all('button').find((b) => b.textContent?.trim() === 'Retry') as HTMLButtonElement).click();
    fixture.detectChanges();
    http.expectOne('/api/v1/organizations/org-1/monitoring/missing').flush(session({ id: 'missing' }));
    fixture.detectChanges(); expect(text()).toContain('SEA-AP-101');
  });
  it('cancels an old read when another session link arrives', async () => {
    fixture.componentRef.setInput('session', 'old'); fixture.detectChanges();
    const old = http.expectOne('/api/v1/organizations/org-1/monitoring/old');
    await render(QUIET);
    expect(old.cancelled).toBe(true); expect(text()).toContain('SEA-AP-114');
  });
  it('clears the device immediately when switching organizations and drops the link', async () => {
    await render(CRITICAL);
    org.set({ id: 'org-2' }); fixture.detectChanges();
    expect(text()).not.toContain('SEA-AP-101');
    http.expectNone((r) => r.url.includes('/monitoring'));
    expect(navigations.at(-1)?.extras).toMatchObject({ queryParams: { session: null } });
  });
  it('withholds current evidence and cancels its read in historical mode', () => {
    fixture.componentRef.setInput('session', 's1'); fixture.detectChanges();
    const pending = http.expectOne('/api/v1/organizations/org-1/monitoring/s1');
    historical.set(true); fixture.detectChanges();
    expect(pending.cancelled).toBe(true);
    expect(text()).toContain('Monitoring evidence is live');
    http.expectNone((r) => r.url.includes('/monitoring'));
  });
  it('returns to the selected device in site impact', async () => {
    await render(CRITICAL);
    all('.page-nav button')[0].click();
    expect(navigations.at(-1)).toMatchObject({ commands: ['/impact'], extras: { queryParams: { site: 'Seattle-DC', device: '5c5b351a2ba1', change: 'cg1' } } });
  });
  it('keeps shared attribution explicit without selecting an arbitrary change', async () => {
    await render({ ...CRITICAL, audit_ids: ['a1', 'a2'] });
    expect(text()).toContain('One monitoring window covers 2 overlapping changes');
    expect(all('.act-buttons').length).toBe(0);
  });
  it('shows metrics once, keeping the chart and AI commentary collapsed', async () => {
    await render(CRITICAL);
    expect(all('.metrics tbody tr').length).toBe(2);
    expect(all('.metrics')[0].textContent).toContain('41%');
    expect(all('.metrics')[0].textContent).toContain('13%');
    const chartDetails = all('app-sle-chart')[0].closest('details')!;
    expect(chartDetails.open).toBe(false);
    expect((all('details.ai')[0] as HTMLDetailsElement).open).toBe(false);
    expect(all('.bar').length).toBe(4);
    expect(all('.cg-visually-hidden tbody tr').length).toBe(4);
  });
  it('separates absent metrics from operational findings', async () => {
    await render(BLANK);
    expect(all('.state').length).toBe(1);
    expect(text()).toContain('Monitoring could not complete');
    expect(text()).toContain('AP_UNREACHABLE');
    expect(all('.metrics').length).toBe(0);
  });
  it('distinguishes trusted quiet metrics from insufficient baseline evidence', async () => {
    await render(QUIET); expect(text()).toContain('NO IMPACT DETECTED');
    fixture.componentRef.setInput('session', 'thin'); fixture.detectChanges();
    http.expectOne('/api/v1/organizations/org-1/monitoring/thin').flush({ ...QUIET, id: 'thin', baseline_confidence: 'none' });
    fixture.detectChanges(); expect(text()).toContain('INSUFFICIENT EVIDENCE');
  });
  it('explains no traffic and collection errors separately', async () => {
    await render(session({ baseline: { captured_at: '2026-09-09T10:00:00Z', values: {}, no_data: ['roaming'], errors: ['coverage: HTTP 403'] } }));
    expect(all('[aria-label="SLE metrics without sampled traffic"]')[0].textContent).toContain('Roaming');
    expect(all('[aria-label="SLE collection problems"]')[0].textContent).toContain('HTTP 403');
    expect(text()).not.toContain('NO IMPACT DETECTED');
  });
  it('offers configuration and restore actions only when available', async () => {
    await render(CRITICAL);
    all('.act-buttons button')[0].click(); all('.act-buttons button')[1].click();
    expect(navigations.at(-2)).toMatchObject({ commands: ['/changes'], extras: { queryParams: { group: 'cg1' } } });
    expect(navigations.at(-1)).toMatchObject({ commands: ['/history/restore'], extras: { queryParams: { changeGroup: 'cg1' } } });
    role = false; fixture.detectChanges(); expect(all('.act-buttons button').length).toBe(1);
  });
});
