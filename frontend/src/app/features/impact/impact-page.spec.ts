import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ActivatedRoute, Router } from '@angular/router';

import { AuthService } from '../../core/auth.service';
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

  it('treats every sample as post-change when the change instant is unknown', () => {
    const bars = sleSeries(session({ ...CRITICAL, config_applied_at: null }), 'capacity');

    expect(bars.every((bar) => !bar.preChange)).toBe(true);
    expect(changeMarkerPercent(bars)).toBeNull();
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
  let monitoring: MonitoringService;
  let navigations: Navigation[];
  let historical: boolean;
  let role: boolean;

  function text(): string {
    return (fixture.nativeElement as HTMLElement).textContent ?? '';
  }

  function all(selector: string): HTMLElement[] {
    return Array.from((fixture.nativeElement as HTMLElement).querySelectorAll(selector));
  }

  async function render(items: MonitoringSession[], selected?: string): Promise<void> {
    monitoring.sessions.set(items);
    monitoring.total.set(items.length);
    if (selected) {
      fixture.componentRef.setInput('session', selected);
    }
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
  }

  beforeEach(async () => {
    navigations = [];
    historical = false;
    role = true;

    await TestBed.configureTestingModule({
      imports: [ImpactPage],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        {
          provide: Router,
          useValue: {
            navigate: (commands: unknown[], extras?: Record<string, unknown>) => {
              navigations.push({ commands, extras });
              return Promise.resolve(true);
            },
          },
        },
        { provide: ActivatedRoute, useValue: {} },
        { provide: AuthService, useValue: { can: () => role } },
        { provide: TimeContextService, useValue: { isHistorical: () => historical } },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(ImpactPage);
    monitoring = TestBed.inject(MonitoringService);
    monitoring.reset();
  });

  it('lists every session and narrows the list from the status chips', async () => {
    await render([CRITICAL, QUIET, BLANK]);

    expect(text()).toContain('MONITORING SESSIONS · 3');
    expect(all('.row').length).toBe(3);

    const failed = all('.cg-chip').find((chip) => chip.textContent?.trim() === 'Failed');
    expect(failed?.getAttribute('aria-pressed')).toBe('false');

    failed?.click();
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();

    expect(all('.row').length).toBe(1);
    expect(all('.row')[0].textContent).toContain('SEA-AP-118');
    expect(
      all('.cg-chip').find((chip) => chip.textContent?.trim() === 'Failed')?.getAttribute('aria-pressed'),
    ).toBe('true');
  });

  it('keeps the selected evidence on screen when a filter hides its row', async () => {
    await render([CRITICAL, QUIET, BLANK], 's1');
    expect(text()).toContain('SEA-AP-101');

    all('.cg-chip').find((chip) => chip.textContent?.trim() === 'Failed')?.click();
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();

    // The row is gone from the rail, but the detail pane still reads s1.
    expect(all('.row').length).toBe(1);
    expect(all('.row--on').length).toBe(0);
    expect(all('.head-device')[0].textContent).toContain('SEA-AP-101');
  });

  it('narrows the list by the severity carried on the deep link', async () => {
    fixture.componentRef.setInput('severity', 'critical');
    await render([CRITICAL, QUIET, BLANK]);

    expect(all('.row').length).toBe(1);
    expect(all('.row')[0].textContent).toContain('SEA-AP-101');
  });

  it('draws grey pre-change and toned post-change bars around the change instant', async () => {
    await render([CRITICAL], 's1');

    expect(all('app-sle-chart').length).toBe(1);
    const bars = all('.bar');
    expect(bars.length).toBe(4);
    expect(bars.filter((bar) => bar.classList.contains('bar--post')).length).toBe(2);
    // The two pre-change bars keep the neutral fill.
    expect(bars.filter((bar) => !bar.classList.contains('bar--post')).length).toBe(2);
    expect(all('.plot')[0].getAttribute('data-tone')).toBe('crit');
    expect(all('.mark-label')[0].textContent).toContain('CHANGE APPLIED');
    // The chart is never the only reading: every sample is in the hidden table.
    expect(all('.cg-visually-hidden tbody tr').length).toBe(4);
    expect(text()).toContain('Capacity');
    expect(text()).toContain('BASELINE 41%');
    expect(text()).toContain('LATEST 13%');
  });

  it('says a session produced no observations instead of drawing an empty chart', async () => {
    await render([BLANK], 's3');

    expect(all('app-sle-chart').length).toBe(0);
    expect(all('.metrics').length).toBe(0);
    expect(all('.state').length).toBe(1);
    expect(text()).toContain('Monitoring could not complete');
    expect(text()).toContain('Monitoring aborted');
    // The state panel carries the only summary; the header must not repeat it.
    expect(all('.head-summary').length).toBe(0);
    // Incidents are deterministic evidence and still render.
    expect(text()).toContain('AP_UNREACHABLE');
  });

  it('distinguishes no impact from insufficient evidence using baseline_confidence', async () => {
    await render([QUIET], 's2');
    expect(text()).toContain('NO IMPACT DETECTED');

    const { baseline_confidence: _dropped, ...withoutConfidence } = QUIET;
    await render([withoutConfidence], 's2');
    expect(text()).toContain('INSUFFICIENT EVIDENCE');
  });

  it('renders the deterministic summary when ai_assessment is null', async () => {
    await render([QUIET], 's2');

    expect(text()).toContain('No monitored metric moved beyond the noise band');
    expect(all('.ai').length).toBe(0);
    expect(all('.ai-note').length).toBe(0);
    // The deterministic panels are untouched by the missing assessment.
    expect(all('.metrics').length).toBe(1);
    expect(text()).toContain('Act on this session');
  });

  it('shows a quiet note when the assessment failed, and keeps the evidence', async () => {
    await render(
      [session({ ...CRITICAL, ai_assessment: null, ai_assessment_error: 'provider timed out' })],
      's1',
    );

    expect(all('.ai').length).toBe(0);
    expect(all('.ai-note')[0].textContent).toContain('provider timed out');
    expect(all('.metrics').length).toBe(1);
  });

  it('reflects the selection onto the URL and deep-links the change group and restore', async () => {
    await render([CRITICAL, QUIET]);

    const reflected = navigations.find((item) => item.commands.length === 0);
    expect(reflected?.extras).toMatchObject({
      queryParams: { session: 's1' },
      queryParamsHandling: 'merge',
      replaceUrl: true,
    });

    const buttons = all('.act-buttons button');
    buttons[0].click();
    buttons[1].click();

    expect(navigations.at(-2)).toMatchObject({
      commands: ['/changes'],
      extras: { queryParams: { group: 'cg1' } },
    });
    expect(navigations.at(-1)).toMatchObject({
      commands: ['/restore'],
      extras: { queryParams: { changeGroup: 'cg1' } },
    });
  });

  it('withholds a restore in historical mode and below the operator role', async () => {
    historical = true;
    await render([CRITICAL], 's1');
    expect(all('.act-buttons button').length).toBe(1);

    historical = false;
    role = false;
    await render([CRITICAL], 's1');
    expect(all('.act-buttons button').length).toBe(1);

    role = true;
    await render([CRITICAL], 's1');
    expect(all('.act-buttons button').length).toBe(2);
  });

  it('disables both actions until the session is correlated to a change group', async () => {
    const { change_group_id: _uncorrelated, ...pending } = CRITICAL;
    await render([pending], 's1');

    expect(text()).toContain('not correlated to a change group yet');
    for (const button of all('.act-buttons button')) {
      expect((button as HTMLButtonElement).disabled).toBe(true);
    }
  });

  it('moves the selection with the arrow keys', async () => {
    await render([CRITICAL, QUIET, BLANK]);
    expect(all('.row--on')[0].textContent).toContain('SEA-AP-101');

    all('.rail-list')[0].dispatchEvent(
      new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }),
    );
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();

    expect(all('.row--on')[0].textContent).toContain('SEA-AP-114');
  });

  it('invites the reader to widen the filter when nothing matches', async () => {
    await render([]);

    expect(all('.row').length).toBe(0);
    expect(text()).toContain('No sessions match this filter');
    expect(text()).toContain('No monitoring session selected');
  });
});
