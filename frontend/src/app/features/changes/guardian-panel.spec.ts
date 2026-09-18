import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import {
  GuardianInvestigation,
  GuardianReport,
  GuardianRunDetail,
  GuardianRunReport,
  ReportSection,
} from '../../core/guardian.model';
import { OrganizationContextService } from '../../core/organization-context.service';
import { GuardianPanel } from './guardian-panel';

function section<T>(items: T[] = [], omitted = 0, explanation: string | null = null): ReportSection<T> {
  return { items, omitted, explanation: items.length ? null : explanation };
}

function report(overrides: Partial<GuardianReport> = {}): GuardianReport {
  return {
    run: {
      kind: 'early',
      attempt: 1,
      state: 'succeeded',
      failure_reason: null,
      started_at: '2026-09-07T09:20:00Z',
      finished_at: '2026-09-07T09:22:00Z',
      anchor: { changed_at: '2026-09-07T09:12:00Z', source: 'audit' },
      as_of: '2026-09-07T09:22:00Z',
      budget: { model_turns: 4, mcp_calls: 2, rule_reads: 1 },
    },
    header: {
      peak: 'warning',
      current: 'none',
      recovery: 'recovered',
      confidence: 'low',
      coverage: 'partial',
      sources: ['monitoring', 'agent'],
    },
    header_note: null,
    summary: {
      deterministic: 'One access point reached warning and recovered.',
      ai: 'The switch reload looks like the cause, but the evidence is thin.',
      ai_note: null,
    },
    change: section([
      {
        id: 'A1',
        logical_object_id: 'obj-1',
        version: 4,
        attribute: 'port_config',
        paths: [['port_config', 'ge-0/0/1']],
        paths_complete: false,
      },
    ]),
    coverage: {
      coverage: 'partial',
      rows: section([
        {
          atom_id: 'A1',
          target: { device_mac: 'aabbccddeeff', site_id: 'site-1', port_id: null, wlan_id: null },
          resolution: 'claimed',
          obligation_ids: ['O1'],
          uncovered_paths: [],
        },
      ]),
      obligations: section([
        {
          obligation: {
            id: 'O2',
            owner: 'core',
            change_ref: null,
            paths: [],
            role: 'observation',
            kind: 'input',
            target: { device_mac: null, site_id: null, port_id: null, wlan_id: null },
            metric: null,
            empty_policy: null,
          },
          status: {
            status: 'unsatisfied',
            reason: 'The stored version was truncated, so the change was never built in full.',
            evidence_ids: [],
          },
        },
      ]),
    },
    devices: section(
      [
        {
          mac: 'aabbccddeeff',
          site_id: 'site-1',
          name: 'Floor 2 AP',
          session_id: 's1',
          exclusive: true,
          terminal: true,
          status: 'satisfied',
          metrics: { peak: 'warning', current: 'none' },
          incidents: null,
          device_state: null,
          peak: 'warning',
          current: 'none',
          deployment: 'configured',
          deployment_precondition: 'satisfied',
        },
      ],
      2,
    ),
    impacted: section(
      [{ mac: 'aabbccddeeff', site_id: 'site-1', name: 'Floor 2 AP', peak: 'warning', current: 'none' }],
      3,
    ),
    findings: section([
      { source: 'monitoring', text: 'Capacity fell on one access point.', severity: 'warning', evidence_ids: ['E1'] },
      { source: 'agent', text: 'The reload is the likeliest cause.', severity: 'info', evidence_ids: ['E2'] },
    ]),
    evidence: section([
      {
        id: 'E1',
        source: 'monitoring',
        kind: 'service_health',
        title: 'Monitoring replay',
        captured_at: '2026-09-07T09:21:00Z',
        window: { start: '2026-09-07T09:12:00Z', end: '2026-09-07T09:21:00Z' },
        scope: { site_ids: ['site-1'], device_macs: ['aabbccddeeff'] },
        collection: 'complete',
        representation: 'full',
        citable: true,
        detail: '',
      },
      {
        id: 'E5',
        source: 'mcp:mist_search_device',
        kind: 'reference',
        title: 'Device search',
        captured_at: '2026-09-07T09:21:30Z',
        window: null,
        scope: { site_ids: [], device_macs: [] },
        collection: 'error',
        representation: 'digest',
        citable: false,
        detail: 'HTTP 500',
      },
    ]),
    gaps: section([{ source: 'agent', text: 'Client history for the window is incomplete.' }]),
    ...overrides,
  };
}

function run(overrides: Partial<GuardianRunReport> = {}): GuardianRunReport {
  return { id: 'run-early', kind: 'early', attempt: 1, state: 'succeeded', published: true, report: report(), ...overrides };
}

function investigation(overrides: Partial<GuardianInvestigation> = {}): GuardianInvestigation {
  return {
    root: {
      id: 'inv-1',
      audit_id: 'audit-1',
      changed_at: '2026-09-07T09:12:00Z',
      anchor_known: true,
      status: 'done',
      status_reason: 'Final attempts exhausted',
      next_check_at: null,
      attempts: { early: 1, final: 2 },
      early_run_id: 'run-early',
      final_run_id: null,
      result: null,
    },
    runs: [run()],
    attempts: [
      { id: 'run-early', kind: 'early', attempt: 1, state: 'succeeded', failure_reason: null, budget: { model_turns: 4, mcp_calls: 2, rule_reads: 1 }, published: true },
      { id: 'run-final-1', kind: 'final', attempt: 1, state: 'failed', failure_reason: 'The provider did not answer', budget: { model_turns: 0, mcp_calls: 0, rule_reads: 0 }, published: false },
    ],
    unreadable_attempts: 1,
    ...overrides,
  };
}

const runDetail: GuardianRunDetail = {
  ...run(),
  investigation_id: 'inv-1',
  audit_id: 'audit-1',
  failure_reason: null,
  budget: { model_turns: 4, mcp_calls: 2, rule_reads: 1 },
  steps: [
    {
      turn: 1,
      action: 'call',
      tool: 'mist_search_device',
      evidence_id: 'E5',
      collection: 'error',
      output: 'I will look at the switch first.',
      visible_evidence_ids: ['E1', 'E2'],
      withheld_evidence_ids: ['E5'],
    },
    {
      turn: 2,
      action: 'report',
      rejection: 'citation_invalid',
      detail: 'E5 is not citable',
      visible_evidence_ids: ['E1', 'E2'],
      withheld_evidence_ids: ['E5'],
    },
  ],
};

const INVESTIGATION_URL = '/api/v1/organizations/org-a/change-groups/group-a/guardian';

describe('GuardianPanel', () => {
  const selected = signal({ id: 'org-a' });
  let fixture: ComponentFixture<GuardianPanel>;
  let http: HttpTestingController;

  beforeEach(async () => {
    selected.set({ id: 'org-a' });
    await TestBed.configureTestingModule({
      imports: [GuardianPanel],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: OrganizationContextService, useValue: { selected } },
      ],
    }).compileComponents();
    http = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(GuardianPanel);
    fixture.componentRef.setInput('groupId', 'group-a');
    fixture.detectChanges();
  });

  afterEach(() => http.verify());

  /** The rendered text with runs of whitespace collapsed, so assertions read as the page does. */
  function text(): string {
    return ((fixture.nativeElement as HTMLElement).textContent ?? '').replace(/\s+/g, ' ');
  }

  async function open(model: GuardianInvestigation | null = investigation()): Promise<void> {
    (fixture.nativeElement as HTMLElement).querySelector('button')!.click();
    http.expectOne((request) => request.url === INVESTIGATION_URL).flush(model);
    await fixture.whenStable();
    fixture.detectChanges();
  }

  async function expand(label: string): Promise<HTMLButtonElement> {
    const button = Array.from(
      (fixture.nativeElement as HTMLElement).querySelectorAll<HTMLButtonElement>('.attempt button'),
    ).find((candidate) => (candidate.textContent ?? '').includes(label))!;
    button.click();
    await fixture.whenStable();
    fixture.detectChanges();
    return button;
  }

  it('reads nothing until it is asked to', () => {
    http.expectNone(() => true);
    expect(text()).toContain('Review Guardian investigation');
  });

  it('renders the published result with its deterministic sentence and the AI summary labelled as AI', async () => {
    await open();

    expect(text()).toContain('Finished · 1 early and 2 final attempts · Final attempts exhausted');
    expect(text()).toContain('Peak: warning');
    expect(text()).toContain('Current: none');
    expect(text()).toContain('Recovered');
    expect(text()).toContain('Confidence: low · Deterministic coverage: partial');
    expect(text()).toContain('Sources: Monitoring, AI agent');
    expect(text()).toContain('One access point reached warning and recovered.');
    expect(text()).toContain("AI summary · the AI agent's own words, not a verified statement");
    expect(text()).toContain('The switch reload looks like the cause');
  });

  it('says an early result is the last one when the investigation ended without a final', async () => {
    await open();

    expect(text()).toContain('Early result · attempt 1');
    expect(text()).toContain('ended without publishing a final result');
    expect(text()).toContain('Final attempts exhausted');
  });

  it('opens on the final result and keeps the early one reachable when both are published', async () => {
    const final = run({ id: 'run-final', kind: 'final', attempt: 1, report: report({ run: { ...report().run, kind: 'final' } }) });
    await open(
      investigation({
        root: { ...investigation().root, final_run_id: 'run-final' },
        runs: [run(), final],
      }),
    );

    const tabs = Array.from((fixture.nativeElement as HTMLElement).querySelectorAll('[role="tab"]')).map(
      (tab) => (tab.textContent ?? '').trim(),
    );
    expect(tabs).toEqual(['Early result · attempt 1', 'Final result · attempt 1']);
    expect(text()).toContain('This is the final result of the investigation.');
    expect(text()).not.toContain('ended without publishing a final result');
  });

  it('shows the core input obligation, which claims no change atom, for what it is', async () => {
    await open();

    expect(text()).toContain('O2 · input · Core · no change atom · an input this attempt never saw in full');
    expect(text()).toContain('unsatisfied');
    expect(text()).toContain('The stored version was truncated');
  });

  it('counts omitted impacted devices without naming a site for them', async () => {
    await open();

    expect(text()).toContain('3 further impacted devices were not recorded individually');
    expect(text()).toContain('they are not named here');
    expect(text()).toContain('2 further devices were counted in a digest');
  });

  it('labels a finding the agent made as the AI agent', async () => {
    await open();

    expect(text()).toContain('AI agent · info · The reload is the likeliest cause.');
    expect(text()).toContain('Monitoring · warning · Capacity fell on one access point.');
    expect(text()).toContain('AI agent · Client history for the window is incomplete.');
  });

  it('marks evidence the agent could not cite as not citable rather than absent', async () => {
    await open();

    expect(text()).toContain('E5');
    expect(text()).toContain('Not citable');
    expect(text()).toContain('HTTP 500');
  });

  it('explains an empty section from the run instead of leaving it blank', async () => {
    await open(
      investigation({
        runs: [
          run({
            report: report({
              findings: section([], 0, 'No rule plug-in applied; the AI agent did not conclude: no capability.'),
            }),
          }),
        ],
      }),
    );

    expect(text()).toContain('No rule plug-in applied; the AI agent did not conclude: no capability.');
  });

  it('says how many attempts it could not read rather than showing a short list as complete', async () => {
    await open();

    expect(text()).toContain('1 attempt could not be read by this build');
    expect(text()).toContain('This list is not complete.');
    expect(text()).toContain('Final result · attempt 1 · failed · not published');
    expect(text()).toContain('The provider did not answer');
  });

  it('loads one attempt on demand and shows withheld evidence as withheld, not missing', async () => {
    await open();
    http.expectNone(() => true);

    await expand('Early result · attempt 1');
    http
      .expectOne((request) => request.url === `${INVESTIGATION_URL}/runs/run-early`)
      .flush(runDetail);
    await fixture.whenStable();
    fixture.detectChanges();

    expect(text()).toContain('Turn 1 · call · mist_search_device · E5 (error)');
    expect(text()).toContain('Shown to the AI agent: E1, E2');
    expect(text()).toContain('Withheld from the AI agent, which could not cite it: E5');
    expect(text()).toContain('rejected: citation_invalid — E5 is not citable');
    expect(text()).toContain('AI agent output · redacted and truncated');
    // Withheld says what happened to it: the item was collected, and the agent
    // could not cite it. It is never reported as evidence that does not exist.
    expect(text()).not.toContain('not collected');
    expect(text()).toContain('MCP mist_search_device');
  });

  it('reports an attempt whose run it cannot read as unavailable, not as empty', async () => {
    await open();
    await expand('Final result · attempt 1');
    http
      .expectOne((request) => request.url === `${INVESTIGATION_URL}/runs/run-final-1`)
      .flush(null, { status: 404, statusText: 'Not Found' });
    await fixture.whenStable();
    fixture.detectChanges();

    expect(text()).toContain('its stored run could not be read');
  });

  it('says a change has no investigation rather than showing an empty one', async () => {
    (fixture.nativeElement as HTMLElement).querySelector('button')!.click();
    http
      .expectOne((request) => request.url === INVESTIGATION_URL)
      .flush(null, { status: 404, statusText: 'Not Found' });
    await fixture.whenStable();
    fixture.detectChanges();

    expect(text()).toContain('No Guardian investigation was recorded for this change.');
  });

  it('renders model and provider text as text', async () => {
    await open(
      investigation({
        runs: [
          run({
            report: report({
              summary: { deterministic: 'One device reached warning.', ai: '<img src=x onerror=alert(1)>', ai_note: null },
            }),
          }),
        ],
      }),
    );

    expect((fixture.nativeElement as HTMLElement).querySelector('img')).toBeNull();
    expect(text()).toContain('<img src=x onerror=alert(1)>');
  });

  it('discards an answer that belongs to the organization the user has left', async () => {
    (fixture.nativeElement as HTMLElement).querySelector('button')!.click();
    const request = http.expectOne((candidate) => candidate.url === INVESTIGATION_URL);
    selected.set({ id: 'org-b' });
    fixture.detectChanges();
    request.flush(investigation());
    await fixture.whenStable();
    fixture.detectChanges();

    expect(text()).not.toContain('Guardian investigation Finished');
    expect(text()).not.toContain('One access point reached warning');
  });
});
