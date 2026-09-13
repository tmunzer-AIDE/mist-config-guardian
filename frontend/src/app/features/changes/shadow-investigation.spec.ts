import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { OrganizationContextService } from '../../core/organization-context.service';
import { ShadowInvestigation, ShadowReport } from './shadow-investigation';

const report: ShadowReport = {
  mode: 'shadow', id: 'investigation', audit_id: 'audit', revision: 1, status: 'monitoring',
  changed_at: '2026-09-12T10:00:00Z', expires_at: '2026-09-12T11:00:00Z', calls_used: 2, calls_limit: 56,
  assessment: { impact: 'info', confidence: 'low', coverage: 'partial', gaps: ['Client history is incomplete'],
    findings: [{ target_handle: 'handle', state: 'unknown', baseline_clients: null, disconnected_clients: null,
      serving_ap_macs: [], explanation: 'Missing evidence is unknown' }] },
  targets: [{ handle: 'handle', site_id: 'site', wlan_id: 'wlan' }],
  checks: [{ check_id: 'wlan-client-sessions.v1', target_handle: 'handle', captured_at: '2026-09-12T10:10:00Z',
    window: { start: '2026-09-12T09:00:00Z', end: '2026-09-12T10:00:00Z' }, state: 'error', row_count: 0, reason: 'HTTP 500' }],
};

describe('ShadowInvestigation', () => {
  const selected = signal({ id: 'org-a' });
  beforeEach(() => {
    selected.set({ id: 'org-a' });
    TestBed.configureTestingModule({ imports: [ShadowInvestigation], providers: [provideHttpClient(), provideHttpClientTesting(),
      { provide: OrganizationContextService, useValue: { selected } }] });
  });
  afterEach(() => TestBed.inject(HttpTestingController).verify());

  function setup() {
    const fixture = TestBed.createComponent(ShadowInvestigation);
    fixture.componentRef.setInput('groupId', 'group-a');
    fixture.detectChanges();
    return fixture;
  }

  it('loads on demand and renders missing evidence and error details without claiming healthy', async () => {
    const fixture = setup();
    const http = TestBed.inject(HttpTestingController);
    http.expectNone(() => true);
    fixture.nativeElement.querySelector('button').click();
    const request = http.expectOne((req) => req.url.endsWith('/change-groups/group-a/investigation'));
    request.flush(report);
    await fixture.whenStable();
    fixture.detectChanges();
    const text = fixture.nativeElement.textContent;
    expect(text).toContain('Impact: Insufficient evidence');
    expect(text).toContain('Confidence: low');
    expect(text).toContain('Unknown');
    expect(text).toContain('HTTP 500');
    expect(text).toContain('Client history is incomplete');
    expect(text).not.toContain('Impact: No observed disconnect');
  });

  it('shows revoked dispatch access as an evidence gap rather than a budget limit', async () => {
    const fixture = setup();
    fixture.nativeElement.querySelector('button').click();
    TestBed.inject(HttpTestingController).expectOne(() => true).flush({ ...report, status: 'incomplete',
      checks: [{ ...report.checks[0], state: 'dispatch_denied', dispatch_denial: 'credentials_changed',
        reason: 'Dispatch denied: the service credential changed; review organization access.' }] });
    await fixture.whenStable();
    fixture.detectChanges();
    const text = fixture.nativeElement.textContent;
    expect(text).toContain('Not dispatched');
    expect(text).toContain('review organization access');
    expect(text).toContain('Impact: Insufficient evidence');
    expect(text).not.toContain('budget is exhausted');
  });

  it('discards an old response after switching organization', async () => {
    const fixture = setup();
    fixture.nativeElement.querySelector('button').click();
    const request = TestBed.inject(HttpTestingController).expectOne(() => true);
    selected.set({ id: 'org-b' });
    fixture.detectChanges();
    request.flush(report);
    await fixture.whenStable();
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).not.toContain('WLAN investigation');
  });

  it('shows absence of a recorded investigation distinctly from a clean result', async () => {
    const fixture = setup();
    fixture.nativeElement.querySelector('button').click();
    TestBed.inject(HttpTestingController).expectOne(() => true).flush(null);
    await fixture.whenStable();
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('No shadow investigation was recorded');
    expect(fixture.nativeElement.textContent).not.toContain('Impact:');
  });
});
