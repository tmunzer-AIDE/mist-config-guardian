import { TestBed } from '@angular/core/testing';
import { ImpactReport } from '../core/impact-report.model';
import { ImpactReportComponent } from './impact-report';

const section = { state: 'partial' as const, explanation: 'Bounded evidence only.' };
export const reportFixture: ImpactReport = {
  schema_version: 1, investigation_id: 'investigation', audit_id: 'audit', revision: 2,
  generated_at: '2026-09-12T10:20:00Z', evidence_as_of: '2026-09-12T10:20:00Z',
  peak_impact: 'critical', peak_revision: 1, peak_confidence: 'medium', current_impact: 'info',
  confidence: 'low', history_complete: true, coverage: 'partial', attribution: 'plausible',
  sections: { summary: section, change: section, scope: section, findings: section, evidence: section,
    timeline: section, context: section, gaps_and_next_checks: section },
  datasets: [{ id: 'evidence-0', check_id: 'check', target_handle: 'target',
    window: { start: '2026-09-12T10:00:00Z', end: '2026-09-12T10:20:00Z' }, captured_at: '2026-09-12T10:20:00Z',
    state: 'partial', title: 'Observed clients', kind: 'bar', columns: ['Serving AP', 'Clients'],
    rows: [['aabbccddeeff', 0], ['112233445566', null]], omitted_rows: 1, explanation: 'Sample only' }],
  impacted_devices: [{ device_mac: 'aabbccddeeff', site_id: 'site', role: 'serving_affected_clients',
    service: 'wlan_sessions', target_handle: 'target', port_id: null, impact: 'warning', current_impact: 'info',
    confidence: 'low', attribution: 'plausible', device_failure: 'not_established' }],
  omitted_device_impacts: 0, device_coverage: 'observed_only', gaps: ['Current evidence unavailable'],
};

describe('ImpactReportComponent', () => {
  it('separates retained peak from unknown current state and shows source values', () => {
    const fixture = TestBed.createComponent(ImpactReportComponent);
    fixture.componentRef.setInput('report', reportFixture); fixture.detectChanges();
    const text = fixture.nativeElement.textContent;
    expect(text).toContain('Peak impact: critical'); expect(text).toContain('source revision 1');
    expect(text).toContain('Current impact: Unknown'); expect(text).toContain('Served affected clients');
    expect(text).toContain('do not establish that an entire device failed');
    expect(text).toContain('1 rows omitted');
    expect(fixture.nativeElement.querySelectorAll('.fill')[0].style.width).toBe('0%');
  });
  it('renders evidence strings as text without interpreting HTML', () => {
    const fixture = TestBed.createComponent(ImpactReportComponent);
    fixture.componentRef.setInput('report', { ...reportFixture, gaps: ['<img src=x onerror=alert(1)>'] });
    fixture.detectChanges(); expect(fixture.nativeElement.querySelector('img')).toBeNull();
    expect(fixture.nativeElement.textContent).toContain('<img src=x');
  });
});
