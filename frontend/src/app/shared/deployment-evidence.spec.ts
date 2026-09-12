import { TestBed } from '@angular/core/testing';
import { DeploymentEvidence } from '../core/deployment-evidence.model';
import { DeploymentEvidenceComponent } from './deployment-evidence';

const evidence: DeploymentEvidence = {
  schema_version: 1, collected_at: '2026-09-12T12:10:00Z', state: 'partial',
  coverage: 'observed_receipts_only', expected_device_count: null,
  gaps: ['Session association is not proof of audit deployment.'],
  devices: [{ device_mac: '001122aabbcc', site_id: 'site-1', device_type: 'ap',
    outcome: 'unknown', correlation: 'session_candidate', last_event_at: null, receipt_ids: ['receipt-1'] }],
  observations: [{ receipt_id: 'receipt-1', received_at: '2026-09-12T12:02:00Z', correlation: 'session_candidate',
    signal: { event_type: 'AP_CONFIGURED', outcome: 'configured', device_mac: '001122aabbcc', site_id: 'site-1',
      occurred_at: '2026-09-12T12:01:00Z', gaps: [] } }],
};

describe('Deployment evidence presentation', () => {
  it('keeps session candidates unknown and separates deployment from device impact', async () => {
    await TestBed.configureTestingModule({ imports: [DeploymentEvidenceComponent] }).compileComponents();
    const fixture = TestBed.createComponent(DeploymentEvidenceComponent);
    fixture.componentRef.setInput('evidence', evidence);
    fixture.detectChanges();
    const text = fixture.nativeElement.textContent as string;
    expect(text).toContain('Expected device count: unknown');
    expect(text).toContain('Session candidate only');
    expect(text).toContain('They do not identify impacted devices');
    expect(text).toContain('Occurrence and receipt times are kept separately');
    expect(text).toContain('AP_CONFIGURED');
    const cells = Array.from(fixture.nativeElement.querySelectorAll('table:first-of-type tbody td')) as HTMLElement[];
    expect(cells[1].textContent).toBe('unknown');
  });

  it('distinguishes old uncollected revisions from empty observed evidence', async () => {
    await TestBed.configureTestingModule({ imports: [DeploymentEvidenceComponent] }).compileComponents();
    const fixture = TestBed.createComponent(DeploymentEvidenceComponent);
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('not collected in this report revision');
    fixture.componentRef.setInput('evidence', { ...evidence, devices: [], observations: [], gaps: [] });
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('No device deployment outcome was established');
    expect(fixture.nativeElement.textContent).not.toContain('not collected in this report revision');
  });
});
