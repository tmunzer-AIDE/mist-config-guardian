import { TestBed } from '@angular/core/testing';
import { DomainFindingsComponent } from './domain-findings';
import { PortEventsComponent } from './port-events';

describe('Scoped infrastructure evidence', () => {
  it('keeps critical service loss distinct from AP failure', async () => {
    await TestBed.configureTestingModule({ imports: [DomainFindingsComponent] }).compileComponents();
    const fixture = TestBed.createComponent(DomainFindingsComponent);
    fixture.componentRef.setInput('findings', [{ service: 'port_power', device_mac: 'switch', port_id: 'ge-0/0/1',
      impact: 'critical', current_impact: 'info', confidence: 'low', attribution: 'plausible', state: 'possible_disruption',
      explanation: '<img src=x onerror=alert(1)>', occurred_at: null, recovered_at: null }]);
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Peak: critical');
    expect(fixture.nativeElement.textContent).toContain('Current: Insufficient evidence');
    expect(fixture.nativeElement.textContent).toContain('does not establish failure of a neighboring AP');
    expect(fixture.nativeElement.querySelector('img')).toBeNull();
  });

  it('shows event times and omissions without treating enable as delivered power', async () => {
    await TestBed.configureTestingModule({ imports: [PortEventsComponent] }).compileComponents();
    const fixture = TestBed.createComponent(PortEventsComponent);
    fixture.componentRef.setInput('events', [{ event_type: 'SW_POE_PORT_ENABLED', occurred_at: '2026-09-13T01:00:00Z' }]);
    fixture.componentRef.setInput('omitted', 3);
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('2026-09-13T01:00:00Z');
    expect(fixture.nativeElement.textContent).toContain('3 events omitted');
    expect(fixture.nativeElement.textContent).toContain('do not establish power delivery');
  });
});
