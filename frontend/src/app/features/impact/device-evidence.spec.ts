import { ComponentFixture, TestBed } from '@angular/core/testing';
import { DeviceEvidence } from './device-evidence';
import { DeviceStateObservation, MonitoringSession } from './monitoring.model';
import { TelemetryCapture } from './telemetry-capture';

function state(overrides: Partial<DeviceStateObservation> = {}): DeviceStateObservation {
  return { captured_at: '2026-09-09T12:00:00Z', device: {}, radios: [], wlans: [], clients: [],
    ports: [], bgp: [], ospf: [], tunnels: [], vpn_peers: [], available: ['clients'], errors: {}, ...overrides };
}

function click(fixture: ComponentFixture<unknown>, text: string) {
  const button = [...fixture.nativeElement.querySelectorAll('button')]
    .find((item: HTMLButtonElement) => item.textContent.trim() === text) as HTMLButtonElement;
  button.click();
  fixture.detectChanges();
}

describe('TelemetryCapture', () => {
  it('formats only 50 records at a time, with access to all 5000 and independent pagination', () => {
    const formatted: number[] = [];
    const records = Array.from({ length: 5000 }, (_, index) => ({ id: `client-${index}`,
      stats: { toJSON: () => { formatted.push(index); return { rssi: -60 }; } } }));
    const fixture = TestBed.createComponent(TelemetryCapture);
    fixture.componentRef.setInput('label', 'At trigger');
    fixture.componentRef.setInput('value', records);
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelectorAll('tbody tr').length).toBe(50);
    expect(formatted).toEqual(Array.from({ length: 50 }, (_, index) => index));
    fixture.detectChanges();
    expect(formatted.length).toBe(50);
    click(fixture, 'Next');
    expect(fixture.nativeElement.textContent).toContain('Records 51–100 of 5000');
    click(fixture, 'Last');
    expect(fixture.nativeElement.textContent).toContain('client-4999');
    expect(fixture.nativeElement.querySelectorAll('tbody tr').length).toBe(50);
    click(fixture, 'Previous');
    expect(fixture.nativeElement.textContent).toContain('Records 4901–4950 of 5000');
    click(fixture, 'First');
    expect(fixture.nativeElement.textContent).toContain('Records 1–50 of 5000');
    click(fixture, 'Last');
    fixture.componentRef.setInput('value', [{ id: 'replacement' }]);
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Records 1–1 of 1');
    expect(fixture.nativeElement.textContent).toContain('replacement');
    expect(fixture.nativeElement.querySelector('nav')).toBeNull();
  });

  it('distinguishes pending, unavailable, empty and single-device captures', () => {
    const fixture = TestBed.createComponent(TelemetryCapture);
    fixture.componentRef.setInput('label', 'Five minutes later');
    fixture.componentRef.setInput('value', null);
    fixture.componentRef.setInput('emptyLabel', 'Pending capture');
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Pending capture');
    fixture.componentRef.setInput('emptyLabel', 'Unavailable');
    fixture.componentRef.setInput('error', 'HTTP 404');
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Unavailable');
    expect(fixture.nativeElement.textContent).toContain('HTTP 404');
    fixture.componentRef.setInput('error', undefined);
    fixture.componentRef.setInput('value', []);
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('No records');
    fixture.componentRef.setInput('value', { status: 'connected' });
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelectorAll('tbody tr').length).toBe(1);
    expect(fixture.nativeElement.textContent).toContain('connected');
  });
});

describe('DeviceEvidence', () => {
  it('summarizes repeated findings once without losing earlier-baseline evidence', () => {
    const fixture = TestBed.createComponent(DeviceEvidence);
    const finding = { kind: 'ssid', subject: 'BYOD-IOT', before: 'configured', after: 'removed',
      severity: 'warning', detail: 'SSID removed with no observed clients.', affected_clients: 0 };
    const comparisons = Array.from({ length: 5 }, (_, i) => ({
      triggered_at: `2026-09-09T12:0${i}:00Z`, due_at: '2026-09-09T12:10:00Z',
      baseline: state(), followup: state(), latest: state(),
      findings: i < 4 ? [finding] : [], current_findings: i < 4 ? [finding] : [],
    }));
    fixture.componentRef.setInput('session', { device_comparisons: comparisons });
    fixture.detectChanges();
    const summary = fixture.nativeElement.querySelector('.findings-summary');
    expect(summary.querySelectorAll('.finding').length).toBe(1);
    expect(summary.textContent).toContain('Reported in 4 captures');
    expect(fixture.nativeElement.querySelectorAll('.capture-history .evidence').length).toBe(1);
    expect(fixture.nativeElement.querySelector('.capture-history').open).toBe(false);
    const select = fixture.nativeElement.querySelector('select');
    expect(select.options.length).toBe(5);
    select.value = '4'; select.dispatchEvent(new Event('change')); fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.capture-history .evidence').textContent).toContain('No disruption detected');
    expect(summary.textContent).toContain('BYOD-IOT');
  });

  it('keeps different findings separate and exposes incomplete device data', () => {
    const fixture = TestBed.createComponent(DeviceEvidence);
    const finding = { kind: 'port', subject: 'ge-0/0/1', before: 'up', after: 'down',
      severity: 'warning', detail: 'Port changed.', affected_clients: 0 };
    fixture.componentRef.setInput('session', { device_comparisons: [{
      triggered_at: '2026-09-09T12:00:00Z', due_at: '2026-09-09T12:05:00Z',
      baseline: state({ errors: { radios: 'Unavailable' } }), followup: state(),
      findings: [finding, { ...finding, severity: 'critical' }],
    }] });
    fixture.detectChanges();
    const summary = fixture.nativeElement.querySelector('.findings-summary');
    expect(summary.querySelectorAll('.finding').length).toBe(2);
    expect(summary.textContent).toContain('Some device data could not be collected');
  });

  it('mounts and formats both capture tables only while the source is expanded', () => {
    let formatted = 0;
    const clients = Array.from({ length: 5000 }, (_, id) => ({ id,
      stats: { toJSON: () => { formatted++; return 'sample'; } } }));
    const fixture = TestBed.createComponent(DeviceEvidence);
    fixture.componentRef.setInput('session', {
      device_comparisons: [{ baseline: state({ clients }), followup: state({ clients }), findings: [],
        triggered_at: '2026-09-09T12:00:00Z', due_at: '2026-09-09T12:05:00Z' }],
    } as Partial<MonitoringSession>);
    fixture.detectChanges();
    expect(formatted).toBe(0);
    expect(fixture.nativeElement.querySelector('app-telemetry-capture')).toBeNull();
    expect(fixture.nativeElement.textContent).toContain('5000 records → 5000 records');
    const detail = fixture.nativeElement.querySelector('.capture-history .evidence details') as HTMLDetailsElement;
    detail.open = true;
    detail.dispatchEvent(new Event('toggle'));
    fixture.detectChanges();
    expect(formatted).toBe(100);
    expect(fixture.nativeElement.querySelectorAll('tbody tr').length).toBe(100);
    click(fixture, 'Next');
    const captures = fixture.nativeElement.querySelectorAll('app-telemetry-capture');
    expect(captures[0].textContent).toContain('Records 51–100 of 5000');
    expect(captures[1].textContent).toContain('Records 1–50 of 5000');
    detail.open = false;
    detail.dispatchEvent(new Event('toggle'));
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('table')).toBeNull();
  });
});
