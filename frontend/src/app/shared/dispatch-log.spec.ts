import { TestBed } from '@angular/core/testing';
import { DispatchLog, DispatchLogComponent } from './dispatch-log';

const reserved: DispatchLog['records'][number] = {
  id: 'attempt-one', generation: 3, candidate_revision: 2, check_id: 'wlan-client-sessions.v1',
  target_handle: 'handle', site_id: 'site-1', wlan_id: 'wlan-1',
  window: { start: '2026-09-12T11:00:00Z', end: '2026-09-12T12:00:00Z' },
  reserved_at: '2026-09-12T12:01:00Z', state: 'reserved', finished_at: null,
  http_status: null, response_bytes: null, row_count: null,
};

describe('Dispatch log', () => {
  it('keeps unfinished execution unknown and separates activity from the published report', async () => {
    await TestBed.configureTestingModule({ imports: [DispatchLogComponent] }).compileComponents();
    const fixture = TestBed.createComponent(DispatchLogComponent);
    fixture.componentRef.setInput('log', { source: 'live_investigation_root', records: [reserved], unlogged_reservations: 2 });
    fixture.detectChanges();
    const text = fixture.nativeElement.textContent as string;
    expect(text).toContain('Outcome unknown');
    expect(text).toContain('may not have reached Mist');
    expect(text).toContain('attempts outside the published report');
    expect(text).toContain('2 earlier budget reservations have no journal entry');
    expect(text).toContain('Parsed rows Unknown');
  });

  it('shows measured zero separately from missing metadata and escapes all text', async () => {
    await TestBed.configureTestingModule({ imports: [DispatchLogComponent] }).compileComponents();
    const fixture = TestBed.createComponent(DispatchLogComponent);
    fixture.componentRef.setInput('log', { source: 'live_investigation_root', unlogged_reservations: 0,
      records: [{ ...reserved, check_id: '<img src=x onerror=alert(1)>', state: 'complete',
        finished_at: '2026-09-12T12:01:01Z', http_status: 200, response_bytes: 0, row_count: 0 }] });
    fixture.detectChanges();
    const text = fixture.nativeElement.textContent as string;
    expect(text).toContain('HTTP 200 · Bytes 0');
    expect(text).toContain('Parsed rows 0');
    expect(text).not.toContain('Outcome unknown');
    expect(fixture.nativeElement.querySelector('img')).toBeNull();
  });
});
