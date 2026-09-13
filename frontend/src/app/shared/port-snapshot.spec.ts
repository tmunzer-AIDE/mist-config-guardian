import { TestBed } from '@angular/core/testing';
import { PortSnapshotComponent } from './port-snapshot';

describe('Port snapshot', () => {
  it('distinguishes reported off and zero from missing evidence and labels neighbor uncertainty', async () => {
    await TestBed.configureTestingModule({ imports: [PortSnapshotComponent] }).compileComponents();
    const fixture = TestBed.createComponent(PortSnapshotComponent);
    fixture.componentRef.setInput('port', {
      up: false, poe_on: null, power_draw: 0, observed_at: null,
      neighbor_handle: '<img src=x onerror=alert(1)>', neighbor_identity: 'unverified',
    });
    fixture.detectChanges();
    const text = fixture.nativeElement.textContent;
    expect(text).toContain('Link: Off');
    expect(text).toContain('PoE: Unknown');
    expect(text).toContain('Power draw: 0');
    expect(text).toContain('Time unavailable');
    expect(text).toContain('Unverified neighbor');
    expect(text).toContain('does not establish a transition');
    expect(fixture.nativeElement.querySelector('img')).toBeNull();
  });
});
