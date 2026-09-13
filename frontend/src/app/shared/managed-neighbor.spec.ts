import { TestBed } from '@angular/core/testing';
import { ManagedNeighborComponent } from './managed-neighbor';

describe('Managed neighbor evidence', () => {
  it('shows membership without claiming a physical dependency or impact and escapes handles', async () => {
    await TestBed.configureTestingModule({ imports: [ManagedNeighborComponent] }).compileComponents();
    const fixture = TestBed.createComponent(ManagedNeighborComponent);
    fixture.componentRef.setInput('neighbor', {
      device_handle: '<img src=x onerror=alert(1)>', kind: 'ap',
      identity: 'verified_inventory', relationship: 'unverified',
    });
    fixture.componentRef.setInput('capturedAt', '2026-09-13T12:34:56Z');
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Managed AP inventory match');
    expect(fixture.nativeElement.textContent).toContain('verified at collection time');
    expect(fixture.nativeElement.textContent).toContain('Collected: 2026-09-13T12:34:56Z');
    expect(fixture.nativeElement.textContent).toContain('physical link, PoE dependency and impact remain unverified');
    expect(fixture.nativeElement.querySelector('img')).toBeNull();
  });
});
