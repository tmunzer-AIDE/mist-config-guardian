import { TestBed } from '@angular/core/testing';

import { TimeContextService } from './time-context.service';

describe('TimeContextService', () => {
  let service: TimeContextService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(TimeContextService);
  });

  it('starts at now and reports no historical mode', () => {
    expect(service.asOf()).toBeNull();
    expect(service.isHistorical()).toBe(false);
  });

  it('enters and leaves historical mode', () => {
    service.setAsOf(new Date('2026-09-07T09:12:00Z'));
    expect(service.isHistorical()).toBe(true);
    service.returnToNow();
    expect(service.isHistorical()).toBe(false);
  });

  it('maps instants onto the selected window and back', () => {
    const now = new Date('2026-09-07T14:22:00Z');
    service.setRange('24h');
    const midpoint = service.instantAt(0.5, now);
    expect(midpoint.getTime()).toBe(now.getTime() - 12 * 60 * 60 * 1000);
    expect(service.positionOf(midpoint, now)).toBeCloseTo(0.5, 5);
  });

  it('clamps positions outside the window', () => {
    const now = new Date('2026-09-07T14:22:00Z');
    expect(service.positionOf(new Date('2020-01-01T00:00:00Z'), now)).toBe(0);
    expect(service.positionOf(new Date('2030-01-01T00:00:00Z'), now)).toBe(1);
  });
});
