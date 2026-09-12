import { TestBed, ComponentFixture } from '@angular/core/testing';
import { signal } from '@angular/core';
import { AppTimeBar } from './app-time-bar';
import { TimeContextService } from '../core/time-context.service';
import { TimelineService } from '../core/timeline.service';

describe('global time selection', () => {
  let fixture: ComponentFixture<AppTimeBar>, time: TimeContextService;
  const start = new Date('2026-01-01T00:00:00Z'),
    end = new Date('2026-01-02T00:00:00Z');
  const markers = signal([
    {
      at: '2026-01-01T12:00:00Z',
      severity: 'critical',
      label: 'Template applied',
      impact_known: false,
    },
  ]);
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [AppTimeBar],
      providers: [
        { provide: TimelineService, useValue: { bounds: signal({ start, end }), markers } },
      ],
    });
    fixture = TestBed.createComponent(AppTimeBar);
    time = TestBed.inject(TimeContextService);
    fixture.detectChanges();
  });
  afterEach(() => fixture.destroy());
  function key(key: string) {
    fixture.nativeElement
      .querySelector('.track-seek')
      .dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true }));
    fixture.detectChanges();
  }
  it('exposes the displayed window and preserves unknown marker severity', () => {
    expect(fixture.nativeElement.textContent).toContain('01 JAN');
    expect(fixture.nativeElement.querySelector('.tick').dataset.tone).toBe('unknown');
    expect(fixture.nativeElement.querySelector('[role=slider] .tick')).toBeNull();
  });
  it('selects an exact event timestamp and returns explicitly to Live', () => {
    fixture.nativeElement.querySelector('.tick').click();
    fixture.detectChanges();
    expect(time.asOf()?.toISOString()).toBe('2026-01-01T12:00:00.000Z');
    expect(fixture.nativeElement.querySelector('[role=slider]').getAttribute('aria-valuenow')).toBe(
      '50',
    );
    fixture.nativeElement.querySelector('.live-button').click();
    expect(time.isHistorical()).toBe(false);
  });
  it('supports bounded keyboard selection and escape to live', () => {
    key('Home');
    expect(time.asOf()).toEqual(start);
    key('ArrowLeft');
    expect(time.asOf()).toEqual(start);
    key('End');
    expect(time.asOf()).toEqual(end);
    key('ArrowRight');
    expect(time.asOf()).toEqual(end);
    key('Escape');
    expect(time.asOf()).toBeNull();
  });
  it('parses the explicitly labeled time as UTC, independent of browser timezone', () => {
    const input = fixture.nativeElement.querySelector('input');
    input.value = '2026-01-01T04:05:06';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    fixture.nativeElement
      .querySelector('form')
      .dispatchEvent(new Event('submit', { cancelable: true }));
    expect(time.asOf()?.toISOString()).toBe('2026-01-01T04:05:06.000Z');
  });
  it('keeps the track stable when a historical response shifts the server window', () => {
    key('Home');
    const timeline = TestBed.inject(TimelineService);
    timeline.bounds.set({ start: new Date('2025-12-31T00:00:00Z'), end: start });
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('[role=slider]').getAttribute('aria-valuenow')).toBe(
      '0',
    );
    key('End');
    expect(time.asOf()).toEqual(end);
  });
  it('uses fresh bounds when returning live from the shell banner', () => {
    key('Home');
    const timeline = TestBed.inject(TimelineService);
    const refreshedEnd = new Date('2026-01-03T00:00:00Z');
    timeline.bounds.set({ start: end, end: refreshedEnd });
    time.returnToNow();
    fixture.detectChanges();
    key('End');
    expect(time.asOf()).toEqual(refreshedEnd);
  });
  it('rejects a cleared date instead of silently using the current time', () => {
    const input = fixture.nativeElement.querySelector('input');
    input.value = '';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    fixture.nativeElement
      .querySelector('form')
      .dispatchEvent(new Event('submit', { cancelable: true }));
    fixture.detectChanges();
    expect(time.asOf()).toBeNull();
    expect(fixture.nativeElement.querySelector('[role=alert]')).not.toBeNull();
  });
  it('selects events through the menu when markers overlap', () => {
    const menu = fixture.nativeElement.querySelector('select');
    menu.value = '2026-01-01T12:00:00Z';
    menu.dispatchEvent(new Event('change'));
    expect(time.asOf()?.toISOString()).toBe('2026-01-01T12:00:00.000Z');
    expect(menu.value).toBe('');
  });
  it('rejects future dates without leaving live mode', () => {
    const input = fixture.nativeElement.querySelector('input');
    input.value = '2999-01-01T04:05';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    fixture.nativeElement
      .querySelector('form')
      .dispatchEvent(new Event('submit', { cancelable: true }));
    fixture.detectChanges();
    expect(time.asOf()).toBeNull();
    expect(fixture.nativeElement.querySelector('[role=alert]').textContent).toContain('past (UTC)');
  });
});
