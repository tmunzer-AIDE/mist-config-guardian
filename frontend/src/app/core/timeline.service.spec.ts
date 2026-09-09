import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TimelineService } from './timeline.service';

describe('timeline window ownership', () => {
  let service: TimelineService, http: HttpTestingController;
  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(TimelineService);
    http = TestBed.inject(HttpTestingController);
  });
  afterEach(() => http.verify());
  it('clears the previous organization bounds and ignores a late response', async () => {
    const old = service.load('one', '24h');
    const previous = http.expectOne((r) => r.url.includes('/one/'));
    service.bounds.set({ start: new Date(0), end: new Date(1) });
    const latest = service.load('two', '7d');
    expect(service.bounds()).toBeNull();
    const current = http.expectOne((r) => r.url.includes('/two/'));
    current.flush({
      items: [],
      range_start: '2026-01-01T00:00:00Z',
      range_end: '2026-01-08T00:00:00Z',
    });
    await latest;
    previous.flush({ items: [], range_start: '2025-01-01', range_end: '2025-01-02' });
    await old;
    expect(service.bounds()?.end.toISOString()).toBe('2026-01-08T00:00:00.000Z');
  });
  it('falls back safely on invalid bounds and clears them on failure', async () => {
    const read = service.load('one', '24h');
    http
      .expectOne((r) => r.url.includes('/one/'))
      .flush({ items: [], range_start: 'invalid', range_end: 'invalid' });
    await read;
    expect(service.bounds()).toBeNull();
    service.bounds.set({ start: new Date(0), end: new Date(1) });
    const failed = service.load('one', '24h');
    http.expectOne((r) => r.url.includes('/one/')).flush({}, { status: 500, statusText: 'Failed' });
    await failed;
    expect(service.bounds()).toBeNull();
  });
});
