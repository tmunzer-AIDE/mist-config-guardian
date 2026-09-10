import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { signal } from '@angular/core';
import { OrganizationContextService } from '../../core/organization-context.service';
import { TimeContextService } from '../../core/time-context.service';
import { SiteImpactPage } from './site-impact-page';
import { SiteChange, TopologyLink, impactDevices } from './site-impact.model';
import { change, impact } from './site-impact.fixtures';

describe('site Impact workspace', () => {
  let fixture: ComponentFixture<SiteImpactPage>,
    http: HttpTestingController,
    time: TimeContextService;
  const org = signal({ id: 'org1' });
  const changes = [
    change(),
    change({
      id: 'c2',
      impacts: [impact({ device_id: '112233445566', device_name: 'Other AP', session_id: 's2' })],
    }),
  ];
  function flushSite(items = changes, total = items.length, links?: TopologyLink[]) {
    http
      .expectOne((r) => r.url.endsWith('/topology'))
      .flush({
        site_id: 'site1',
        links,
        source: 'mist',
        devices: impactDevices([], changes),
        warnings: [],
        complete: true,
        collected_at: null,
      });
    http
      .expectOne((r) => r.url.endsWith('/changes'))
      .flush({ items, total, historical: false, as_of: '2026-09-09T12:00:00Z' });
    fixture.detectChanges();
  }
  function panel() {
    return fixture.nativeElement.querySelector('.details').getAttribute('data-panel');
  }
  function chooseRow(index = 0) {
    fixture.nativeElement.querySelectorAll('.change-row')[index].click();
    fixture.detectChanges();
  }
  function chooseNode(index = 0) {
    fixture.nativeElement.querySelectorAll('.node')[index].click();
    fixture.detectChanges();
  }
  beforeEach(async () => {
    vi.stubGlobal(
      'ResizeObserver',
      class {
        observe() {}
        disconnect() {}
      },
    );
    org.set({ id: 'org1' });
    await TestBed.configureTestingModule({
      imports: [SiteImpactPage],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: OrganizationContextService, useValue: { selected: org } },
      ],
    }).compileComponents();
    http = TestBed.inject(HttpTestingController);
    time = TestBed.inject(TimeContextService);
    fixture = TestBed.createComponent(SiteImpactPage);
    fixture.detectChanges();
  });
  afterEach(() => {
    fixture.destroy();
    http.verify();
    vi.unstubAllGlobals();
  });
  function load(links?: TopologyLink[]) {
    http
      .expectOne((r) => r.url.endsWith('/sites'))
      .flush({
        items: [
          { id: 'site1', name: 'Paris' },
          { id: 'site2', name: 'London' },
        ],
      });
    fixture.detectChanges();
    flushSite(changes, changes.length, links);
  }
  it('mounts one contextual panel and follows all four selection states', () => {
    load();
    expect(panel()).toBe('site');
    chooseRow();
    expect(panel()).toBe('change');
    chooseNode();
    expect(panel()).toBe('device-change');
    chooseNode(1);
    expect(panel()).toBe('device');
    expect(fixture.nativeElement.textContent).toContain('Not in the scope');
    fixture.nativeElement.querySelector('.history-row').click();
    fixture.detectChanges();
    expect(panel()).toBe('device-change');
    expect(fixture.nativeElement.querySelectorAll('.details').length).toBe(1);
  });
  it('renders explicit neighbor links and lets the operator open a peer from its port evidence', () => {
    load([{
      source: 'aabbccddeeff', target: '112233445566',
      source_ports: ['ge-0/0/0'], target_ports: ['eth0'],
    }]);
    expect(fixture.nativeElement.querySelectorAll('.links path').length).toBe(1);
    chooseNode();
    const neighbors = fixture.nativeElement.querySelector('details.detail-section');
    expect(neighbors.textContent).toContain('Observed neighbors · 1');
    expect(neighbors.textContent).toContain('ge-0/0/0 → eth0');
    neighbors.querySelector('button').click();
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.detail-head h2').textContent).toContain('Other AP');
    expect(fixture.nativeElement.querySelector('details.detail-section').textContent).toContain('eth0 → ge-0/0/0');
  });
  it('toggles a change and clears its device selection', () => {
    load();
    chooseRow();
    chooseNode();
    chooseRow();
    expect(panel()).toBe('site');
    expect(fixture.nativeElement.querySelectorAll('.node.selected').length).toBe(0);
  });
  it('clears the prior site immediately and cancels its pending reads', () => {
    load();
    chooseRow();
    const select = fixture.nativeElement.querySelector('select');
    select.value = 'site2';
    select.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    expect(panel()).toBe('site');
    expect(fixture.nativeElement.querySelectorAll('.node').length).toBe(0);
    const stale = http.match((r) => r.url.includes('/sites/site2/'));
    select.value = 'site1';
    select.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    expect(stale.every((r) => r.cancelled)).toBe(true);
    flushSite();
  });
  it('retries the initial sites request after a failure', () => {
    http
      .expectOne((r) => r.url.endsWith('/sites'))
      .flush({}, { status: 500, statusText: 'Failed' });
    fixture.detectChanges();
    const retry = [...fixture.nativeElement.querySelectorAll('button')].find(
      (b: any) => b.textContent.trim() === 'Retry',
    ) as HTMLButtonElement;
    retry.click();
    fixture.detectChanges();
    load();
    expect(fixture.nativeElement.textContent).toContain('Paris');
  });
  it('retains loaded pages and selection on refresh', () => {
    http
      .expectOne((r) => r.url.endsWith('/sites'))
      .flush({ items: [{ id: 'site1', name: 'Paris' }] });
    fixture.detectChanges();
    const first = Array.from({ length: 50 }, (_, i) => change({ id: 'first' + i }));
    flushSite(first, 51);
    fixture.nativeElement.querySelector('.load-more').click();
    http
      .expectOne((r) => r.url.endsWith('/changes') && r.params.get('skip') === '50')
      .flush({ items: [change({ id: 'older' })], total: 51 });
    fixture.detectChanges();
    chooseRow(50);
    fixture.nativeElement.querySelector('.topology-foot button').click();
    fixture.detectChanges();
    http
      .expectOne((r) => r.url.endsWith('/topology'))
      .flush({ devices: [], warnings: [], source: 'stored' });
    http
      .expectOne((r) => r.url.endsWith('/changes') && r.params.get('skip') === '0')
      .flush({ items: first, total: 51 });
    http
      .expectOne((r) => r.url.endsWith('/changes') && r.params.get('skip') === '50')
      .flush({ items: [change({ id: 'older' })], total: 51 });
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelectorAll('.change-row').length).toBe(51);
    expect(panel()).toBe('change');
  });
  it('withholds drilldown links in historical inspection', () => {
    load();
    time.setAsOf(new Date('2026-09-09T11:00:00Z'));
    fixture.detectChanges();
    load();
    chooseRow();
    chooseNode();
    const evidence = fixture.nativeElement.querySelector('.actions a');
    expect(evidence.getAttribute('aria-disabled')).toBe('true');
    expect(evidence.getAttribute('href')).toBeNull();
  });
  it('clears the old organization before loading a new one', () => {
    load();
    org.set({ id: 'org2' });
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelectorAll('.change-row').length).toBe(0);
    const stale = http.match((r) => r.url.includes('/organizations/org2/'));
    expect(stale.some((r) => r.request.url.endsWith('/sites'))).toBe(true);
    for (const req of stale) req.flush({ items: [] });
    fixture.detectChanges();
  });
});
