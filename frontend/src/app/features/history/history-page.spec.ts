import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Component } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';

import { API_ROOT } from '../../core/api';
import { Organization } from '../../core/organization.model';
import { OrganizationContextService } from '../../core/organization-context.service';
import { UiStateService } from '../../core/ui-state.service';
import { AiSettings } from './ai-assist.service';
import { ConfigurationDiff, DiffEntry, DiffSection } from './diff.model';
import { ConfigurationObject, ConfigurationVersion } from './history.model';
import { HistoryPage } from './history-page';

@Component({ selector: 'app-blank', template: '' })
class Blank {}

const ORGANIZATION = { id: 'org-1', name: 'Northwind Retail' } as unknown as Organization;
const OTHER_ORGANIZATION = { id: 'org-2', name: 'Contoso' } as unknown as Organization;

const SETTINGS: AiSettings = {
  enabled: true,
  base_url: 'https://api.openai.example/v1',
  model: 'gpt-4o-mini',
  api_key_set: true,
  api_key_last_four: '7Qd3',
  max_response_tokens: 1500,
  automatic_summaries: false,
  last_test_at: null,
  last_test_ok: null,
  last_test_detail: null,
};

function object(id: string, name: string): ConfigurationObject {
  return {
    id,
    scope: 'org',
    object_type: 'wlan',
    current_mist_id: '4d0e1111-2222-3333-4444-5555666677b2',
    site_mist_id: null,
    name,
    is_deleted: false,
    current_version: 15,
    updated_at: '2026-09-07T09:12:00Z',
  };
}

function version(id: string, n: number): ConfigurationVersion {
  return {
    id,
    version: n,
    event: n === 1 ? 'initial' : 'updated',
    configuration: {},
    changed_fields: [],
    is_deleted: false,
    observed_at: `2026-09-0${n}T09:12:00Z`,
    actor: 'j.mercer',
    audit_id: null,
  };
}

function entry(field: string, section: string, notable = false): DiffEntry {
  return {
    field,
    kind: 'MODIFIED',
    before: 'Indoor-Std-5G',
    after: 'Indoor-Dense-6G',
    note: 'A different RF plan now governs 6 APs.',
    section,
    notable,
    secret: false,
    secret_unknown: false,
    reordered: false,
  };
}

function section(key: string, name: string, entries: DiffEntry[], included: boolean): DiffSection {
  return {
    key,
    name,
    path: `${key}{}`,
    counts: { changed: entries.length || 3, added: 0, modified: entries.length || 3, removed: 0 },
    detail: '3 modified',
    notable: 0,
    entries: included ? entries : [],
    entries_included: included,
  };
}

function diff(overrides: Partial<ConfigurationDiff> = {}): ConfigurationDiff {
  return {
    mode: 'chips',
    summary: '3 fields changed · 0 added · 3 modified · 0 removed',
    counts: { changed: 3, added: 0, modified: 3, removed: 0 },
    entries: [],
    notable: [],
    sections: [],
    entries_included: true,
    truncated: false,
    secret_fields: 0,
    from_version: null,
    to_version: null,
    ...overrides,
  };
}

describe('HistoryPage', () => {
  let http: HttpTestingController;
  let ui: UiStateService;

  beforeEach(async () => {
    try {
      localStorage.clear();
    } catch {
      // Storage is unavailable in the test environment; selection still applies.
    }
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([{ path: '**', component: Blank }]),
      ],
    });
    http = TestBed.inject(HttpTestingController);
    ui = TestBed.inject(UiStateService);
    const organizations = TestBed.inject(OrganizationContextService);
    const loaded = organizations.load();
    http.expectOne('/api/v1/organizations').flush({ items: [ORGANIZATION], total: 1 });
    await loaded;
  });

  /**
   * Drain the promise chain a response starts — the HTTP callback, the service
   * continuation, and the component's own await all land on separate turns —
   * then render what they produced.
   */
  async function settle(fixture: ComponentFixture<HistoryPage>): Promise<void> {
    for (let pass = 0; pass < 4; pass += 1) {
      await fixture.whenStable();
      fixture.detectChanges();
    }
    await fixture.whenStable();
  }

  /** Create the page and answer the object, version, and metadata requests. */
  async function open(
    versions: ConfigurationVersion[],
    meta: ConfigurationDiff,
  ): Promise<ComponentFixture<HistoryPage>> {
    const fixture = TestBed.createComponent(HistoryPage);
    fixture.detectChanges();
    http.expectOne(`${API_ROOT}/ai/settings`).flush(SETTINGS);
    http
      .expectOne((request) => request.url === '/api/v1/organizations/org-1/objects')
      .flush({ items: [object('obj-1', 'NW-Corp')], total: 1 });
    await settle(fixture);

    http
      .expectOne((request) => request.url === '/api/v1/organizations/org-1/objects/obj-1/versions')
      .flush({ items: versions, total: versions.length });
    await settle(fixture);

    http
      .expectOne(
        (request) =>
          request.url === '/api/v1/organizations/org-1/diff' &&
          request.params.get('include_entries') === 'false',
      )
      .flush(meta);
    await settle(fixture);
    showVersions(fixture);
    return fixture;
  }

  function showLibrary(fixture: ComponentFixture<HistoryPage>): void {
    const back = [...fixture.nativeElement.querySelectorAll('button')].find((button: any) => button.textContent.includes('All objects')) as HTMLButtonElement | undefined;
    back?.click();
    fixture.detectChanges();
  }
  function showVersions(fixture: ComponentFixture<HistoryPage>): void {
    const back = fixture.nativeElement.querySelector('.return-selected') as HTMLButtonElement | null;
    back?.click();
    fixture.detectChanges();
  }
  function libraryFilter(fixture: ComponentFixture<HistoryPage>): HTMLInputElement {
    showLibrary(fixture);
    return fixture.nativeElement.querySelector('.filter-input');
  }
  function comparisonName(fixture: ComponentFixture<HistoryPage>): string | undefined {
    return (fixture.componentInstance as unknown as { selectedObject(): ConfigurationObject | null }).selectedObject()?.name;
  }

  function pins(fixture: ComponentFixture<HistoryPage>): HTMLButtonElement[][] {
    showVersions(fixture);
    const element = fixture.nativeElement as HTMLElement;
    return [...element.querySelectorAll('.version')].map((row) => [
      ...row.querySelectorAll<HTMLButtonElement>('.pin'),
    ]);
  }

  function pinned(fixture: ComponentFixture<HistoryPage>): string[] {
    return pins(fixture).map((row) =>
      row
        .map((pin, index) => (pin.getAttribute('aria-pressed') === 'true' ? (index === 0 ? 'A' : 'B') : ''))
        .join(''),
    );
  }

  // ---- object rail: server-side search and paging -------------------------

  /** Create the page with an object rail of `total` matches, page one flushed. */
  async function openRail(items: ConfigurationObject[], total: number) {
    const fixture = TestBed.createComponent(HistoryPage);
    fixture.detectChanges();
    http.expectOne(`${API_ROOT}/ai/settings`).flush(SETTINGS);
    const first = http.expectOne((request) => request.url === '/api/v1/organizations/org-1/objects');
    first.flush({ items, total });
    await settle(fixture);
    return { fixture, first };
  }

  function railText(fixture: ComponentFixture<HistoryPage>): string {
    return ((fixture.nativeElement as HTMLElement).textContent ?? '').replace(/\s+/g, ' ');
  }

  /** Open the page with `?object=` already set, as a notification link does. */
  async function openDeepLinked(objectId: string, items: ConfigurationObject[], total: number) {
    // The page reads the link from the route snapshot in its constructor, so
    // the URL has to carry it before the component exists.
    await TestBed.inject(Router).navigate([], { queryParams: { object: objectId } });
    const fixture = TestBed.createComponent(HistoryPage);
    fixture.detectChanges();
    http.expectOne(`${API_ROOT}/ai/settings`).flush(SETTINGS);
    http
      .expectOne((request) => request.url === '/api/v1/organizations/org-1/objects')
      .flush({ items, total });
    await settle(fixture);
    return fixture;
  }

  it('keeps a deep-linked object that sorts past the page it loaded', async () => {
    // obj-99 matches the filters but falls on a later page, so the rail does
    // not contain it. Replacing the selection would quietly open a different
    // object than the link named.
    const fixture = await openDeepLinked('obj-99', [object('obj-1', 'NW-Corp')], 124);

    const versions = http.expectOne(
      (request) => request.url === '/api/v1/organizations/org-1/objects/obj-99/versions',
    );
    expect(versions.request.method).toBe('GET');
    http.expectNone((request) => request.url.includes('/objects/obj-1/versions'));
    versions.flush({ items: [], total: 0 });

    // The rail cannot describe an object it does not hold, so the object is
    // resolved on its own — otherwise the comparison panel has no name to show
    // and renders nothing at all.
    http
      .expectOne((request) => request.url === '/api/v1/organizations/org-1/objects/obj-99')
      .flush(object('obj-99', 'Deep Linked WLAN'));
    await settle(fixture);

    const panel = (fixture.nativeElement as HTMLElement).querySelector('.panel-name');
    expect(panel?.textContent).toContain('Deep Linked WLAN');
  });

  it('re-resolves the compared object when a new page stops holding it', async () => {
    const { fixture } = await openRail([object('obj-1', 'NW-Corp')], 124);

    http
      .expectOne((request) => request.url === '/api/v1/organizations/org-1/objects/obj-1/versions')
      .flush({ items: [], total: 0 });
    await settle(fixture);
    http.expectNone((request) => request.url === '/api/v1/organizations/org-1/objects/obj-1');

    // The selection does not change here — the page under it does. A search
    // narrows the rail to something else while the comparison stays open.
    const filter = libraryFilter(fixture);
    filter!.value = 'guest';
    filter!.dispatchEvent(new Event('input'));
    await new Promise((resolve) => setTimeout(resolve, 320));
    await settle(fixture);
    http
      .expectOne((request) => request.url === '/api/v1/organizations/org-1/objects')
      .flush({ items: [object('obj-7', 'Guest WLAN')], total: 1 });
    await settle(fixture);

    http
      .expectOne((request) => request.url === '/api/v1/organizations/org-1/objects/obj-1')
      .flush(object('obj-1', 'NW-Corp'));
    await settle(fixture);

    expect(
      comparisonName(fixture),
    ).toContain('NW-Corp');
  });

  it('ignores a resolver failure for an object that is no longer selected', async () => {
    // A read for the deep-linked object is left in flight while the selection
    // moves on and a second read succeeds for a different object.
    const fixture = await openDeepLinked('obj-99', [object('obj-1', 'NW-Corp')], 124);
    http
      .expectOne((request) => request.url === '/api/v1/organizations/org-1/objects/obj-99/versions')
      .flush({ items: [], total: 0 });
    const stale = http.expectOne(
      (request) => request.url === '/api/v1/organizations/org-1/objects/obj-99',
    );
    await settle(fixture);

    showLibrary(fixture);
    (fixture.nativeElement as HTMLElement).querySelector<HTMLButtonElement>('.object-link')!.click();
    await settle(fixture);
    http
      .expectOne((request) => request.url === '/api/v1/organizations/org-1/objects/obj-1/versions')
      .flush({ items: [], total: 0 });
    await settle(fixture);

    // A search pushes the now-selected object off the rail, so it is resolved
    // on its own and the panel is named from that.
    const filter = libraryFilter(fixture);
    filter!.value = 'guest';
    filter!.dispatchEvent(new Event('input'));
    await new Promise((resolve) => setTimeout(resolve, 320));
    await settle(fixture);
    http
      .expectOne((request) => request.url === '/api/v1/organizations/org-1/objects')
      .flush({ items: [object('obj-7', 'Guest WLAN')], total: 1 });
    await settle(fixture);
    http
      .expectOne((request) => request.url === '/api/v1/organizations/org-1/objects/obj-1')
      .flush(object('obj-1', 'NW-Corp'));
    await settle(fixture);
    expect(
      comparisonName(fixture),
    ).toContain('NW-Corp');

    // The abandoned read fails last. It describes an object nobody is looking
    // at, so it must not blank the panel that is on screen.
    stale.flush('gone', { status: 404, statusText: 'Not Found' });
    await settle(fixture);

    expect(
      comparisonName(fixture),
    ).toContain('NW-Corp');
  });

  it('lets an abandoned read finish without disowning the one that replaced it', async () => {
    const objectsUrl = '/api/v1/organizations/org-1/objects';
    const detailUrl = `${objectsUrl}/obj-1`;

    async function search(term: string, items: ConfigurationObject[]): Promise<void> {
      const filter = libraryFilter(fixture);
      filter!.value = term;
      filter!.dispatchEvent(new Event('input'));
      await new Promise((resolve) => setTimeout(resolve, 320));
      await settle(fixture);
      http.expectOne((request) => request.url === objectsUrl).flush({ items, total: 124 });
      await settle(fixture);
    }

    const { fixture } = await openRail([object('obj-1', 'NW-Corp')], 124);
    http.expectOne((request) => request.url === `${detailUrl}/versions`).flush({ items: [], total: 0 });
    await settle(fixture);

    // Off the rail: the first read starts. It is never answered until later.
    await search('guest', [object('obj-7', 'Guest WLAN')]);
    const abandoned = http.expectOne((request) => request.url === detailUrl);

    // Back on the rail, which abandons that read, then off it again, which
    // starts a second one for the very same object.
    await search('', [object('obj-1', 'NW-Corp')]);
    await search('guest', [object('obj-7', 'Guest WLAN')]);
    // Deliberately left in flight, and not consumed by an expectation: the
    // assertion at the end counts what is still outstanding.
    expect(http.match((request) => request.url === detailUrl)).toHaveLength(1);

    // The abandoned read answers last. Its cleanup names an id, and that id
    // now belongs to the read that replaced it.
    abandoned.flush(object('obj-1', 'NW-Corp'));
    await settle(fixture);

    // Any later run of the resolver must still see a read in flight.
    const more = [...(fixture.nativeElement as HTMLElement).querySelectorAll('button')].find((node) =>
      (node.textContent ?? '').includes('Load more'),
    ) as HTMLButtonElement;
    more.click();
    await settle(fixture);
    http
      .expectOne((request) => request.url === objectsUrl)
      .flush({ items: [object('obj-8', 'Lab')], total: 124 });
    await settle(fixture);

    // With the cleanup keyed on the id rather than the read, the abandoned
    // one disowns its replacement and a third request goes out for the same
    // object.
    expect(http.match((request) => request.url === detailUrl)).toHaveLength(0);
  });

  it('does not re-fetch an object the rail already describes', async () => {
    const { fixture } = await openRail([object('obj-1', 'NW-Corp')], 124);

    http
      .expectOne((request) => request.url === '/api/v1/organizations/org-1/objects/obj-1/versions')
      .flush({ items: [], total: 0 });
    await settle(fixture);

    http.expectNone((request) => request.url === '/api/v1/organizations/org-1/objects/obj-1');
    expect(
      comparisonName(fixture),
    ).toContain('NW-Corp');
  });

  it('selects the first row only when nothing is selected yet', async () => {
    const { fixture } = await openRail([object('obj-1', 'NW-Corp')], 124);

    http
      .expectOne((request) => request.url === '/api/v1/organizations/org-1/objects/obj-1/versions')
      .flush({ items: [], total: 0 });
    await settle(fixture);

    // A search that hides the object being compared must not end the
    // comparison, so the selection survives a page it is absent from.
    const filter = libraryFilter(fixture);
    filter!.value = 'guest';
    filter!.dispatchEvent(new Event('input'));
    await new Promise((resolve) => setTimeout(resolve, 320));
    await settle(fixture);

    http
      .expectOne((request) => request.url === '/api/v1/organizations/org-1/objects')
      .flush({ items: [object('obj-7', 'Guest WLAN')], total: 1 });
    await settle(fixture);

    http.expectNone((request) => request.url.includes('/objects/obj-7/versions'));
  });

  it('reads the rail one page at a time and says how much it is showing', async () => {
    const page = [object('obj-1', 'NW-Corp'), object('obj-2', 'Guest')];
    const { fixture, first } = await openRail(page, 124);

    expect(first.request.params.get('limit')).toBe('50');
    expect(first.request.params.get('skip')).toBe('0');
    expect(railText(fixture)).toContain('Showing 2 of 124');

    const more = [...fixture.nativeElement.querySelectorAll('button')].find((node: HTMLButtonElement) =>
      (node.textContent ?? '').includes('Load more'),
    ) as HTMLButtonElement;
    more.click();
    await settle(fixture);

    const next = http.expectOne((request) => request.url === '/api/v1/organizations/org-1/objects');
    expect(next.request.params.get('skip')).toBe('2');
    next.flush({ items: [object('obj-3', 'Lab')], total: 124 });
    await settle(fixture);

    // Appended, not replaced: the object being compared stays on screen.
    expect(railText(fixture)).toContain('Showing 3 of 124');
    expect(fixture.nativeElement.querySelectorAll('.object-link').length).toBe(3);
  });

  it('sends the filter to the server rather than narrowing the page it holds', async () => {
    const { fixture } = await openRail([object('obj-1', 'NW-Corp')], 124);

    const filter = libraryFilter(fixture);
    filter!.value = 'guest';
    filter!.dispatchEvent(new Event('input'));
    // The term trails the keystroke by a debounce.
    http.expectNone((request) => request.url === '/api/v1/organizations/org-1/objects');
    await new Promise((resolve) => setTimeout(resolve, 320));
    await settle(fixture);

    const search = http.expectOne((request) => request.url === '/api/v1/organizations/org-1/objects');
    expect(search.request.params.get('q')).toBe('guest');
    // A new term is a new list, read from the first row.
    expect(search.request.params.get('skip')).toBe('0');
    search.flush({ items: [object('obj-7', 'Guest WLAN')], total: 1 });
    await settle(fixture);

    expect(fixture.nativeElement.querySelectorAll('.object-link').length).toBe(1);
    expect(railText(fixture)).toContain('Showing 1 of 1');
  });

  it('offers no further page once the rail holds every match', async () => {
    const { fixture } = await openRail([object('obj-1', 'NW-Corp')], 1);
    const labels = [...fixture.nativeElement.querySelectorAll('button')].map(
      (node: HTMLButtonElement) => node.textContent ?? '',
    );

    expect(labels.some((label: string) => label.includes('Load more'))).toBe(false);
    expect(railText(fixture)).toContain('Showing 1 of 1');
  });

  it('defaults to the two newest versions and re-pins A on demand', async () => {
    const versions = [version('v-3', 3), version('v-2', 2), version('v-1', 1)];
    const fixture = await open(versions, diff());
    http
      .expectOne((request) => request.url === '/api/v1/organizations/org-1/diff')
      .flush(diff({ entries: [entry('rf_template_id', 'rf')] }));
    await settle(fixture);

    // Newest is B, previous is A.
    expect(pinned(fixture)).toEqual(['B', 'A', '']);

    // A is independently selectable: pin the oldest version to A.
    pins(fixture)[2][0].click();
    await settle(fixture);

    expect(pinned(fixture)).toEqual(['B', '', 'A']);
    const reload = http.expectOne(
      (request) =>
        request.url === '/api/v1/organizations/org-1/diff' &&
        request.params.get('include_entries') === 'false',
    );
    expect(reload.request.params.get('from_version_id')).toBe('v-1');
    expect(reload.request.params.get('to_version_id')).toBe('v-3');
    reload.flush(diff());
  });

  it('forgets the object and versions on screen when the organization changes', async () => {
    // Identifiers belong to the organization they were read from; under
    // another they name nothing, and reads for them can only fail.
    const fixture = await open([version('v-2', 2), version('v-1', 1)], diff());
    http.expectOne((request) => request.url === '/api/v1/organizations/org-1/diff').flush(diff());
    await settle(fixture);

    const organizations = TestBed.inject(OrganizationContextService);
    const reloaded = organizations.load(true);
    http.expectOne('/api/v1/organizations').flush({ items: [ORGANIZATION, OTHER_ORGANIZATION], total: 2 });
    await reloaded;
    organizations.select('org-2');
    await settle(fixture);

    http.expectNone((request) => request.url.startsWith('/api/v1/organizations/org-2/objects/obj-1'));
    http.expectNone((request) => request.url === '/api/v1/organizations/org-2/diff');
    http
      .expectOne((request) => request.url === '/api/v1/organizations/org-2/objects')
      .flush({ items: [object('obj-9', 'Contoso-Guest')], total: 1 });
    await settle(fixture);
    // The new organization's own first object is what gets read next.
    http
      .expectOne((request) => request.url === '/api/v1/organizations/org-2/objects/obj-9/versions')
      .flush({ items: [], total: 0 });
    await settle(fixture);

    expect(ui.error()).toBeNull();
  });

  it('moves the selection with j and k, but never from inside a text field', async () => {
    const versions = [version('v-3', 3), version('v-2', 2), version('v-1', 1)];
    const fixture = await open(versions, diff());
    http.expectOne((request) => request.url === '/api/v1/organizations/org-1/diff').flush(diff());
    await settle(fixture);

    const element = fixture.nativeElement as HTMLElement;
    const filter = libraryFilter(fixture);
    expect(filter).not.toBeNull();

    // A keystroke typed into the filter is text, not a command.
    filter?.dispatchEvent(new KeyboardEvent('keydown', { key: 'j', bubbles: true }));
    await settle(fixture);
    expect(pinned(fixture)).toEqual(['B', 'A', '']);

    document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'j', bubbles: true }));
    await settle(fixture);
    expect(pinned(fixture)).toEqual(['', 'B', 'A']);

    http
      .expectOne(
        (request) =>
          request.url === '/api/v1/organizations/org-1/diff' &&
          request.params.get('include_entries') === 'false',
      )
      .flush(diff());
    await settle(fixture);

    document.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', bubbles: true }));
    await settle(fixture);
    expect(pinned(fixture)).toEqual(['B', 'A', '']);
  });

  it('fetches a section body only when the section is opened', async () => {
    const versions = [version('v-3', 3), version('v-2', 2)];
    const sections = [
      section('networks', 'Networks', [], false),
      section('bgp', 'BGP', [], false),
    ];
    const fixture = await open(
      versions,
      diff({
        mode: 'sections',
        counts: { changed: 14, added: 3, modified: 10, removed: 1 },
        summary: '14 fields changed · 3 added · 10 modified · 1 removed',
        entries_included: false,
        sections,
      }),
    );

    // The first section opens on arrival and is the only body requested.
    const first = http.expectOne(
      (request) =>
        request.url === '/api/v1/organizations/org-1/diff' && request.params.get('sections') !== null,
    );
    expect(first.request.params.get('sections')).toBe('networks');
    first.flush(
      diff({
        mode: 'sections',
        sections: [
          section('networks', 'Networks', [entry('corp-data.subnet', 'networks')], true),
          section('bgp', 'BGP', [], false),
        ],
      }),
    );
    await settle(fixture);

    const element = fixture.nativeElement as HTMLElement;
    const heads = [...element.querySelectorAll<HTMLButtonElement>('.section-head')];
    expect(heads.length).toBe(2);
    expect(heads[0].getAttribute('aria-expanded')).toBe('true');
    expect(element.textContent).toContain('corp-data.subnet');

    heads[1].click();
    await settle(fixture);

    const second = http.expectOne(
      (request) =>
        request.url === '/api/v1/organizations/org-1/diff' && request.params.get('sections') === 'bgp',
    );
    second.flush(
      diff({
        mode: 'sections',
        sections: [section('bgp', 'BGP', [entry('local_as', 'bgp')], true)],
      }),
    );
    await settle(fixture);

    expect(element.textContent).toContain('local_as');
    // Re-opening a loaded section asks for nothing more.
    heads[1].click();
    await settle(fixture);
    heads[1].click();
    await settle(fixture);
    http.expectNone(
      (request) =>
        request.url === '/api/v1/organizations/org-1/diff' && request.params.get('sections') === 'bgp',
    );
  });

  it('degrades to the quiet unavailable note when AI answers 409', async () => {
    const versions = [version('v-3', 3), version('v-2', 2)];
    const fixture = await open(versions, diff());
    http
      .expectOne((request) => request.url === '/api/v1/organizations/org-1/diff')
      .flush(diff({ entries: [entry('rf_template_id', 'rf')] }));
    await settle(fixture);

    const element = fixture.nativeElement as HTMLElement;
    const run = element.querySelector<HTMLButtonElement>('.ai-run');
    expect(run?.textContent?.trim()).toBe('Summarise these 3 changes');

    run?.click();
    await settle(fixture);

    http
      .expectOne(`${API_ROOT}/ai/diff-summary`)
      .flush({ detail: 'AI assist is disabled' }, { status: 409, statusText: 'Conflict' });
    await settle(fixture);

    // Advisory only: no shell error banner, and the comparison still stands.
    expect(ui.error()).toBeNull();
    expect(element.querySelector('.ai-run')).toBeNull();
    expect(element.querySelector('.ai-off-text')?.textContent).toContain('not configured');
    expect(element.querySelector('.card-field')?.textContent).toContain('rf_template_id');
  });
});
