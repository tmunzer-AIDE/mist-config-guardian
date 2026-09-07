import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { Component } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';

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
    configuration_hash: `hash-${n}`,
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
    return fixture;
  }

  function pins(fixture: ComponentFixture<HistoryPage>): HTMLButtonElement[][] {
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

  it('moves the selection with j and k, but never from inside a text field', async () => {
    const versions = [version('v-3', 3), version('v-2', 2), version('v-1', 1)];
    const fixture = await open(versions, diff());
    http.expectOne((request) => request.url === '/api/v1/organizations/org-1/diff').flush(diff());
    await settle(fixture);

    const element = fixture.nativeElement as HTMLElement;
    const filter = element.querySelector<HTMLInputElement>('.filter-input');
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
