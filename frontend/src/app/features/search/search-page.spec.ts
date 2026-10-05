import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';

import { OrganizationContextService } from '../../core/organization-context.service';
import { SearchResult, SearchService } from '../../core/search.service';
import { SearchPage } from './search-page';

const ORGANIZATION_ID = 'org-1';
const SEARCH_URL = `/api/v1/organizations/${ORGANIZATION_ID}/search`;

const organizationStub = {
  selected: signal({ id: ORGANIZATION_ID, name: 'Northwind Retail', status: 'verified' }),
};

const WLAN: SearchResult = {
  kind: 'object',
  id: 'obj-1',
  title: 'NW-Corp',
  subtitle: 'Organization WLAN',
  meta: 'v15',
  target: 'history',
  target_params: { object: 'obj-1' },
};

describe('SearchPage', () => {
  let fixture: ComponentFixture<SearchPage>;
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SearchPage],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        {
          provide: OrganizationContextService,
          useValue: organizationStub as unknown as OrganizationContextService,
        },
      ],
    }).compileComponents();

    TestBed.inject(SearchService).reset();
    fixture = TestBed.createComponent(SearchPage);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  function text(selector: string): string[] {
    const element = fixture.nativeElement as HTMLElement;
    return Array.from(element.querySelectorAll(selector)).map((node) => (node.textContent ?? '').trim());
  }

  it('searches for the term in the URL, so the page survives a reload', async () => {
    // Nothing has typed into the service: this is a cold load of ?q=NW-Corp,
    // which is what a reload or a shared link looks like.
    fixture.componentRef.setInput('q', 'NW-Corp');
    fixture.detectChanges();
    await fixture.whenStable();

    const request = httpMock.expectOne((candidate) => candidate.url === SEARCH_URL);
    expect(request.request.params.get('q')).toBe('NW-Corp');
    request.flush({ items: [WLAN], total: 1 });
    await fixture.whenStable();
    fixture.detectChanges();

    expect(text('.row-title')).toEqual(['NW-Corp']);
  });

  /** Run the page's effects, answer nothing, and render what has landed. */
  async function settle(): Promise<void> {
    for (let pass = 0; pass < 3; pass += 1) {
      await fixture.whenStable();
      fixture.detectChanges();
    }
  }

  function result(kind: SearchResult['kind'], id: string, title: string): SearchResult {
    return { ...WLAN, kind, id, title, target_params: {} };
  }

  async function searchFor(term: string, items: SearchResult[], total = items.length): Promise<void> {
    TestBed.inject(SearchService).setQuery(term);
    await settle();
    httpMock.expectOne((candidate) => candidate.url === SEARCH_URL).flush({ items, total });
    await settle();
  }

  function chip(label: string): HTMLButtonElement {
    return [...(fixture.nativeElement as HTMLElement).querySelectorAll<HTMLButtonElement>('.cg-chip')].find(
      (button) => (button.textContent ?? '').includes(label),
    )!;
  }

  it('drops a kind filter when the search changes', async () => {
    // Kept, a kind the next term has no results of hid every result, and the
    // chip row that could undo it disappeared with them.
    fixture.detectChanges();
    await searchFor('corp', [result('object', 'o1', 'NW-Corp'), result('actor', 'a1', 'corp-admin@x')]);
    chip('ACTOR').click();
    await settle();
    expect(text('.row-title')).toEqual(['corp-admin@x']);

    await searchFor('guest', [result('object', 'o2', 'Guest-WLAN'), result('object', 'o3', 'Guest-PSK')]);

    expect(text('.row-title')).toEqual(['Guest-WLAN', 'Guest-PSK']);
  });

  it('shows every result when the chosen kind is no longer among them', async () => {
    fixture.detectChanges();
    await searchFor('corp', [result('object', 'o1', 'NW-Corp'), result('actor', 'a1', 'corp-admin@x')]);
    chip('ACTOR').click();
    await settle();

    // The same term read again, after the actor's changes aged out.
    const search = TestBed.inject(SearchService);
    const again = search.run(ORGANIZATION_ID, 'corp');
    httpMock
      .expectOne((candidate) => candidate.url === SEARCH_URL)
      .flush({ items: [result('object', 'o1', 'NW-Corp')], total: 1 });
    await again;
    await settle();

    expect(text('.row-title')).toEqual(['NW-Corp']);
  });

  it('says when the results are one capped page of a larger match', async () => {
    fixture.detectChanges();
    const items = Array.from({ length: 25 }, (_, index) => result('object', `o${index}`, `AP-${index}`));
    await searchFor('ap', items, 61);

    expect(text('.head-sub')).toEqual(['Showing 25 of 61 results for “ap”']);
  });

  it('counts the results plainly when every match is shown', async () => {
    fixture.detectChanges();
    await searchFor('guest', [result('object', 'o2', 'Guest-WLAN'), result('object', 'o3', 'Guest-PSK')]);

    expect(text('.head-sub')).toEqual(['2 results for “guest”']);
  });

  it('asks for nothing and says so when the URL carries no term', async () => {
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();

    expect(text('.head-sub')).toEqual([
      'Type at least two characters to search objects, actors, and audit IDs.',
    ]);
  });
});
