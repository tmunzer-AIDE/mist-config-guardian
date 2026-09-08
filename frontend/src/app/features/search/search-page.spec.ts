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

  it('asks for nothing and says so when the URL carries no term', async () => {
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();

    expect(text('.head-sub')).toEqual([
      'Type at least two characters to search objects, actors, and audit IDs.',
    ]);
  });
});
