import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { Organization } from './organization.model';
import { OrganizationContextService } from './organization-context.service';

function organizations(from: number, count: number): Organization[] {
  return Array.from(
    { length: count },
    (_, index) => ({ id: `org-${from + index}`, name: `Org ${from + index}` }) as Organization,
  );
}

describe('OrganizationContextService', () => {
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting()] });
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('reads every page of organizations, not only the first', async () => {
    // The API answers 50 by default. The picker, the Settings cards and the
    // stored selection all need the whole list, which can be longer than one
    // page allows.
    const context = TestBed.inject(OrganizationContextService);
    context.select('org-230', false);
    const loading = context.load();

    const first = http.expectOne((request) => request.url === '/api/v1/organizations');
    expect(first.request.params.get('skip')).toBe('0');
    expect(first.request.params.get('limit')).toBe('200');
    first.flush({ items: organizations(0, 200), total: 250 });
    await new Promise((resolve) => setTimeout(resolve, 0));

    const second = http.expectOne((request) => request.url === '/api/v1/organizations');
    expect(second.request.params.get('skip')).toBe('200');
    second.flush({ items: organizations(200, 50), total: 250 });
    await loading;

    expect(context.all()).toHaveLength(250);
    expect(context.selected()?.id).toBe('org-230');
  });

  it('stops at a short page even when the total says there are more', async () => {
    // Organizations removed while paging shrink the list under the reader; a
    // page with nothing on it is the end, whatever the total claimed.
    const context = TestBed.inject(OrganizationContextService);
    const loading = context.load();

    http.expectOne((request) => request.url === '/api/v1/organizations').flush({ items: organizations(0, 200), total: 201 });
    await new Promise((resolve) => setTimeout(resolve, 0));
    http.expectOne((request) => request.url === '/api/v1/organizations').flush({ items: [], total: 200 });
    await loading;

    expect(context.all()).toHaveLength(200);
  });
});
