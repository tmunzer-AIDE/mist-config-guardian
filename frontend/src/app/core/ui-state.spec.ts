import { HttpErrorResponse } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';

import { UiStateService } from './ui-state.service';

describe('UiStateService', () => {
  let ui: UiStateService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    ui = TestBed.inject(UiStateService);
  });

  it('stays loading until every concurrent unit of work finishes', () => {
    ui.begin('one');
    ui.begin('two');
    ui.end();
    expect(ui.loading()).toBe(true);
    ui.end();
    expect(ui.loading()).toBe(false);
  });

  it('surfaces the API detail string on failure and clears loading', async () => {
    await ui.track('Loading overview', () => {
      throw new HttpErrorResponse({ status: 403, error: { detail: 'Administrator role required' } });
    });
    expect(ui.loading()).toBe(false);
    expect(ui.error()?.detail).toBe('Administrator role required');
    expect(ui.error()?.title).toBe('You are not authorized to perform this action');
  });

  it('reports an unreachable server distinctly', () => {
    ui.fail(new HttpErrorResponse({ status: 0 }), 'Loading overview');
    expect(ui.error()?.title).toBe('The application server is unreachable');
  });
});
