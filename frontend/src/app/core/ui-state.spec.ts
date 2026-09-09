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

  it('stops counting abandoned work at once and keeps its failure to itself', async () => {
    // The page moved on while the request was in flight: the skeleton must not
    // wait for an answer nobody wants, and that answer's error is not news.
    const controller = new AbortController();
    let reject: (cause: unknown) => void = () => undefined;
    const pending = ui.track(
      'Loading the restore operation',
      () => new Promise<never>((_resolve, fail) => (reject = fail)),
      controller.signal,
    );
    expect(ui.loading()).toBe(true);

    controller.abort();
    expect(ui.loading()).toBe(false);

    reject(new HttpErrorResponse({ status: 404, error: { detail: 'Restore operation not found' } }));
    expect(await pending).toBeNull();
    expect(ui.error()).toBeNull();
  });

  it('does not start work whose selection is already gone', async () => {
    const controller = new AbortController();
    controller.abort();
    const work = vi.fn(() => Promise.resolve('value'));

    expect(await ui.track('Loading', work, controller.signal)).toBeNull();
    expect(work).not.toHaveBeenCalled();
    expect(ui.loading()).toBe(false);
  });

  it('reports an unreachable server distinctly', () => {
    ui.fail(new HttpErrorResponse({ status: 0 }), 'Loading overview');
    expect(ui.error()?.title).toBe('The application server is unreachable');
  });
});
