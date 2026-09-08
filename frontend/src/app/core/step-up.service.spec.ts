import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { StepUpService } from './step-up.service';

const RENEWED = { verified_at: '2026-09-08T12:00:00Z', expires_at: '2026-09-08T12:10:00Z' };
const ENDPOINT = '/api/v1/account/mfa/step-up';

describe('StepUpService', () => {
  let stepUp: StepUpService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    stepUp = TestBed.inject(StepUpService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => TestBed.resetTestingModule());

  /** Whether a promise has settled, without waiting on one that never will. */
  async function settled(pending: Promise<boolean>): Promise<boolean> {
    const marker = Symbol('pending');
    return (await Promise.race([pending, Promise.resolve(marker)])) !== marker;
  }

  it('does not release a new session on the previous one confirmation', async () => {
    const abandoned = stepUp.request();
    const submitting = stepUp.submit('123456');
    const posted = http.expectOne(ENDPOINT);

    // The session ends while the code is in flight — signed out, or revoked.
    stepUp.reset();
    expect(await abandoned).toBe(false);

    // Someone signs in and one of their requests is refused in turn.
    const waiting = stepUp.request();
    expect(stepUp.asking()).toBe(true);

    // The previous session's confirmation lands. It renewed *that* session's
    // step-up, so it says nothing about this one.
    posted.flush(RENEWED);
    await submitting;

    expect(await settled(waiting)).toBe(false);
    expect(stepUp.asking()).toBe(true);

    stepUp.dismiss();
    expect(await waiting).toBe(false);
  });

  it('does not accuse a new session of mistyping the previous one code', async () => {
    const abandoned = stepUp.request();
    const submitting = stepUp.submit('000000');
    const posted = http.expectOne(ENDPOINT);

    stepUp.reset();
    expect(await abandoned).toBe(false);

    stepUp.request();
    posted.flush({ detail: 'That code is not valid' }, { status: 400, statusText: 'Bad Request' });
    await submitting;

    // Nobody here entered that code, and the prompt is ready for one.
    expect(stepUp.error()).toBe('');
    expect(stepUp.busy()).toBe(false);
    stepUp.dismiss();
  });

  it('still answers the session that asked, when it is still the one signed in', async () => {
    const waiting = stepUp.request();
    const submitting = stepUp.submit('123456');

    http.expectOne(ENDPOINT).flush(RENEWED);
    await submitting;

    expect(await waiting).toBe(true);
    expect(stepUp.asking()).toBe(false);
  });

  it('keeps the prompt open on a code the server refuses', async () => {
    const waiting = stepUp.request();
    const submitting = stepUp.submit('000000');

    http
      .expectOne(ENDPOINT)
      .flush({ detail: 'That code is not valid' }, { status: 400, statusText: 'Bad Request' });
    await submitting;

    expect(stepUp.asking()).toBe(true);
    expect(stepUp.error()).not.toBe('');
    expect(await settled(waiting)).toBe(false);
    stepUp.dismiss();
  });
});
