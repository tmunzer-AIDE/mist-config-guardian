import { HttpClient } from '@angular/common/http';
import { inject, Injectable, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

interface Pending {
  resolve(renewed: boolean): void;
}

/**
 * The second-factor confirmation a sensitive action asks for again.
 *
 * The actions that require a recent authenticator code — onboarding an
 * organization, replacing a service token, rotating a webhook secret, changing
 * the AI provider key — are reached long after signing in, and the window is
 * ten minutes. The prompt exists so meeting that requirement is a code away
 * rather than a sign-out and back in.
 *
 * One prompt is open at a time: several requests failing together should ask
 * once and all continue on the same answer.
 */
@Injectable({ providedIn: 'root' })
export class StepUpService {
  private readonly http = inject(HttpClient);

  /** Whether the prompt is on screen. */
  readonly asking = signal(false);
  readonly error = signal('');
  readonly busy = signal(false);

  private pending: Pending[] = [];
  /**
   * Which session is asking.
   *
   * A confirmation is in flight for as long as the network takes, and the
   * session that asked for it can end in the meantime. Advancing this at the
   * boundary is what lets the answer be recognised as belonging to a session
   * that is gone.
   */
  private generation = 0;

  /**
   * Ask for a code and resolve once the answer is known.
   *
   * Resolves true when the session is fresh again and the caller should retry,
   * false when the person dismissed the prompt.
   */
  request(): Promise<boolean> {
    const answered = new Promise<boolean>((resolve) => this.pending.push({ resolve }));
    if (!this.asking()) {
      this.error.set('');
      this.asking.set(true);
    }
    return answered;
  }

  /** Confirm the code, and let every waiting request know how it went. */
  async submit(code: string): Promise<void> {
    if (this.busy()) {
      return;
    }
    // Whose confirmation this is. What comes back describes the session that
    // sent it: it renewed that session's step-up, or that session's code was
    // wrong. Once that session has ended the answer describes nothing on
    // screen, and applying it would release the next session's requests on a
    // code nobody there entered, or accuse them of mistyping one.
    const issuedBy = this.generation;
    this.busy.set(true);
    this.error.set('');
    try {
      await firstValueFrom(this.http.post('/api/v1/account/mfa/step-up', { code }));
      if (this.generation === issuedBy) {
        this.settle(true);
      }
    } catch {
      // Deliberately unspecific, and the prompt stays open: a wrong code is the
      // only thing a person can act on, and the attempts are counted server-side.
      if (this.generation === issuedBy) {
        this.error.set('That code was not accepted. Check your authenticator and try again.');
      }
    } finally {
      if (this.generation === issuedBy) {
        this.busy.set(false);
      }
    }
  }

  /** Give up, and fail the requests that were waiting on the code. */
  dismiss(): void {
    this.settle(false);
  }

  /**
   * Forget an unanswered prompt at a session boundary.
   *
   * The requests waiting here belong to the session that is ending. Left
   * suspended they outlive it: the prompt would come back for whoever signs in
   * next and, on their code, replay the previous session's requests. They are
   * failed instead, and each caller sees the refusal it already had — and a
   * confirmation still in flight stops being able to answer for anyone.
   */
  reset(): void {
    // Only a session boundary advances this. Dismissing the prompt does not:
    // a confirmation still in flight belongs to the session still signed in,
    // and its answer is as good for a request that queued a moment later.
    this.generation += 1;
    this.busy.set(false);
    this.settle(false);
  }

  private settle(renewed: boolean): void {
    const waiting = this.pending;
    this.pending = [];
    this.asking.set(false);
    this.error.set('');
    for (const request of waiting) {
      request.resolve(renewed);
    }
  }
}
