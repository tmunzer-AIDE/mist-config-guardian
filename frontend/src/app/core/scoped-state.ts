/**
 * Bookkeeping for a signal that describes one scope at a time.
 *
 * Three separate questions decide whether an answer may be written, and each
 * of them does work the others do not:
 *
 * - **epoch** — has the state been thrown away since the request was issued?
 *   A sign-out or an explicit clear must stop everything already in flight.
 * - **scope** — does the answer still describe what is on screen? An answer
 *   for an organization, window or instant nobody is looking at any more is
 *   refused however recent it is.
 * - **order** — is it newer than the answer already shown? Two answers for
 *   one live scope are observations at different moments, not the same fact
 *   twice, so an older reading must not revert a newer one.
 *
 * The order is the one that is easy to get wrong: it advances when an answer
 * is *applied*, never when a request is issued. A request that is issued and
 * then fails must leave the last good answer standing rather than making
 * everything before it look old.
 */
export interface ScopeClaim {
  scope: string;
  epoch: number;
  sequence: number;
}

export class ScopedState {
  private scope = '';
  private epoch = 0;
  private issued = 0;
  private applied = 0;

  /** The scope the answer currently shown describes, or '' when there is none. */
  get current(): string {
    return this.scope;
  }

  /** Take the state for a scope, and return the claim its answer must still hold. */
  claim(scope: string): ScopeClaim {
    this.scope = scope;
    return { scope, epoch: this.epoch, sequence: ++this.issued };
  }

  /**
   * Report whether an answer may be written, recording it as the one shown.
   *
   * Only call this for an answer that arrived: a failure has nothing to
   * record, and recording it would suppress the successes before it.
   */
  accepts(claim: ScopeClaim): boolean {
    if (claim.epoch !== this.epoch || claim.scope !== this.scope) {
      return false;
    }
    if (claim.sequence <= this.applied) {
      return false;
    }
    this.applied = claim.sequence;
    return true;
  }

  /** Forget the scope and refuse everything already in flight. */
  invalidate(): void {
    this.epoch += 1;
    this.scope = '';
    this.applied = 0;
  }
}
