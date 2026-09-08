import { ScopedState } from './scoped-state';

/**
 * Each of the three conditions is checked on its own, because every mistake
 * made in this area came from one of them being folded into another.
 */
describe('ScopedState', () => {
  let state: ScopedState;

  beforeEach(() => {
    state = new ScopedState();
  });

  it('accepts an answer for the scope on screen', () => {
    expect(state.accepts(state.claim('org-a'))).toBe(true);
  });

  it('refuses an answer for a scope nobody is looking at any more', () => {
    const stale = state.claim('org-a');
    const current = state.claim('org-b');

    expect(state.accepts(current)).toBe(true);
    expect(state.accepts(stale)).toBe(false);
  });

  it('refuses an answer older than the one already shown', () => {
    const earlier = state.claim('org-a');
    const later = state.claim('org-a');

    expect(state.accepts(later)).toBe(true);
    expect(state.accepts(earlier)).toBe(false);
  });

  it('lets an earlier answer through when the later request never applied one', () => {
    // The heart of it: order advances on application, not on issue. A request
    // that is issued and then fails records nothing, so the earlier answer is
    // still the newest one there is.
    const earlier = state.claim('org-a');
    state.claim('org-a'); // issued, then fails: never passed to accepts()

    expect(state.accepts(earlier)).toBe(true);
  });

  it('refuses everything in flight once invalidated', () => {
    const claim = state.claim('org-a');

    state.invalidate();

    expect(state.accepts(claim)).toBe(false);
  });

  it('starts over cleanly after being invalidated', () => {
    state.claim('org-a');
    state.invalidate();

    expect(state.accepts(state.claim('org-a'))).toBe(true);
  });

  it('reports the scope it currently describes', () => {
    expect(state.current).toBe('');
    state.claim('org-a|24h|now');
    expect(state.current).toBe('org-a|24h|now');
    state.invalidate();
    expect(state.current).toBe('');
  });
});
