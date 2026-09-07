import { computed, Injectable, signal } from '@angular/core';

/** Timeline window the shell's time bar and every range-aware page share. */
export type TimeRange = '24h' | '7d' | '30d';

const RANGE_KEY = 'mist-config-guardian.range';
const RANGE_MS: Record<TimeRange, number> = {
  '24h': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
  '30d': 30 * 24 * 60 * 60 * 1000,
};

/**
 * Global time-travel state.
 *
 * `asOf` is null while the application is at "now". Setting it puts the whole
 * application into historical mode: the shell shows the amber banner, writes are
 * disabled in the UI, and the request interceptor tags every call so the API
 * refuses writes as well.
 */
@Injectable({ providedIn: 'root' })
export class TimeContextService {
  private readonly rangeState = signal<TimeRange>(readStoredRange());
  private readonly asOfState = signal<Date | null>(null);

  readonly range = this.rangeState.asReadonly();
  readonly asOf = this.asOfState.asReadonly();

  /** True while the user is viewing a reconstructed past point in time. */
  readonly isHistorical = computed(() => this.asOfState() !== null);

  /** Start of the currently selected window. */
  readonly windowStart = computed(() => new Date(this.windowEnd().getTime() - RANGE_MS[this.rangeState()]));

  /** End of the currently selected window: the as-of instant, or now. */
  readonly windowEnd = computed(() => this.asOfState() ?? new Date());

  setRange(range: TimeRange): void {
    this.rangeState.set(range);
    try {
      localStorage.setItem(RANGE_KEY, range);
    } catch {
      // Storage can be unavailable in private windows; the range still applies.
    }
  }

  setAsOf(value: Date | null): void {
    this.asOfState.set(value);
  }

  returnToNow(): void {
    this.asOfState.set(null);
  }

  /** Fraction 0..1 of a timestamp's position inside the selected window. */
  positionOf(at: Date, now = new Date()): number {
    const end = now.getTime();
    const start = end - RANGE_MS[this.rangeState()];
    return Math.min(1, Math.max(0, (at.getTime() - start) / (end - start)));
  }

  /** Resolve a 0..1 track position back to an instant. */
  instantAt(fraction: number, now = new Date()): Date {
    const end = now.getTime();
    const start = end - RANGE_MS[this.rangeState()];
    return new Date(start + Math.min(1, Math.max(0, fraction)) * (end - start));
  }
}

function readStoredRange(): TimeRange {
  try {
    const stored = localStorage.getItem(RANGE_KEY);
    if (stored === '24h' || stored === '7d' || stored === '30d') {
      return stored;
    }
  } catch {
    // Ignore unavailable storage.
  }
  return '24h';
}
