import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { TimeContextService, TimeRange } from '../core/time-context.service';
import { TimelineService } from '../core/timeline.service';
import { formatInstant } from '../core/format';

@Component({
  selector: 'app-time-bar',
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './app-time-bar.html',
  styleUrl: './app-time-bar.scss',
})
export class AppTimeBar {
  protected readonly time = inject(TimeContextService);
  private readonly timeline = inject(TimelineService);
  protected readonly ranges: TimeRange[] = ['24h', '7d', '30d'];
  protected readonly draft = signal('');
  protected readonly dateError = signal('');
  protected readonly window = computed(
    () => this.timeline.bounds() ?? { start: this.time.windowStart(), end: this.time.windowEnd() },
  );
  protected readonly asOfLabel = computed(() =>
    this.time.asOf() ? formatInstant(this.time.asOf()!) : 'Live',
  );
  protected readonly startLabel = computed(() => formatInstant(this.window().start));
  protected readonly endLabel = computed(() => formatInstant(this.window().end));
  protected readonly exactValue = computed(
    () => this.draft() || (this.time.asOf() ?? new Date()).toISOString().slice(0, 19),
  );
  protected readonly cursor = computed(() => {
    const { start, end } = this.window();
    return Math.max(
      0,
      Math.min(
        100,
        (100 * ((this.time.asOf() ?? end).getTime() - start.getTime())) /
          (end.getTime() - start.getTime()),
      ),
    );
  });
  protected readonly ticks = computed(() => {
    const { start, end } = this.window();
    return this.timeline
      .markers()
      .filter((m) => new Date(m.at) >= start && new Date(m.at) <= end)
      .map((m) => ({
        at: m.at,
        left:
          (100 * (new Date(m.at).getTime() - start.getTime())) /
          Math.max(1, end.getTime() - start.getTime()),
        label: m.label,
        tone: m.impact_known === false ? 'unknown' : m.severity,
      }));
  });
  protected scrub(event: MouseEvent) {
    const bounds = (event.currentTarget as HTMLElement).getBoundingClientRect();
    if (bounds.width <= 0) return;
    this.chooseFraction((event.clientX - bounds.left) / bounds.width);
  }
  private chooseFraction(fraction: number) {
    const { start, end } = this.window();
    const value = new Date(
      start.getTime() + Math.min(1, Math.max(0, fraction)) * (end.getTime() - start.getTime()),
    );
    this.time.setAsOf(value);
    this.draft.set('');
  }
  protected marker(event: MouseEvent, at: string) {
    event.stopPropagation();
    this.time.setAsOf(new Date(at));
    this.draft.set('');
  }
  protected live() {
    this.time.returnToNow();
    this.draft.set('');
    this.dateError.set('');
  }
  protected apply(event: Event, picker: HTMLDetailsElement) {
    event.preventDefault();
    const value = new Date(this.exactValue() + 'Z');
    if (!Number.isFinite(value.getTime()) || value > new Date()) {
      this.dateError.set('Choose a valid time in the past (UTC).');
      return;
    }
    this.time.setAsOf(value);
    this.dateError.set('');
    picker.open = false;
  }
  protected onTrackKey(event: KeyboardEvent) {
    if (event.target !== event.currentTarget) return;
    if (event.key === 'Escape') {
      event.preventDefault();
      this.live();
    } else if (event.key === 'Home') {
      event.preventDefault();
      this.chooseFraction(0);
    } else if (event.key === 'End') {
      event.preventDefault();
      this.chooseFraction(1);
    } else if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') {
      event.preventDefault();
      const { start, end } = this.window();
      const current = this.time.asOf() ?? end;
      const step = (end.getTime() - start.getTime()) * (event.shiftKey ? 0.1 : 0.02);
      const next = new Date(current.getTime() + (event.key === 'ArrowLeft' ? -step : step));
      this.time.setAsOf(
        new Date(Math.min(end.getTime(), Math.max(start.getTime(), next.getTime()))),
      );
      this.draft.set('');
    }
  }
}
