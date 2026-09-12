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
  protected readonly draft = signal<string | null>(null);
  protected readonly preview = signal<Date | null>(null);
  private readonly pinnedWindow = signal<{ start: Date; end: Date } | null>(null);
  protected readonly dateError = signal('');
  protected readonly window = computed(
    () =>
      (this.time.isHistorical() || this.preview() ? this.pinnedWindow() : null) ??
      this.timeline.bounds() ?? { start: this.time.windowStart(), end: this.time.windowEnd() },
  );
  protected readonly asOfLabel = computed(() =>
    this.preview() || this.time.asOf()
      ? formatInstant((this.preview() ?? this.time.asOf())!)
      : 'Live',
  );
  protected readonly startLabel = computed(() => formatInstant(this.window().start));
  protected readonly endLabel = computed(() => formatInstant(this.window().end));
  protected readonly exactValue = computed(
    () => this.draft() ?? (this.time.asOf() ?? new Date()).toISOString().slice(0, 19),
  );
  protected readonly cursor = computed(() => {
    const { start, end } = this.window();
    return Math.max(
      0,
      Math.min(
        100,
        (100 * ((this.preview() ?? this.time.asOf() ?? end).getTime() - start.getTime())) /
          Math.max(1, end.getTime() - start.getTime()),
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
  protected closePicker(picker: HTMLDetailsElement) {
    picker.open = false;
    picker.querySelector('summary')?.focus();
  }
  protected openPicker(picker: HTMLDetailsElement) {
    if (picker.open) {
      this.draft.set((this.time.asOf() ?? new Date()).toISOString().slice(0, 19));
      this.dateError.set('');
      picker.querySelector('input')?.focus();
    }
  }
  protected jumpToChange(event: Event) {
    const input = event.target as HTMLSelectElement;
    if (input.value) this.select(new Date(input.value));
    input.value = '';
  }
  protected setRange(range: TimeRange) {
    this.pinnedWindow.set(null);
    this.preview.set(null);
    this.time.setRange(range);
  }
  protected startDrag(event: PointerEvent) {
    if (event.button !== 0) return;
    const track = event.currentTarget as HTMLElement;
    track.focus();
    track.setPointerCapture(event.pointerId);
    this.pinnedWindow.set(this.window());
    this.moveDrag(event);
  }
  protected moveDrag(event: PointerEvent) {
    const track = event.currentTarget as HTMLElement;
    if (!track.hasPointerCapture(event.pointerId)) return;
    const bounds = track.getBoundingClientRect();
    if (!bounds.width) return;
    const { start, end } = this.window();
    const fraction = Math.min(1, Math.max(0, (event.clientX - bounds.left) / bounds.width));
    this.preview.set(new Date(start.getTime() + fraction * (end.getTime() - start.getTime())));
  }
  protected endDrag(event: PointerEvent) {
    if (!this.preview()) return;
    this.moveDrag(event);
    this.select(this.preview()!);
    this.preview.set(null);
  }
  protected cancelDrag() {
    this.preview.set(null);
  }
  private select(value: Date) {
    this.pinnedWindow.set(this.window());
    this.time.setAsOf(value);
    this.draft.set(null);
    this.dateError.set('');
  }
  private chooseFraction(fraction: number) {
    const { start, end } = this.window();
    const value = new Date(
      start.getTime() + Math.min(1, Math.max(0, fraction)) * (end.getTime() - start.getTime()),
    );
    this.select(value);
  }
  protected marker(event: MouseEvent, at: string) {
    event.stopPropagation();
    this.select(new Date(at));
  }
  protected live() {
    this.preview.set(null);
    this.pinnedWindow.set(null);
    this.time.returnToNow();
    this.draft.set(null);
    this.dateError.set('');
  }
  protected apply(event: Event, picker: HTMLDetailsElement) {
    event.preventDefault();
    const value = new Date(this.exactValue() + 'Z');
    if (!Number.isFinite(value.getTime()) || value > new Date()) {
      this.dateError.set('Choose a valid time in the past (UTC).');
      return;
    }
    this.pinnedWindow.set(null);
    this.time.setAsOf(value);
    this.draft.set(null);
    this.dateError.set('');
    picker.open = false;
    picker.querySelector('summary')?.focus();
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
      this.select(new Date(Math.min(end.getTime(), Math.max(start.getTime(), next.getTime()))));
    }
  }
}
