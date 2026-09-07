import { ChangeDetectionStrategy, Component, computed, inject } from '@angular/core';

import { TimeContextService, TimeRange } from '../core/time-context.service';
import { TimelineService } from '../core/timeline.service';
import { formatInstant } from '../core/format';

interface Tick {
  left: string;
  height: string;
  color: string;
  label: string;
}

const RANGES: TimeRange[] = ['24h', '7d', '30d'];

@Component({
  selector: 'app-time-bar',
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './app-time-bar.html',
  styleUrl: './app-time-bar.scss',
})
export class AppTimeBar {
  protected readonly time = inject(TimeContextService);
  private readonly timeline = inject(TimelineService);

  protected readonly ranges = RANGES;

  protected readonly asOfLabel = computed(() => {
    const asOf = this.time.asOf();
    return asOf ? formatInstant(asOf) : `NOW · ${formatInstant(new Date())}`;
  });

  protected readonly ticks = computed<Tick[]>(() =>
    this.timeline.markers().map((marker) => {
      const at = new Date(marker.at);
      const critical = marker.severity === 'critical';
      const warning = marker.severity === 'warning';
      return {
        left: `${(this.time.positionOf(at) * 100).toFixed(2)}%`,
        height: critical ? '28px' : warning ? '22px' : '12px',
        color: critical ? 'var(--tone-critical-ink)' : warning ? 'var(--tone-warning-ink)' : 'var(--tone-none-mark)',
        label: marker.label,
      };
    }),
  );

  protected readonly handleLeft = computed(() => {
    const asOf = this.time.asOf();
    return asOf ? `${(this.time.positionOf(asOf) * 100).toFixed(2)}%` : '96%';
  });

  protected scrub(event: MouseEvent): void {
    const track = event.currentTarget as HTMLElement;
    const bounds = track.getBoundingClientRect();
    const fraction = (event.clientX - bounds.left) / bounds.width;
    // The rightmost sliver of the track means "now"; anything else is history.
    this.time.setAsOf(fraction > 0.985 ? null : this.time.instantAt(fraction));
  }

  protected onTrackKey(event: KeyboardEvent): void {
    const step = event.shiftKey ? 0.1 : 0.02;
    const current = this.time.asOf() ? this.time.positionOf(this.time.asOf() as Date) : 1;
    if (event.key === 'ArrowLeft') {
      event.preventDefault();
      this.time.setAsOf(this.time.instantAt(current - step));
    }
    if (event.key === 'ArrowRight') {
      event.preventDefault();
      const next = current + step;
      this.time.setAsOf(next >= 0.985 ? null : this.time.instantAt(next));
    }
    if (event.key === 'End' || event.key === 'Escape') {
      event.preventDefault();
      this.time.returnToNow();
    }
  }
}
