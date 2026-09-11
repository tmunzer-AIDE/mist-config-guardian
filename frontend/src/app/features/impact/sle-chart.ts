import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';

import { Tone } from '../../core/tone';
import { SleBar, changeMarkerPercent } from './monitoring.model';

interface Geometry {
  left: number;
  width: number;
  height: number;
  preChange: boolean;
  label: string;
}

/**
 * The SLE series over one monitoring window.
 *
 * Deliberately hand-drawn: the design is a plain bar series with a single
 * vertical marker, which CSS renders exactly and a charting dependency would
 * only approximate. The bars are decorative — every value is also published in
 * the visually hidden table below them, so the chart is never the only reading.
 */
@Component({
  selector: 'app-sle-chart',
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <figure class="chart">
      <figcaption class="chart-head">
        <span class="chart-title">SLE over the monitoring window</span>
        <span class="chart-hint">Grey is the measured pre-change baseline; coloured is post-change</span>
      </figcaption>

      <div class="plot" [attr.data-tone]="tone()" aria-hidden="true">
        @for (bar of geometry(); track $index) {
          <span
            class="bar"
            [class.bar--post]="!bar.preChange"
            [style.left.%]="bar.left"
            [style.width.%]="bar.width"
            [style.height.%]="bar.height"
          ></span>
        }
        @if (markerPercent() !== null) {
          <span class="mark" [style.left.%]="markerPercent()"></span>
          <span class="mark-label" [style.left.%]="markerPercent()">CHANGE APPLIED</span>
        }
      </div>

      <div class="axis">
        @for (label of axis(); track $index) {
          <span>{{ label }}</span>
        }
      </div>

      <table class="cg-visually-hidden">
        <caption>
          {{ summary() }}
        </caption>
        <thead>
          <tr>
            <th scope="col">Sample</th>
            <th scope="col">Phase</th>
            <th scope="col">{{ metric() }}</th>
          </tr>
        </thead>
        <tbody>
          @for (bar of geometry(); track $index) {
            <tr>
              <td>{{ bar.label }}</td>
              <td>{{ bar.preChange ? 'Before the change' : 'After the change' }}</td>
              <td>{{ bar.height }}%</td>
            </tr>
          }
        </tbody>
      </table>
    </figure>
  `,
  styles: `
    :host {
      display: block;
    }

    .chart {
      margin: 0;
    }

    .chart-head {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 14px;
      flex-wrap: wrap;
    }

    .chart-title {
      font-weight: 600;
      font-size: 13px;
    }

    .chart-hint {
      font-size: 11.5px;
      color: var(--ink-soft);
    }

    .plot {
      position: relative;
      height: 150px;
      border-bottom: 1px solid var(--border-strong);
      border-left: 1px solid rgba(20, 22, 26, 0.09);
    }

    .bar {
      position: absolute;
      bottom: 0;
      border-radius: 1px 1px 0 0;
      background: var(--rule-strong);
    }

    .plot[data-tone='crit'] .bar--post {
      background: var(--tone-critical-ink);
    }

    .plot[data-tone='warn'] .bar--post {
      background: var(--tone-warning-ink);
    }

    .plot[data-tone='ok'] .bar--post {
      background: var(--tone-ok-ink);
    }

    .plot[data-tone='info'] .bar--post {
      background: var(--tone-info-ink);
    }

    .plot[data-tone='none'] .bar--post {
      background: var(--ink-faint);
    }

    .mark {
      position: absolute;
      top: 0;
      bottom: 0;
      width: 2px;
      background: var(--tone-critical-ink);
    }

    .mark-label {
      position: absolute;
      top: 2px;
      margin-left: 5px;
      font: 600 9px var(--font-mono);
      color: var(--tone-critical-ink);
      white-space: nowrap;
    }

    .axis {
      display: flex;
      justify-content: space-between;
      margin-top: 7px;
      font: 400 10px var(--font-mono);
      color: var(--ink-soft);
    }
  `,
})
export class SleChart {
  readonly bars = input.required<SleBar[]>();
  /** Tone applied to post-change bars; pre-change bars stay grey. */
  readonly tone = input<Tone>('none');
  readonly axis = input<string[]>([]);
  /** Human metric name, used in the accessible table header and caption. */
  readonly metric = input('SLE');
  /** Sample labels, one per bar, in the same order. */
  readonly labels = input<string[]>([]);

  protected readonly geometry = computed<Geometry[]>(() => {
    const bars = this.bars();
    const labels = this.labels();
    if (bars.length === 0) {
      return [];
    }
    const slot = 100 / bars.length;
    return bars.map((bar, index) => ({
      left: index * slot,
      width: slot * 0.65,
      height: Math.max(0, Math.min(100, Math.round(bar.value))),
      preChange: bar.preChange,
      label: labels[index] ?? bar.at,
    }));
  });

  protected readonly markerPercent = computed(() => changeMarkerPercent(this.bars()));

  protected readonly summary = computed(() => {
    const bars = this.bars();
    const before = bars.filter((bar) => bar.preChange).length;
    return (
      `${this.metric()} success rate across ${bars.length} sample` +
      `${bars.length === 1 ? '' : 's'}: ${before} before the configuration change ` +
      `and ${bars.length - before} after it.`
    );
  });
}
