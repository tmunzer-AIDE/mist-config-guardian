import { ChangeDetectionStrategy, Component, computed, effect, input, signal } from '@angular/core';
import { formatInstant } from '../../core/format';
import {
  DeviceStateComparison,
  DeviceStateObservation,
  DeviceStateFinding,
  MonitoringSession,
} from './monitoring.model';
import { TelemetryCapture } from './telemetry-capture';

const SOURCES = [
  ['device', 'Device statistics'],
  ['radios', 'RF statistics'],
  ['wlans', 'Configured site SSIDs'],
  ['clients', 'Observed clients'],
  ['ports', 'Interfaces'],
  ['bgp', 'BGP peers'],
  ['ospf', 'OSPF peers'],
  ['tunnels', 'WAN tunnels'],
  ['vpn_peers', 'VPN peers'],
] as const;

@Component({
  selector: 'app-device-evidence',
  imports: [TelemetryCapture],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="evidence cg-card findings-summary" aria-labelledby="device-findings-heading">
      <h2 id="device-findings-heading">What changed on the device</h2>
      <p class="timing">Latest available findings across this monitoring window. Repeated findings are shown once.</p>
      @for (item of findings(); track item.key) {
        <article class="finding" [class.critical]="item.finding.severity === 'critical'">
          <span [class]="'cg-badge cg-badge--' + (item.finding.severity === 'critical' ? 'crit' : 'warn')">{{ item.finding.severity }}</span>
          <strong>{{ item.finding.subject }} · {{ item.finding.before }} → {{ item.finding.after }}</strong>
          <p>{{ item.finding.detail }}</p>
          @if (item.count > 1) { <small>Reported in {{ item.count }} captures · shown once</small> }
        </article>
      } @empty {
        <p>{{ !comparisons().length ? 'No device-state captures were recorded for this window.' : pendingCount() === comparisons().length ? 'Waiting for a device-state comparison.' : 'No differences reported in the available device comparisons.' }}</p>
      }
      @if (recoveredCount()) { <p class="recovery">Operational recovery recorded for {{ recoveredCount() }} capture comparisons. Earlier findings remain in capture history.</p> }
      @if (pendingCount()) { <p class="timing">{{ pendingCount() }} capture comparisons are still awaiting a follow-up.</p> }
      @if (sourceErrors().length) {
        <p class="source-warning" role="status">Some device data could not be collected. Findings cover only the available sources.</p>
        <details><summary>Device collection errors</summary><ul>@for (error of sourceErrors(); track error) { <li>{{ error }}</li> }</ul></details>
      }
      <p class="timing">Device configuration and network performance are separate checks. Missing data is unknown.</p>
    </section>
    @if (comparisons().length) {
      <details class="evidence cg-card capture-history">
        <summary>Inspect captures · {{ comparisons().length }} configuration triggers</summary>
        <p class="timing">These are captures within one session, not separate monitoring sessions. Select a trigger to compare its initial and later device state.</p>
        <label for="evidence-capture">Configuration trigger</label>
        <select id="evidence-capture" [value]="captureIndex()" (change)="captureIndex.set(+$any($event.target).value)">
          @for (comparison of comparisons(); track $index) {
            <option [value]="$index" [selected]="$index === captureIndex()">{{ at(comparison.triggered_at) }} · capture {{ $index + 1 }}</option>
          }
        </select>
    @if (comparisons().at(captureIndex()) ?? comparisons().at(0); as comparison) {
      <section class="evidence cg-card">
        <h3>Initial capture → latest available state</h3>
        <p class="timing">
          Initial capture: {{ at(comparison.baseline.captured_at) }} ·
          @if (comparison.followup; as after) {
            Follow-up: {{ at(after.captured_at) }}
          } @else {
            Five-minute comparison due: {{ at(comparison.due_at) }}
          }
        </p>
        @if (comparison.latest) {
          <p class="timing">Current operational check: {{ at(comparison.latest.captured_at) }}</p>
        }
        @if (comparison.recovered_at) {
          <p class="recovery">
            <span class="cg-badge cg-badge--ok">RECOVERED</span> Operational recovery observed
            {{ at(comparison.recovered_at) }}. SLE evidence is assessed separately.
          </p>
        }
        @for (finding of comparison.current_findings ?? comparison.findings; track $index) {
          <article class="finding" [class.critical]="finding.severity === 'critical'">
            <span
              [class]="'cg-badge cg-badge--' + (finding.severity === 'critical' ? 'crit' : 'warn')"
              >{{ finding.severity }}</span
            >
            <strong>{{ finding.subject }} · {{ finding.before }} → {{ finding.after }}</strong>
            <p>{{ finding.detail }}</p>
          </article>
        }
        @if (comparison.followup && !(comparison.current_findings ?? comparison.findings).length) {
          <p>No disruption detected in the telemetry sources that could be compared.</p>
        }
        @if (
          comparison.findings.length &&
          comparison.current_findings !== undefined &&
          comparison.current_findings !== null
        ) {
          <details>
            <summary>First comparison findings · historical</summary>
            @for (finding of comparison.findings; track $index) {
              <p>{{ finding.subject }} · {{ finding.detail }}</p>
            }
          </details>
        }
        <p class="timing">
          Evidence describes the captures shown above. Missing API data is unknown; normal client
          roaming alone is not treated as an outage.
        </p>
        @for (source of sources(comparison); track source.key) {
          <details #detail (toggle)="setExpanded(comparison, source.key, detail.open)">
            <summary>
              {{ source.label }} <span>{{ source.beforeSummary }} → {{ source.afterSummary }}</span>
            </summary>
            @if (expanded.get(comparison)?.has(source.key)) {
              <div class="captures">
                <app-telemetry-capture
                  label="At trigger"
                  [value]="source.before"
                  [error]="source.beforeError"
                />
                <app-telemetry-capture
                  [label]="comparison.latest ? 'Latest capture' : 'Five minutes later'"
                  [value]="source.after"
                  [error]="source.afterError"
                  [emptyLabel]="comparison.followup ? 'Unavailable' : 'Pending capture'"
                />
              </div>
            }
          </details>
        }
      </section>
    }
      </details>
    }
  `,
  styles: `
    :host {
      display: flex;
      flex-direction: column;
      gap: 15px;
      min-width: 0;
    }
    .evidence {
      padding: 20px;
    }
    h2 { font-size: 17px; margin: 0; }
    select { display: block; width: 100%; margin: 8px 0 18px; padding: 10px; color: inherit; background: var(--surface-raised); border: 1px solid var(--hairline-strong); border-radius: var(--radius-md); }
    label, small { font-size: 12px; color: var(--ink-soft); }
    .source-warning { font-size: 12px; color: var(--tone-warning-ink); }
    .capture-history > summary { font-size: 13px; }
    .capture-history > .evidence { padding: 16px 0 0; border: 0; box-shadow: none; background: transparent; }
    h3 {
      margin: 0 0 10px;
      font-size: 16px;
    }
    .timing {
      font-size: 12px;
      color: var(--ink-soft);
      line-height: 1.5;
    }
    .finding {
      padding: 12px;
      border: 1px solid var(--tone-warning-line);
      border-radius: var(--radius-md);
      background: var(--tone-warning-wash);
      margin: 10px 0;
    }
    .finding .cg-badge {
      display: table;
      margin-bottom: 8px;
      text-transform: uppercase;
    }
    .finding.critical {
      border-color: var(--tone-critical-line);
      background: var(--tone-critical-wash);
    }
    .finding p {
      margin: 6px 0 0;
    }
    details {
      border-top: 1px solid var(--hairline);
      padding: 12px 0;
    }
    summary {
      cursor: pointer;
      font-weight: 600;
    }
    summary span {
      font-weight: 400;
      color: var(--ink-soft);
      margin-left: 10px;
    }
    .captures {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
    }
    .captures > div {
      min-width: 0;
    }
    .error {
      color: var(--tone-warning-ink);
    }
    @media (max-width: 700px) {
      .captures {
        grid-template-columns: 1fr;
      }
    }
  `,
})
export class DeviceEvidence {
  readonly session = input.required<MonitoringSession>();
  protected readonly captureIndex = signal(0);
  private previousSessionId: string | undefined;
  constructor() {
    effect(() => {
      const id = this.session().id;
      if (id !== this.previousSessionId) {
        this.previousSessionId = id;
        this.captureIndex.set(0);
      }
    });
  }
  protected readonly comparisons = computed(() => [...(this.session().device_comparisons ?? [])]
    .sort((a, b) => Date.parse(a.triggered_at) - Date.parse(b.triggered_at)));
  protected readonly findings = computed(() => {
    const result = new Map<string, { key: string; finding: DeviceStateFinding; count: number }>();
    for (const comparison of this.comparisons()) {
      const seen = new Set<string>();
      for (const finding of comparison.current_findings ?? comparison.findings) {
        const key = JSON.stringify([finding.kind, finding.subject, finding.before, finding.after,
          finding.severity, finding.detail, finding.affected_clients]);
        if (seen.has(key)) continue;
        seen.add(key);
        const existing = result.get(key);
        if (existing) existing.count++;
        else result.set(key, { key, finding, count: 1 });
      }
    }
    return [...result.values()].sort((a, b) => Number(b.finding.severity === 'critical') - Number(a.finding.severity === 'critical'));
  });
  protected readonly recoveredCount = computed(() => this.comparisons().filter((c) => c.recovered_at).length);
  protected readonly pendingCount = computed(() => this.comparisons().filter((c) => !c.followup && !c.latest).length);
  protected readonly sourceErrors = computed(() => [...new Set(this.comparisons().flatMap((c) =>
    [c.baseline, c.latest ?? c.followup].flatMap((state) => Object.entries(state?.errors ?? {}).map(([source, error]) => source + ': ' + error))))]);
  protected readonly expanded = new WeakMap<DeviceStateComparison, Set<string>>();
  protected setExpanded(comparison: DeviceStateComparison, key: string, open: boolean): void {
    const sources = this.expanded.get(comparison) ?? new Set<string>();
    if (open) sources.add(key);
    else sources.delete(key);
    this.expanded.set(comparison, sources);
  }
  protected readonly at = (value?: string | null) =>
    value ? formatInstant(new Date(value)) : 'not available';
  protected sources(comparison: DeviceStateComparison) {
    const before = comparison.baseline;
    const after = comparison.latest ?? comparison.followup;
    return SOURCES.filter(
      ([key]) =>
        before?.available.includes(key) ||
        before?.errors[key] ||
        after?.available.includes(key) ||
        after?.errors[key],
    ).map(([key, label]) => ({
      key,
      label,
      before: before?.available.includes(key) ? before[key] : null,
      after: after?.available.includes(key) ? after[key] : null,
      beforeSummary: this.summary(before, key),
      afterSummary: this.summary(after, key),
      beforeError: before?.errors[key],
      afterError: after?.errors[key],
    }));
  }
  private summary(
    state: DeviceStateObservation | null | undefined,
    key: (typeof SOURCES)[number][0],
  ): string {
    if (!state) return 'pending';
    if (!state.available.includes(key)) return 'unavailable';
    const value = state[key];
    return Array.isArray(value) ? value.length + ' records' : 'captured';
  }
}
