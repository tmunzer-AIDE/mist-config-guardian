import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { formatInstant } from '../../core/format';
import { DeviceStateComparison, DeviceStateObservation, MonitoringSession } from './monitoring.model';
import { TelemetryCapture } from './telemetry-capture';

const SOURCES = [
  ['device', 'Device statistics'], ['radios', 'RF statistics'], ['wlans', 'Configured site SSIDs'],
  ['clients', 'Observed clients'], ['ports', 'Interfaces'], ['bgp', 'BGP peers'], ['ospf', 'OSPF peers'],
  ['tunnels', 'WAN tunnels'], ['vpn_peers', 'VPN peers'],
] as const;

@Component({
  selector: 'app-device-evidence',
  imports: [TelemetryCapture],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @for (comparison of session().device_comparisons ?? []; track comparison) {
      <section class="evidence cg-card">
        <h3>Device state comparison</h3>
        <p class="timing">SLE baseline: 24 hours before the change. Post-change SLE monitoring: at least 1 hour.</p>
        <p class="timing">Initial capture: {{ at(comparison.baseline.captured_at) }} ·
          @if (comparison.followup; as after) { Follow-up: {{ at(after.captured_at) }} }
          @else { Five-minute comparison due: {{ at(comparison.due_at) }} }
        </p>
        @for (finding of comparison.findings; track $index) {
          <article class="finding" [class.critical]="finding.severity === 'critical'">
            <span [class]="'cg-badge cg-badge--' + (finding.severity === 'critical' ? 'crit' : 'warn')">{{ finding.severity }}</span>
            <strong>{{ finding.subject }} · {{ finding.before }} → {{ finding.after }}</strong>
            <p>{{ finding.detail }}</p>
          </article>
        }
        @if (comparison.followup && !(comparison.findings.length)) {
          <p>No disruption detected in the telemetry sources that could be compared.</p>
        }
        <p class="timing">Evidence describes the captures shown above. Missing API data is unknown; normal client roaming alone is not treated as an outage.</p>
        @for (source of sources(comparison); track source.key) {
          <details #detail (toggle)="setExpanded(comparison, source.key, detail.open)">
            <summary>{{ source.label }} <span>{{ source.beforeSummary }} → {{ source.afterSummary }}</span></summary>
            @if (expanded.get(comparison)?.has(source.key)) {
              <div class="captures">
                <app-telemetry-capture label="At trigger" [value]="source.before" [error]="source.beforeError" />
                <app-telemetry-capture label="Five minutes later" [value]="source.after" [error]="source.afterError"
                  [emptyLabel]="comparison.followup ? 'Unavailable' : 'Pending capture'" />
              </div>
            }
          </details>
        }
      </section>
    }
  `,
  styles: `
    :host { display:flex; flex-direction:column; gap:15px; min-width:0; }
    .evidence { padding: 20px; }
    h3 { margin:0 0 10px; font-size:16px; }
    .timing { font-size:12px; color:var(--ink-soft); line-height:1.5; }
    .finding { padding:12px; border:1px solid var(--tone-warning-line); border-radius:var(--radius-md); background:var(--tone-warning-wash); margin:10px 0; }
    .finding .cg-badge { display:table; margin-bottom:8px; text-transform:uppercase; }
    .finding.critical { border-color:var(--tone-critical-line); background:var(--tone-critical-wash); }
    .finding p { margin:6px 0 0; }
    details { border-top:1px solid var(--hairline); padding:12px 0; }
    summary { cursor:pointer; font-weight:600; } summary span { font-weight:400; color:var(--ink-soft); margin-left:10px; }
    .captures { display:grid; grid-template-columns:1fr 1fr; gap:16px; } .captures > div { min-width:0; }
    .error { color:var(--tone-warning-ink); } @media(max-width:700px) { .captures { grid-template-columns:1fr; } }
  `,
})
export class DeviceEvidence {
  readonly session = input.required<MonitoringSession>();
  protected readonly expanded = new WeakMap<DeviceStateComparison, Set<string>>();
  protected setExpanded(comparison: DeviceStateComparison, key: string, open: boolean): void {
    const sources = this.expanded.get(comparison) ?? new Set<string>();
    if (open) sources.add(key);
    else sources.delete(key);
    this.expanded.set(comparison, sources);
  }
  protected readonly at = (value?: string | null) => value ? formatInstant(new Date(value)) : 'not available';
  protected sources(comparison: DeviceStateComparison) {
    const before = comparison.baseline;
    const after = comparison.followup;
    return SOURCES.filter(([key]) => before?.available.includes(key) || before?.errors[key] || after?.available.includes(key) || after?.errors[key])
      .map(([key, label]) => ({ key, label,
        before: before?.available.includes(key) ? before[key] : null,
        after: after?.available.includes(key) ? after[key] : null,
        beforeSummary: this.summary(before, key), afterSummary: this.summary(after, key),
        beforeError: before?.errors[key], afterError: after?.errors[key],
      }));
  }
  private summary(state: DeviceStateObservation | null | undefined, key: typeof SOURCES[number][0]): string {
    if (!state) return 'pending';
    if (!state.available.includes(key)) return 'unavailable';
    const value = state[key];
    return Array.isArray(value) ? value.length + ' records' : 'captured';
  }
}
