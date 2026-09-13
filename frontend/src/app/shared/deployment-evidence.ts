import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { DeploymentEvidence } from '../core/deployment-evidence.model';
import { formatInstant } from '../core/format';

@Component({
  selector: 'app-deployment-evidence',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section aria-label="Configuration deployment evidence">
      <h4>Configuration deployment evidence</h4>
      <p>These events describe configuration delivery. They do not identify impacted devices or prove that all expected devices received configuration.</p>
      @if (evidence(); as value) {
        <p>Receipt collection: {{ value.state }} · as of {{ at(value.collected_at) }} · Expected device count: unknown</p>
        @if (value.devices.length) {
          <div class="table-scroll">
            <table>
              <caption>Observed device deployment outcomes</caption>
              <thead><tr><th>Device / site</th><th>Outcome</th><th>Audit association</th><th>Last ordered event</th></tr></thead>
              <tbody>@for (device of value.devices; track device.site_id + ':' + device.device_mac) {
                <tr><td>{{ device.device_mac }} ({{ device.device_type }})<br />{{ device.site_id }}</td>
                  <td>{{ device.outcome }}</td><td>{{ association(device.correlation) }}</td>
                  <td>{{ device.last_event_at ? at(device.last_event_at) : 'Not established' }}</td></tr>
              }</tbody>
            </table>
          </div>
        } @else { <p>No device deployment outcome was established from the collected receipts.</p> }
        @if (value.gaps.length) {
          <ul>@for (gap of value.gaps; track $index) { <li>{{ gap }}</li> }</ul>
        }
        <details>
          <summary>Deployment event receipts · {{ value.observations.length }}</summary>
          <div class="table-scroll">
            <table>
              <caption>Occurrence and receipt times are kept separately</caption>
              <thead><tr><th>Event / device</th><th>Occurred</th><th>Received</th><th>Association / receipt</th></tr></thead>
              <tbody>@for (event of value.observations; track event.receipt_id) {
                <tr><td>{{ event.signal.event_type }}<br />{{ event.signal.device_mac ?? 'Unknown device' }}</td>
                  <td>{{ event.signal.occurred_at ? at(event.signal.occurred_at) : 'Unknown' }}</td>
                  <td>{{ at(event.received_at) }}</td><td>{{ association(event.correlation) }}<br />{{ event.receipt_id }}</td></tr>
              }</tbody>
            </table>
          </div>
        </details>
      } @else { <p>Deployment evidence was not collected in this report revision.</p> }
    </section>
  `,
  styles: `
    section { border-top: 1px solid var(--border); margin-top: 1rem; padding-top: .5rem; }
    p, li { line-height: 1.5; } .table-scroll { max-height: 24rem; overflow: auto; }
    table { width: 100%; border-collapse: collapse; font-size: .8rem; }
    th, td { padding: .5rem; text-align: left; border-bottom: 1px solid var(--border); overflow-wrap: anywhere; }
    caption { text-align: left; margin: .5rem 0; } summary { margin: .7rem 0; cursor: pointer; }
  `,
})
export class DeploymentEvidenceComponent {
  readonly evidence = input<DeploymentEvidence | null | undefined>(null);
  protected readonly at = (value: string) => formatInstant(new Date(value));
  protected association(value: string): string {
    return ({ audit_id: 'Explicit audit ID', session_candidate: 'Session candidate only',
      ambiguous: 'Uncertain', time_unknown: 'Timing unknown', outside_window: 'Outside investigation window',
    } as Record<string, string>)[value] ?? 'Unknown';
  }
}
