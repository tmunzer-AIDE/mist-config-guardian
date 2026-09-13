import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { formatInstant } from '../core/format';

export interface DispatchLog {
  source: 'live_investigation_root';
  unlogged_reservations: number;
  records: {
    id: string;
    generation: number;
    candidate_revision: number;
    check_id: string;
    target_handle: string;
    site_id: string | null;
    document_id?: string | null;
    wlan_id: string | null;
    device_mac?: string | null;
    port_id?: string | null;
    source_dispatch_id?: string | null;
    window: { start: string; end: string };
    reserved_at: string;
    state: 'reserved' | 'complete' | 'partial' | 'error';
    finished_at: string | null;
    http_status: number | null;
    response_bytes: number | null;
    row_count: number | null;
  }[];
}

@Component({
  selector: 'app-dispatch-log',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <details>
      <summary>Live collection activity</summary>
      <p>This activity belongs to the current investigation and may include attempts outside the published report.
        A reserved request with no recorded result has an unknown outcome; it may not have reached Mist.</p>
      <p>Bytes count only response content read by the collector. Unknown means no size was recorded,
        including when an HTTP error stopped collection before reading the body.</p>
      @if (log(); as log) {
        @if (log.unlogged_reservations) {
          <p role="status">{{ log.unlogged_reservations }} earlier budget reservations have no journal entry.</p>
        }
        @if (log.records.length) {
          <div class="scroll">
            <table>
              <caption>Read-only checks · response metadata only</caption>
              <thead><tr><th>Check and scope</th><th>Investigation interval</th><th>Attempt timing</th><th>Result</th></tr></thead>
              <tbody>@for (entry of log.records; track entry.id) {
                <tr>
                  <td>{{ entry.check_id }}<br>@if (entry.site_id) { Site {{ entry.site_id }}<br> }@if (entry.document_id) { Pinned OAS · {{ entry.document_id }} } @else if (entry.wlan_id) { WLAN {{ entry.wlan_id }} } @else if (entry.source_dispatch_id) { AP check · Source attempt {{ entry.source_dispatch_id }} } @else { Switch {{ entry.device_mac }} · Port {{ entry.port_id }} }
                    <br>Worker {{ entry.generation }} · candidate revision {{ entry.candidate_revision }}
                    <br>Attempt {{ entry.id }}</td>
                  <td>{{ at(entry.window.start) }}–{{ at(entry.window.end) }}</td>
                  <td>Reserved {{ at(entry.reserved_at) }}<br>
                    {{ entry.finished_at ? 'Recorded result ' + at(entry.finished_at) : 'No result recorded' }}</td>
                  <td>{{ entry.state === 'reserved' ? 'Outcome unknown' : entry.state }}<br>
                    {{ entry.document_id ? 'Local library' : 'HTTP ' + (entry.http_status ?? 'Unknown') }} · Bytes {{ entry.response_bytes ?? 'Unknown' }}
                    <br>Parsed rows {{ entry.row_count ?? 'Unknown' }}</td>
                </tr>
              }</tbody>
            </table>
          </div>
        } @else { <p>No journal entries are available.</p> }
      } @else { <p>Collection activity was not provided.</p> }
    </details>
  `,
  styles: `
    :host { display: block; margin-top: 1rem; }
    summary { cursor: pointer; } p { line-height: 1.5; }
    .scroll { overflow: auto; max-height: 24rem; }
    table { width: 100%; border-collapse: collapse; font-size: .85rem; }
    th, td { text-align: left; vertical-align: top; padding: .5rem; border-bottom: 1px solid var(--border); overflow-wrap: anywhere; }
    caption { text-align: left; padding: .5rem; }
  `,
})
export class DispatchLogComponent {
  readonly log = input<DispatchLog | null>();
  protected readonly at = (value: string) => formatInstant(new Date(value));
}
