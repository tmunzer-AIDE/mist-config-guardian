import { ChangeDetectionStrategy, Component, input } from '@angular/core';

export interface PortSnapshot {
  up: boolean | null;
  poe_on: boolean | null;
  power_draw: number | null;
  observed_at: string | null;
  neighbor_handle: string | null;
  neighbor_identity: 'unverified';
}

@Component({
  selector: 'app-port-snapshot',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (port(); as row) {
      <p>Most recent port state · Link: {{ state(row.up) }} · PoE: {{ state(row.poe_on) }} ·
        Power draw: {{ row.power_draw ?? 'Unknown' }}</p>
      <p>Observed: {{ row.observed_at ?? 'Time unavailable' }}.</p>
      @if (row.neighbor_handle) { <p>Unverified neighbor: {{ row.neighbor_handle }}</p> }
      <p>This snapshot does not establish a transition, a managed or powered device, or impact.</p>
    }
  `,
  styles: `:host { display: block; overflow-wrap: anywhere; } p { margin: .3rem 0; }`,
})
export class PortSnapshotComponent {
  readonly port = input<PortSnapshot | null>();
  protected state(value: boolean | null): string {
    return value === null ? 'Unknown' : value ? 'On' : 'Off';
  }
}
