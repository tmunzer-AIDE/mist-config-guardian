import { ChangeDetectionStrategy, Component, input } from '@angular/core';

export interface ManagedNeighbor {
  device_handle: string;
  kind: 'ap';
  identity: 'verified_inventory';
  relationship: 'unverified';
}

@Component({
  selector: 'app-managed-neighbor',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (neighbor(); as row) {
      <p>Managed AP inventory match: {{ row.device_handle }}</p>
      <p>Collected: {{ capturedAt() ?? 'Time unavailable' }}.</p>
      <p>Membership was verified at collection time. The physical link, PoE dependency and impact remain unverified.</p>
    }
  `,
  styles: `:host { display: block; overflow-wrap: anywhere; } p { margin: .3rem 0; }`,
})
export class ManagedNeighborComponent {
  readonly neighbor = input<ManagedNeighbor | null>();
  readonly capturedAt = input<string | null>();
}
