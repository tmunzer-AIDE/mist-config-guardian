import { ChangeDetectionStrategy, Component, input } from '@angular/core';
export interface ApAdjacency {
  device_handle: string; connected: boolean | null; observed_at: string | null;
  relationship: 'corroborated_recent' | 'unverified'; historical_dependency: 'not_established'; device_failure: 'not_established';
}
@Component({
  selector: 'app-ap-adjacency', changeDetection: ChangeDetectionStrategy.OnPush,
  template: `@if (value(); as row) {
    <p>Managed AP: {{ row.device_handle }}</p>
    <p>{{ row.relationship === 'corroborated_recent' ? 'Recent reciprocal adjacency corroborated' : 'Physical relationship unverified' }}.</p>
    <p>Reported connectivity: {{ row.connected === null ? 'Unknown' : row.connected ? 'Connected' : 'Disconnected' }} · Observed {{ row.observed_at ?? 'Time unavailable' }}.</p>
    <p>Historical dependency, sole power path and device failure are not established.</p>
  }`,
  styles: `:host { display:block; overflow-wrap:anywhere; } p { margin:.3rem 0; }`,
})
export class ApAdjacencyComponent { readonly value = input<ApAdjacency | null | undefined>(); }
