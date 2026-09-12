import { Injectable, signal } from '@angular/core';

/** Site preferences shared by scoped pages for the current signed-in session. */
@Injectable({ providedIn: 'root' })
export class SiteContextService {
  private readonly selections = signal<ReadonlyMap<string, string>>(new Map());

  selectedFor(organizationId: string | undefined): string {
    return organizationId ? this.selections().get(organizationId) ?? '' : '';
  }

  select(organizationId: string | undefined, siteId: string): void {
    if (!organizationId || this.selectedFor(organizationId) === siteId) return;
    this.selections.update((items) => new Map(items).set(organizationId, siteId));
  }

  reset(): void {
    this.selections.set(new Map());
  }
}
