import { ChangeDetectionStrategy, Component, computed, effect, inject, signal, untracked } from '@angular/core';
import { Router } from '@angular/router';

import { OrganizationContextService } from '../../core/organization-context.service';
import { SearchResult, SearchResultKind, SearchService } from '../../core/search.service';
import { UiStateService } from '../../core/ui-state.service';

const ROUTES: Record<string, string> = {
  overview: '/',
  changes: '/changes',
  history: '/history',
  restore: '/restore',
  impact: '/impact',
  settings: '/settings',
};

const KIND_LABEL: Record<SearchResultKind, string> = {
  object: 'OBJECT',
  change_group: 'CHANGE',
  actor: 'ACTOR',
  audit_id: 'AUDIT',
  restore: 'RESTORE',
  site: 'SITE',
};

/**
 * Results for the header's global search.
 *
 * The approved design defines the search field but not a results surface, so
 * this page reuses the established row and badge language rather than
 * introducing a new pattern.
 */
@Component({
  selector: 'app-search-page',
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './search-page.html',
  styleUrl: './search-page.scss',
})
export class SearchPage {
  private readonly router = inject(Router);
  private readonly organizations = inject(OrganizationContextService);
  private readonly ui = inject(UiStateService);
  protected readonly search = inject(SearchService);

  protected readonly kinds = signal<SearchResultKind | 'all'>('all');
  protected readonly query = this.search.query;

  protected readonly results = computed(() => {
    const kind = this.kinds();
    return this.search
      .results()
      .filter((item) => kind === 'all' || item.kind === kind)
      .map((item) => ({ ...item, kindLabel: KIND_LABEL[item.kind] }));
  });

  protected readonly available = computed(() => {
    const counts = new Map<SearchResultKind, number>();
    for (const item of this.search.results()) {
      counts.set(item.kind, (counts.get(item.kind) ?? 0) + 1);
    }
    return [...counts.entries()].map(([kind, count]) => ({ kind, count, label: KIND_LABEL[kind] }));
  });

  protected readonly subtitle = computed(() => {
    const term = this.search.query().trim();
    if (term.length < 2) {
      return 'Type at least two characters to search objects, actors, and audit IDs.';
    }
    const total = this.search.results().length;
    return `${total} result${total === 1 ? '' : 's'} for “${term}”`;
  });

  constructor() {
    effect(() => {
      const organizationId = this.organizations.selected()?.id;
      const term = this.search.query();
      if (!organizationId) {
        return;
      }
      void untracked(() => this.ui.track('Searching', () => this.search.run(organizationId, term)));
    });
  }

  protected async open(result: SearchResult): Promise<void> {
    await this.router.navigate([ROUTES[result.target] ?? '/'], { queryParams: result.target_params });
  }
}
