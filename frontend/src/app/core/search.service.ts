import { HttpClient, HttpParams } from '@angular/common/http';
import { inject, Injectable, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { orgPath } from './api';

export type SearchResultKind = 'object' | 'change_group' | 'actor' | 'audit_id' | 'restore' | 'site';

export interface SearchResult {
  kind: SearchResultKind;
  id: string;
  title: string;
  subtitle: string;
  meta: string;
  target: string;
  target_params: Record<string, string>;
}

interface SearchResponse {
  items: SearchResult[];
  total: number;
}

/** Global search across configuration objects, actors, and audit identifiers. */
@Injectable({ providedIn: 'root' })
export class SearchService {
  private readonly http = inject(HttpClient);

  readonly query = signal('');
  readonly results = signal<SearchResult[]>([]);
  readonly searching = signal(false);

  setQuery(value: string): void {
    this.query.set(value);
  }

  async run(organizationId: string, query: string, limit = 25): Promise<SearchResult[]> {
    const term = query.trim();
    if (term.length < 2) {
      this.results.set([]);
      return [];
    }
    this.searching.set(true);
    try {
      const params = new HttpParams().set('q', term).set('limit', limit);
      const response = await firstValueFrom(
        this.http.get<SearchResponse>(orgPath(organizationId, '/search'), { params }),
      );
      this.results.set(response.items);
      return response.items;
    } finally {
      this.searching.set(false);
    }
  }

  reset(): void {
    this.query.set('');
    this.results.set([]);
  }
}
