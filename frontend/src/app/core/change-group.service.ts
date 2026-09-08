import { HttpClient, HttpParams } from '@angular/common/http';
import { inject, Injectable, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { orgPath } from './api';
import { ChangeGroupDetail, ChangeGroupPage, ChangeGroupSummary } from './change-group.model';
import { TimeRange } from './time-context.service';

/** The four impact filters the Changes header offers. */
export type SeverityFilter = 'any' | 'critical' | 'warning' | 'none';

/** Query sent to the change-group index. */
export interface ChangeGroupQuery {
  range: TimeRange;
  severity?: SeverityFilter;
  /** Restrict to one administrator; the search page passes this through. */
  actor?: string;
  /** Free-text match over title, audit id, and object names. */
  q?: string;
  skip?: number;
  limit?: number;
  /**
   * Historical mode only. The list is reconstructed as of this instant so a
   * point-in-time view never mixes in groups that happened after it.
   */
  asOf?: Date | null;
}

/**
 * Change-group index and detail.
 *
 * The list is filtered server-side: impact severity is a stored column, so
 * paging and the total stay correct instead of the client filtering a page it
 * already fetched.
 */
@Injectable({ providedIn: 'root' })
export class ChangeGroupService {
  private readonly http = inject(HttpClient);

  readonly items = signal<ChangeGroupSummary[]>([]);
  /** Total matching the current query, which can exceed the page in `items`. */
  readonly total = signal(0);
  readonly detail = signal<ChangeGroupDetail | null>(null);

  // Answers arrive in any order; only the latest request of each kind
  // describes what is on screen, whichever organization it was for.
  private listRequest = 0;
  private detailRequest = 0;

  async list(organizationId: string, query: ChangeGroupQuery): Promise<ChangeGroupPage> {
    let params = new HttpParams().set('range', query.range).set('severity', query.severity ?? 'any');
    if (query.actor) {
      params = params.set('actor', query.actor);
    }
    if (query.q) {
      params = params.set('q', query.q);
    }
    if (query.skip !== undefined) {
      params = params.set('skip', query.skip);
    }
    if (query.limit !== undefined) {
      params = params.set('limit', query.limit);
    }
    if (query.asOf) {
      params = params.set('as_of', query.asOf.toISOString());
    }
    const request = ++this.listRequest;
    const response = await firstValueFrom(
      this.http.get<ChangeGroupPage>(orgPath(organizationId, '/change-groups'), { params }),
    );
    if (request === this.listRequest) {
      this.items.set(response.items);
      this.total.set(response.total);
    }
    return response;
  }

  /** Fetch the evidence, changed objects, and assessment for one group. */
  async load(organizationId: string, id: string, asOf: Date | null = null): Promise<ChangeGroupDetail> {
    const request = ++this.detailRequest;
    // The instant travels with the read: expanded from a past view the panel
    // must withhold the same fields the row does.
    const params = asOf ? new HttpParams().set('as_of', asOf.toISOString()) : undefined;
    const response = await firstValueFrom(
      this.http.get<ChangeGroupDetail>(orgPath(organizationId, `/change-groups/${id}`), { params }),
    );
    if (request === this.detailRequest) {
      this.detail.set(response);
    }
    return response;
  }

  clearDetail(): void {
    this.detail.set(null);
  }

  reset(): void {
    this.items.set([]);
    this.total.set(0);
    this.detail.set(null);
  }
}
