import { HttpClient, HttpParams } from '@angular/common/http';
import { inject, Injectable, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { orgPath } from '../../core/api';
import {
  ImpactSeverity,
  MonitoringSession,
  MonitoringSessionList,
  MonitoringStatus,
} from './monitoring.model';

/** Server-side narrowing accepted by `GET /organizations/{id}/monitoring`. */
export interface MonitoringQuery {
  status?: MonitoringStatus;
  severity?: ImpactSeverity;
  skip?: number;
  limit?: number;
}

const PAGE_SIZE = 100;

/**
 * Monitoring sessions for the Impact page.
 *
 * The list endpoint already returns whole sessions — baseline, observations and
 * incidents included — so the detail endpoint is only used to resolve a deep
 * link whose session falls outside the current filter.
 */
@Injectable({ providedIn: 'root' })
export class MonitoringService {
  private readonly http = inject(HttpClient);

  readonly sessions = signal<MonitoringSession[]>([]);
  readonly total = signal(0);
  /** A session fetched by ID because the loaded page does not contain it. */
  readonly resolved = signal<MonitoringSession | null>(null);

  list(organizationId: string, query: MonitoringQuery = {}) {
    let params = new HttpParams();
    if (query.status) {
      params = params.set('status', query.status);
    }
    if (query.severity) {
      params = params.set('severity', query.severity);
    }
    if (query.skip !== undefined) {
      params = params.set('skip', query.skip);
    }
    params = params.set('limit', query.limit ?? PAGE_SIZE);
    return this.http.get<MonitoringSessionList>(orgPath(organizationId, '/monitoring'), { params });
  }

  get(organizationId: string, sessionId: string) {
    return this.http.get<MonitoringSession>(orgPath(organizationId, `/monitoring/${sessionId}`));
  }

  /** Load a page of sessions into the signals the page renders from. */
  // Answers arrive in any order; only the latest request of each kind
  // describes what is on screen, whichever organization it was for.
  private loadRequest = 0;
  private sessionRequest = 0;

  async load(organizationId: string, query: MonitoringQuery = {}): Promise<MonitoringSessionList> {
    const request = ++this.loadRequest;
    const response = await firstValueFrom(this.list(organizationId, query));
    if (request === this.loadRequest) {
      this.sessions.set(response.items);
      this.total.set(response.total);
    }
    return response;
  }

  /**
   * Resolve one session by ID for a `?session=` deep link.
   *
   * A link can point at a session the current filter excludes, or at one that
   * has since been deleted; a failure clears the held session rather than
   * raising, so the page falls back to its first row.
   */
  async loadSession(organizationId: string, sessionId: string): Promise<MonitoringSession | null> {
    const request = ++this.sessionRequest;
    try {
      const session = await firstValueFrom(this.get(organizationId, sessionId));
      if (request === this.sessionRequest) {
        this.resolved.set(session);
      }
      return session;
    } catch {
      if (request === this.sessionRequest) {
        this.resolved.set(null);
      }
      return null;
    }
  }

  /**
   * Forget everything read so far.
   *
   * A single-session answer still in flight is dropped, since nothing newer
   * would supersede it. A list read is not: the read for the organization
   * being switched to may already be in flight, and it is the latest.
   */
  reset(): void {
    this.sessionRequest += 1;
    this.sessions.set([]);
    this.total.set(0);
    this.resolved.set(null);
  }
}
