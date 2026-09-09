import { HttpClient, HttpParams } from '@angular/common/http';
import { inject, Injectable, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { orgPath } from './api';
import { TimeRange } from './time-context.service';

/** One change marker drawn on the shell's time track. */
export interface TimelineMarker {
  at: string;
  severity: 'none' | 'info' | 'warning' | 'critical';
  /** False on a past window, where the severity is not knowable. */
  impact_known?: boolean;
  change_group_id: string;
  label: string;
}

interface TimelineResponse {
  items: TimelineMarker[];
  range_start: string;
  range_end: string;
}

/** Timeline markers for the global time-travel bar. */
@Injectable({ providedIn: 'root' })
export class TimelineService {
  private readonly http = inject(HttpClient);

  readonly markers = signal<TimelineMarker[]>([]);
  readonly bounds = signal<{ start: Date; end: Date } | null>(null);

  /** Only the latest read describes the track; a slow answer for a previous organization must not. */
  private request = 0;
  /** The organization the markers on the track belong to. */
  private owner: string | null = null;

  async load(organizationId: string, range: TimeRange): Promise<void> {
    if (this.owner !== organizationId) {
      // The track is drawn from one organization's changes. Clearing here
      // rather than on the answer means the previous organization's markers
      // are gone even if this read fails or never answers.
      this.owner = organizationId;
      this.markers.set([]);
      this.bounds.set(null);
    }
    const request = ++this.request;
    // The instant reaches this endpoint in the as-of header, which the session
    // interceptor sets from the current time context. The caller only has to
    // read that context so the read happens again when it moves.
    const params = new HttpParams().set('range', range);
    try {
      const response = await firstValueFrom(
        this.http.get<TimelineResponse>(orgPath(organizationId, '/point-in-time/markers'), {
          params,
        }),
      );
      if (request === this.request) {
        this.markers.set(response.items);
        const start = new Date(response.range_start),
          end = new Date(response.range_end);
        this.bounds.set(
          Number.isFinite(start.getTime()) && Number.isFinite(end.getTime()) && end > start
            ? { start, end }
            : null,
        );
      }
    } catch {
      // A failed read leaves an empty track rather than markers that no longer
      // describe anything on screen.
      if (request === this.request) {
        this.markers.set([]);
        this.bounds.set(null);
      }
    }
  }

  reset(): void {
    this.request += 1;
    this.owner = null;
    this.markers.set([]);
    this.bounds.set(null);
  }
}
