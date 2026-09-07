import { HttpClient, HttpParams } from '@angular/common/http';
import { inject, Injectable, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { orgPath } from './api';
import { TimeRange } from './time-context.service';

/** One change marker drawn on the shell's time track. */
export interface TimelineMarker {
  at: string;
  severity: 'none' | 'info' | 'warning' | 'critical';
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

  async load(organizationId: string, range: TimeRange): Promise<void> {
    const params = new HttpParams().set('range', range);
    const response = await firstValueFrom(
      this.http.get<TimelineResponse>(orgPath(organizationId, '/point-in-time/markers'), { params }),
    );
    this.markers.set(response.items);
  }

  reset(): void {
    this.markers.set([]);
  }
}
