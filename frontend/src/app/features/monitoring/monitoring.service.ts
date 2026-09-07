import { HttpClient, HttpParams } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';

import { MonitoringSession, MonitoringSessionList } from './monitoring.model';

@Injectable({ providedIn: 'root' })
export class MonitoringService {
  private readonly http = inject(HttpClient);

  list(organizationId: string, status?: string) {
    const params = status ? new HttpParams().set('status', status) : undefined;
    return this.http.get<MonitoringSessionList>(
      `/api/v1/organizations/${organizationId}/monitoring`,
      { params },
    );
  }

  get(organizationId: string, sessionId: string) {
    return this.http.get<MonitoringSession>(
      `/api/v1/organizations/${organizationId}/monitoring/${sessionId}`,
    );
  }
}
