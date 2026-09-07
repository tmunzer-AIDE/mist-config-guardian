import { HttpClient } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';

import {
  Organization,
  OrganizationCreate,
  OrganizationList,
  SnapshotManifestList,
  WebhookSecret,
} from './organization.model';

@Injectable({ providedIn: 'root' })
export class OrganizationService {
  private readonly http = inject(HttpClient);

  list() {
    return this.http.get<OrganizationList>('/api/v1/organizations');
  }

  create(request: OrganizationCreate) {
    return this.http.post<Organization>('/api/v1/organizations', request);
  }

  verify(id: string) {
    return this.http.post<Organization>(`/api/v1/organizations/${id}/verify`, {});
  }

  snapshots(id: string) {
    return this.http.get<SnapshotManifestList>(`/api/v1/organizations/${id}/snapshots`);
  }

  triggerSnapshot(id: string, kind: 'initial' | 'manual') {
    return this.http.post<{ task_id: string }>(`/api/v1/organizations/${id}/snapshots`, { kind });
  }

  rotateWebhookSecret(id: string) {
    return this.http.post<WebhookSecret>(`/api/v1/organizations/${id}/webhook-secret/rotate`, {});
  }
}
