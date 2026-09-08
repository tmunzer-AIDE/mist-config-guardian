import { HttpClient } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';

import { orgPath } from './api';

import {
  Organization,
  OrganizationCreate,
  OrganizationList,
  OrganizationUpdate,
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

  get(id: string) {
    return this.http.get<Organization>(orgPath(id));
  }

  /** Update the non-credential settings the organization card exposes. */
  update(id: string, patch: OrganizationUpdate) {
    return this.http.patch<Organization>(orgPath(id), patch);
  }

  /** Replace the read-only service token. Write-capable tokens are refused. */
  replaceServiceToken(id: string, serviceToken: string, password: string) {
    return this.http.put<Organization>(orgPath(id, '/service-token'), {
      service_token: serviceToken,
      password,
    });
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

  rotateWebhookSecret(id: string, password: string) {
    return this.http.post<WebhookSecret>(`/api/v1/organizations/${id}/webhook-secret/rotate`, {
      password,
    });
  }
}
