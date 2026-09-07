import { HttpClient, HttpParams } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';

import { ConfigurationObjectList, ConfigurationVersionList } from './history.model';

@Injectable({ providedIn: 'root' })
export class HistoryService {
  private readonly http = inject(HttpClient);

  objects(organizationId: string, includeDeleted: boolean) {
    const params = new HttpParams().set('include_deleted', includeDeleted);
    return this.http.get<ConfigurationObjectList>(
      `/api/v1/organizations/${organizationId}/objects`,
      { params },
    );
  }

  versions(organizationId: string, objectId: string) {
    return this.http.get<ConfigurationVersionList>(
      `/api/v1/organizations/${organizationId}/objects/${objectId}/versions`,
    );
  }
}
