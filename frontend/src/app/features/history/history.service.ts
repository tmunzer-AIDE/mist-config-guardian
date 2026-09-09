import { HttpClient, HttpParams } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { orgPath } from '../../core/api';
import { ConfigurationObjectList, ConfigurationVersionList, ObjectQuery } from './history.model';

/** Logical configuration objects and their captured version chains. */
@Injectable({ providedIn: 'root' })
export class HistoryService {
  private readonly http = inject(HttpClient);

  objects(organizationId: string, query: ObjectQuery = {}): Promise<ConfigurationObjectList> {
    let params = new HttpParams();
    if (query.objectType) {
      params = params.set('object_type', query.objectType);
    }
    if (query.siteId) {
      params = params.set('site_id', query.siteId);
    }
    if (query.includeDeleted !== undefined) {
      params = params.set('include_deleted', query.includeDeleted);
    }
    if (query.skip !== undefined) {
      params = params.set('skip', query.skip);
    }
    if (query.limit !== undefined) {
      params = params.set('limit', query.limit);
    }
    return firstValueFrom(
      this.http.get<ConfigurationObjectList>(orgPath(organizationId, '/objects'), { params }),
    );
  }

  /** Versions for one logical object, newest first. */
  versions(organizationId: string, logicalObjectId: string): Promise<ConfigurationVersionList> {
    return firstValueFrom(
      this.http.get<ConfigurationVersionList>(
        orgPath(organizationId, `/objects/${logicalObjectId}/versions`),
      ),
    );
  }
}
