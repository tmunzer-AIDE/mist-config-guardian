import { HttpClient, HttpParams } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { orgPath } from '../../core/api';
import {
  ConfigurationObject,
  ConfigurationObjectList,
  ConfigurationVersionList,
  ObjectQuery,
  ObjectFacets,
} from './history.model';

/** Logical configuration objects and their captured version chains. */
@Injectable({ providedIn: 'root' })
export class HistoryService {
  private readonly http = inject(HttpClient);

  facets(organizationId: string, includeDeleted: boolean): Promise<ObjectFacets> {
    return firstValueFrom(this.http.get<ObjectFacets>(orgPath(organizationId, '/objects/facets'), {
      params: { include_deleted: includeDeleted },
    }));
  }

  objects(organizationId: string, query: ObjectQuery = {}): Promise<ConfigurationObjectList> {
    let params = new HttpParams();
    if (query.scope) { params = params.set('scope', query.scope); }
    if (query.objectType) {
      params = params.set('object_type', query.objectType);
    }
    if (query.siteId) {
      params = params.set('site_id', query.siteId);
    }
    if (query.includeDeleted !== undefined) {
      params = params.set('include_deleted', query.includeDeleted);
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
    return firstValueFrom(
      this.http.get<ConfigurationObjectList>(orgPath(organizationId, '/objects'), { params }),
    );
  }

  /**
   * One object's identity.
   *
   * The rail holds a page, so the object being compared is not always in it;
   * this resolves the ones that are not.
   */
  object(organizationId: string, logicalObjectId: string): Promise<ConfigurationObject> {
    return firstValueFrom(
      this.http.get<ConfigurationObject>(orgPath(organizationId, `/objects/${logicalObjectId}`)),
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
