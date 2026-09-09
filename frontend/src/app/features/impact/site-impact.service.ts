import { HttpClient, HttpParams } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import { orgPath } from '../../core/api';
import { ImpactSite, SiteChangeList, SiteTopology } from './site-impact.model';
@Injectable({ providedIn: 'root' })
export class SiteImpactService {
  private readonly http = inject(HttpClient);
  sites(org: string, asOf: string | null) {
    return this.http.get<{ items: ImpactSite[] }>(orgPath(org, '/impact/sites'), {
      params: asOf ? { as_of: asOf } : {},
    });
  }
  topology(org: string, site: string, asOf: string | null) {
    return this.http.get<SiteTopology>(
      orgPath(org, `/impact/sites/${encodeURIComponent(site)}/topology`),
      { params: asOf ? { as_of: asOf } : {} },
    );
  }
  changes(org: string, site: string, range: string, asOf: string | null, skip = 0) {
    let params = new HttpParams().set('range', range).set('skip', skip).set('limit', 50);
    if (asOf) params = params.set('as_of', asOf);
    return this.http.get<SiteChangeList>(
      orgPath(org, `/impact/sites/${encodeURIComponent(site)}/changes`),
      { params },
    );
  }
}
