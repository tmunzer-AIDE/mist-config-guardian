import { HttpClient, HttpParams } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { orgPath } from '../../core/api';
import { ConfigurationDiff, DiffExportFormat, RawConfigurationDiff } from './diff.model';

/** Options for a partial structured-diff fetch. */
export interface DiffQuery {
  /** Restrict entry bodies to these section keys. */
  sections?: readonly string[];
  /** Pass false for a metadata-only response: counts, summary, section heads. */
  includeEntries?: boolean;
}

/**
 * Deterministic diffing between two captured versions.
 *
 * Every value here is computed by the API, never generated: the page renders
 * these results whether or not AI assist is configured.
 */
@Injectable({ providedIn: 'root' })
export class DiffService {
  private readonly http = inject(HttpClient);

  compare(
    organizationId: string,
    fromVersionId: string,
    toVersionId: string,
    query: DiffQuery = {},
  ): Promise<ConfigurationDiff> {
    let params = pair(fromVersionId, toVersionId);
    if (query.sections && query.sections.length > 0) {
      params = params.set('sections', query.sections.join(','));
    }
    if (query.includeEntries === false) {
      params = params.set('include_entries', false);
    }
    return firstValueFrom(this.http.get<ConfigurationDiff>(orgPath(organizationId, '/diff'), { params }));
  }

  raw(organizationId: string, fromVersionId: string, toVersionId: string): Promise<RawConfigurationDiff> {
    return firstValueFrom(
      this.http.get<RawConfigurationDiff>(orgPath(organizationId, '/diff/raw'), {
        params: pair(fromVersionId, toVersionId),
      }),
    );
  }

  export(
    organizationId: string,
    fromVersionId: string,
    toVersionId: string,
    format: DiffExportFormat,
  ): Promise<Blob> {
    return firstValueFrom(
      this.http.get(orgPath(organizationId, '/diff/export'), {
        params: pair(fromVersionId, toVersionId).set('format', format),
        responseType: 'blob',
      }),
    );
  }
}

function pair(fromVersionId: string, toVersionId: string): HttpParams {
  return new HttpParams().set('from_version_id', fromVersionId).set('to_version_id', toVersionId);
}
