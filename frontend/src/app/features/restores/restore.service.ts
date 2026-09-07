import { HttpClient } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';

import { RestoreMode, RestoreOperation } from './restore.model';

@Injectable({ providedIn: 'root' })
export class RestoreService {
  private readonly http = inject(HttpClient);

  createPlan(
    organizationId: string,
    versionIds: string[],
    mode: RestoreMode,
    includeDependencies: boolean,
  ) {
    return this.http.post<RestoreOperation>(
      `/api/v1/organizations/${organizationId}/restores/plans`,
      {
        version_ids: versionIds,
        mode,
        include_dependencies: includeDependencies,
      },
    );
  }

  execute(organizationId: string, operationId: string, administratorToken: string) {
    return this.http.post<RestoreOperation>(
      `/api/v1/organizations/${organizationId}/restores/${operationId}/execute`,
      { administrator_token: administratorToken },
    );
  }
}
