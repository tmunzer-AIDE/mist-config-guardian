import { HttpClient, HttpParams } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { MistMfaService } from '../../core/mist-mfa.service';
import { orgPath } from '../../core/api';
import {
  ApprovalRequest,
  RestoreCredential,
  RestoreMode,
  RestoreOperation,
  RestoreOperationPage,
  RestoreTargetList,
  RestoreTargetQuery,
  RestoreVerification,
} from './restore.model';

/**
 * The restore API.
 *
 * Every method resolves to a plain value so pages can stay free of RxJS
 * lifetimes. The administrator token is only ever a request body argument: it is
 * never stored on the service, in a signal it owns, or in a URL.
 */
@Injectable({ providedIn: 'root' })
export class RestoreService {
  private readonly http = inject(HttpClient);
  private readonly mistMfa = inject(MistMfaService);

  private authorize(path: string, credential: RestoreCredential): Promise<RestoreOperation> {
    if (typeof credential === 'string') {
      return firstValueFrom(this.http.post<RestoreOperation>(path, { administrator_token: credential }));
    }
    return this.mistMfa.run((two_factor) => firstValueFrom(this.http.post<RestoreOperation>(path, {
      mist_login: { ...credential.mist_login, ...(two_factor ? { two_factor } : {}) },
    })));
  }

  /** Build a side-effect-free plan from the selected version ids. */
  createPlan(
    organizationId: string,
    versionIds: string[],
    mode: RestoreMode,
    includeDependencies: boolean,
  ): Promise<RestoreOperation> {
    return firstValueFrom(
      this.http.post<RestoreOperation>(orgPath(organizationId, '/restores/plans'), {
        version_ids: versionIds,
        mode,
        include_dependencies: includeDependencies,
      }),
    );
  }

  /** Authorize and queue the plan. The token is used once and discarded. */
  execute(
    organizationId: string,
    operationId: string,
    administratorToken: RestoreCredential,
  ): Promise<RestoreOperation> {
    return this.authorize(orgPath(organizationId, `/restores/${operationId}/execute`), administratorToken);
  }

  /**
   * Restorable object versions for step 1.
   *
   * Filtering is server-side because the type and site facet counts are: each
   * facet is counted with every filter except the one it drives, which a client
   * holding one page of results cannot reproduce.
   */
  targets(organizationId: string, query: RestoreTargetQuery = {}): Promise<RestoreTargetList> {
    let params = new HttpParams();
    if (query.scope) {
      params = params.set('scope', query.scope);
    }
    if (query.siteId) {
      params = params.set('site_id', query.siteId);
    }
    if (query.objectType) {
      params = params.set('object_type', query.objectType);
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
      this.http.get<RestoreTargetList>(orgPath(organizationId, '/restores/targets'), { params }),
    );
  }

  /** Recent restore operations for the step 1 rail. */
  list(organizationId: string, skip = 0, limit = 10): Promise<RestoreOperationPage> {
    const params = new HttpParams().set('skip', skip).set('limit', limit);
    return firstValueFrom(
      this.http.get<RestoreOperationPage>(orgPath(organizationId, '/restores'), { params }),
    );
  }

  /** One operation — also the polling read while a restore is in flight. */
  get(organizationId: string, operationId: string): Promise<RestoreOperation> {
    return firstValueFrom(
      this.http.get<RestoreOperation>(orgPath(organizationId, `/restores/${operationId}`)),
    );
  }

  /** Post-restore checks, snapshot, and reopened monitoring sessions. */
  verification(organizationId: string, operationId: string): Promise<RestoreVerification> {
    return firstValueFrom(
      this.http.get<RestoreVerification>(
        orgPath(organizationId, `/restores/${operationId}/verification`),
      ),
    );
  }

  /** Plan the reversal of the actions a failed run applied, in reverse order. */
  planCompensation(organizationId: string, operationId: string): Promise<RestoreOperation> {
    return firstValueFrom(
      this.http.post<RestoreOperation>(
        orgPath(organizationId, `/restores/${operationId}/compensation`),
        {},
      ),
    );
  }

  /** Authorize and queue the compensation plan. */
  executeCompensation(
    organizationId: string,
    operationId: string,
    administratorToken: RestoreCredential,
  ): Promise<RestoreOperation> {
    return this.authorize(orgPath(organizationId, `/restores/${operationId}/compensation/execute`), administratorToken);
  }

  /** Ask a second administrator to review this plan. */
  requestApproval(organizationId: string, restoreOperationId: string): Promise<ApprovalRequest> {
    return firstValueFrom(
      this.http.post<ApprovalRequest>(orgPath(organizationId, '/approvals'), {
        restore_operation_id: restoreOperationId,
      }),
    );
  }

  /** Re-read one approval so the authorize step can show a fresh decision. */
  approval(organizationId: string, approvalId: string): Promise<ApprovalRequest> {
    return firstValueFrom(
      this.http.get<ApprovalRequest>(orgPath(organizationId, `/approvals/${approvalId}`)),
    );
  }
}
