import { HttpClient, HttpParams } from '@angular/common/http';
import { inject, Injectable, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { orgPath } from './api';
import { ChangeGroupSummary } from './change-group.model';
import { TimeRange } from './time-context.service';

export type SafetyNetStatus = 'ok' | 'warn' | 'crit';

/** One line in the Overview "safety net" card. */
export interface SafetyNetItem {
  key: 'backup' | 'webhook' | 'reconciliation' | 'credential';
  label: string;
  status: SafetyNetStatus;
  detail: string;
}

export interface PendingApproval {
  id: string;
  restore_operation_id: string;
  title: string;
  detail: string;
  requested_by_email: string;
  requested_at: string;
}

export interface FailedRestore {
  id: string;
  title: string;
  detail: string;
  failed_at: string;
  compensation_available: boolean;
}

export interface OverviewCounts {
  change_groups: number;
  impacting: number;
  mine: number;
  unrecovered: number;
  pending_approvals: number;
  failed_restores: number;
}

export interface OrganizationOverview {
  generated_at: string;
  range_start: string;
  range_end: string;
  counts: OverviewCounts;
  change_groups: ChangeGroupSummary[];
  safety_net: SafetyNetItem[];
  pending_approvals: PendingApproval[];
  failed_restores: FailedRestore[];
  latest_snapshot_at: string | null;
  latest_snapshot_objects: number | null;
}

/** The Overview page's purpose-built read model, plus the shell's nav badge. */
@Injectable({ providedIn: 'root' })
export class OverviewService {
  private readonly http = inject(HttpClient);

  readonly overview = signal<OrganizationOverview | null>(null);
  /** Change groups with unrecovered impact — drives the sidebar Changes badge. */
  readonly unrecovered = signal(0);

  // Answers arrive in any order; only the latest request describes the
  // organization and range on screen. A slow answer for a previous
  // organization must not overwrite the current one.
  private loadRequest = 0;
  private badgeRequest = 0;

  async load(organizationId: string, range: TimeRange): Promise<OrganizationOverview> {
    const request = ++this.loadRequest;
    const params = new HttpParams().set('range', range);
    const response = await firstValueFrom(
      this.http.get<OrganizationOverview>(orgPath(organizationId, '/overview'), { params }),
    );
    if (request === this.loadRequest) {
      this.overview.set(response);
      this.unrecovered.set(response.counts.unrecovered);
    }
    return response;
  }

  /** Cheap counts-only fetch used by the shell so navigation badges stay live. */
  async loadBadges(organizationId: string): Promise<void> {
    const request = ++this.badgeRequest;
    try {
      const params = new HttpParams().set('counts_only', true);
      const response = await firstValueFrom(
        this.http.get<{ counts: OverviewCounts }>(orgPath(organizationId, '/overview'), { params }),
      );
      if (request === this.badgeRequest) {
        this.unrecovered.set(response.counts.unrecovered);
      }
    } catch {
      if (request === this.badgeRequest) {
        this.unrecovered.set(0);
      }
    }
  }

  reset(): void {
    this.overview.set(null);
    this.unrecovered.set(0);
  }
}
