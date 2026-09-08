import { HttpClient, HttpParams } from '@angular/common/http';
import { inject, Injectable, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { orgPath } from './api';
import { ScopedState } from './scoped-state';
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
  /** Built as of a past instant: the feed is historical and the live sections are empty. */
  historical?: boolean;
}

/** What an Overview read describes: one organization, over one window, ending at one instant. */
function scopeKey(organizationId: string, range: TimeRange, asOf: Date | null): string {
  return `${organizationId}|${range}|${asOf?.toISOString() ?? 'now'}`;
}

/** The Overview page's purpose-built read model, plus the shell's nav badge. */
@Injectable({ providedIn: 'root' })
export class OverviewService {
  private readonly http = inject(HttpClient);

  readonly overview = signal<OrganizationOverview | null>(null);
  /** Change groups with unrecovered impact — drives the sidebar Changes badge. */
  readonly unrecovered = signal(0);

  /**
   * The read model and the badge each describe one scope at a time, and are
   * written by different requests: the full read fills both, while the shell
   * reads counts alone. Both follow the same rule — see `ScopedState` — and
   * they keep it separately, because a badge cleared on a scrub says nothing
   * about the model, and a model replaced on a page change says nothing about
   * the badge.
   */
  private readonly model = new ScopedState();
  private readonly badge = new ScopedState();

  async load(organizationId: string, range: TimeRange, asOf: Date | null = null): Promise<OrganizationOverview> {
    const scope = scopeKey(organizationId, range, asOf);
    // A replacement, not a refresh. What is on screen describes another
    // organization, window or instant, and the shell only hides it while the
    // read is in flight: after a failure the skeleton goes and it would be
    // visible again — today's safety net, approvals and failed restores
    // sitting under a historical banner. A refresh of the same scope keeps its
    // last good model, which a failure does not invalidate.
    const replacing = this.model.current !== scope;
    const modelClaim = this.model.claim(scope);
    if (replacing) {
      this.overview.set(null);
    }
    const badgeClaim = this.badge.claim(scope);
    let params = new HttpParams().set('range', range);
    if (asOf) {
      params = params.set('as_of', asOf.toISOString());
    }
    const response = await firstValueFrom(
      this.http.get<OrganizationOverview>(orgPath(organizationId, '/overview'), { params }),
    );
    if (this.model.accepts(modelClaim)) {
      this.overview.set(response);
    }
    if (this.badge.accepts(badgeClaim)) {
      this.unrecovered.set(response.counts.unrecovered);
    }
    return response;
  }

  /**
   * Forget the change badge without touching the Overview's own read model.
   *
   * The count is an outcome for one organization, range and instant. When any
   * of those move it stops describing what is on screen, and a slow or hanging
   * re-read would otherwise leave it asserting harm that belongs elsewhere.
   */
  clearBadge(): void {
    this.badge.invalidate();
    this.unrecovered.set(0);
  }

  /**
   * Cheap counts-only read that keeps the navigation badges live.
   *
   * It takes the same range as the full read: the badge sits beside the
   * Changes link, and clicking through must not show a different number
   * because the shell asked over a different window.
   */
  async loadBadges(organizationId: string, range: TimeRange, asOf: Date | null = null): Promise<void> {
    const claim = this.badge.claim(scopeKey(organizationId, range, asOf));
    try {
      // The unrecovered count is an outcome; the server withholds it for a
      // past instant, and the badge disappears with it rather than asserting
      // that nothing went wrong then.
      let params = new HttpParams().set('counts_only', true).set('range', range);
      if (asOf) {
        params = params.set('as_of', asOf.toISOString());
      }
      const response = await firstValueFrom(
        this.http.get<{ counts: OverviewCounts }>(orgPath(organizationId, '/overview'), { params }),
      );
      if (this.badge.accepts(claim)) {
        this.unrecovered.set(response.counts.unrecovered);
      }
    } catch {
      // A failed read says nothing about the count, so it writes nothing and
      // does not count as a newer reading. The badge is zeroed when the scope
      // it described goes, not when one of the two reads for the current scope
      // happens to fail — the other may have already answered correctly.
    }
  }

  reset(): void {
    this.model.invalidate();
    this.overview.set(null);
    this.clearBadge();
  }
}
