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
  /** Built as of a past instant: the feed is historical and the live sections are empty. */
  historical?: boolean;
}

/** A badge writer's right to write: the scope it read, and the epoch it read in. */
interface BadgeClaim {
  scope: string;
  epoch: number;
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

  /**
   * What the badge currently describes, and how many times it has been
   * invalidated.
   *
   * The badge has two writers — the full read carries a count, and the shell
   * reads counts alone — and on the Overview route both run for the same
   * organization, window and instant. A single sequence shared between them
   * made the later-issued request cancel the earlier one even then, so a
   * counts-only success followed by a full-read failure left the badge at
   * zero. Ordering is not the question here: the question is whether an
   * answer still describes what is on screen. Two answers for the same scope
   * are both valid, and either may write.
   */
  private badgeScope = '';
  private badgeEpoch = 0;

  /** Take the badge for a scope, and return the claim an answer must still hold. */
  private claimBadge(organizationId: string, range: TimeRange, asOf: Date | null): BadgeClaim {
    this.badgeScope = `${organizationId}|${range}|${asOf?.toISOString() ?? 'now'}`;
    return { scope: this.badgeScope, epoch: this.badgeEpoch };
  }

  /** Write a count if its claim still holds: same scope, and not cleared since. */
  private writeBadge(claim: BadgeClaim, unrecovered: number): void {
    if (claim.epoch === this.badgeEpoch && claim.scope === this.badgeScope) {
      this.unrecovered.set(unrecovered);
    }
  }

  async load(organizationId: string, range: TimeRange, asOf: Date | null = null): Promise<OrganizationOverview> {
    const request = ++this.loadRequest;
    const claim = this.claimBadge(organizationId, range, asOf);
    let params = new HttpParams().set('range', range);
    if (asOf) {
      params = params.set('as_of', asOf.toISOString());
    }
    const response = await firstValueFrom(
      this.http.get<OrganizationOverview>(orgPath(organizationId, '/overview'), { params }),
    );
    if (request === this.loadRequest) {
      this.overview.set(response);
    }
    this.writeBadge(claim, response.counts.unrecovered);
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
    this.badgeEpoch += 1;
    this.badgeScope = '';
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
    const claim = this.claimBadge(organizationId, range, asOf);
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
      this.writeBadge(claim, response.counts.unrecovered);
    } catch {
      // A failed read says nothing about the count, so it writes nothing. The
      // badge is zeroed when the scope it described goes, not when one of the
      // two reads for the current scope happens to fail — the other may have
      // already answered correctly.
    }
  }

  reset(): void {
    this.loadRequest += 1;
    this.clearBadge();
    this.overview.set(null);
  }
}
