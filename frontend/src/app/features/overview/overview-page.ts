import {
  ChangeDetectionStrategy,
  Component,
  computed,
  DestroyRef,
  effect,
  inject,
  signal,
  untracked,
} from '@angular/core';
import { Router } from '@angular/router';

import { ChangeGroupSummary } from '../../core/change-group.model';
import { formatAgo, formatCount, formatDate, formatTime } from '../../core/format';
import { OrganizationContextService } from '../../core/organization-context.service';
import { OverviewService } from '../../core/overview.service';
import { TimeContextService } from '../../core/time-context.service';
import { UiStateService } from '../../core/ui-state.service';
import { AuthService } from '../../core/auth.service';
import { toneOf } from '../../core/tone';

type FeedFilter = 'all' | 'impacting' | 'mine';

@Component({
  selector: 'app-overview-page',
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './overview-page.html',
  styleUrl: './overview-page.scss',
})
export class OverviewPage {
  private readonly router = inject(Router);
  private readonly ui = inject(UiStateService);
  private readonly organizations = inject(OrganizationContextService);
  private readonly auth = inject(AuthService);
  protected readonly overview = inject(OverviewService);
  protected readonly time = inject(TimeContextService);

  /** The read on screen; a superseded one reports nothing. */
  private scope = new AbortController();

  protected readonly filter = signal<FeedFilter>('all');
  protected readonly filters: FeedFilter[] = ['all', 'impacting', 'mine'];

  protected readonly organization = this.organizations.selected;

  protected readonly counts = computed(() => this.overview.overview()?.counts ?? null);

  protected readonly subtitle = computed(() => {
    const model = this.overview.overview();
    if (!model || model.counts.change_groups === 0) {
      return 'No change history yet';
    }
    const day = formatDate(new Date(model.range_end));
    const groups = `${formatCount(model.counts.change_groups)} change group${model.counts.change_groups === 1 ? '' : 's'}`;
    return `${day} · ${groups} · ${model.counts.unrecovered} with unrecovered impact · times UTC`;
  });

  protected readonly feed = computed(() => {
    const model = this.overview.overview();
    if (!model) {
      return [];
    }
    const active = this.filter();
    return model.change_groups
      .filter((group) => {
        if (active === 'impacting') {
          return group.impact_severity === 'critical' || group.impact_severity === 'warning';
        }
        if (active === 'mine') {
          return group.is_mine;
        }
        return true;
      })
      .map((group) => this.toCard(group));
  });

  protected readonly hasChanges = computed(() => (this.overview.overview()?.change_groups.length ?? 0) > 0);
  protected readonly atNow = computed(() => !this.time.isHistorical() && this.hasChanges());
  protected readonly nowLabel = computed(() => formatTime(new Date()));

  /** Built as of the past: approvals, failed restores and the safety net have no past to show. */
  protected readonly historical = computed(() => this.overview.overview()?.historical ?? false);

  protected readonly pending = computed(() => this.overview.overview()?.pending_approvals ?? []);
  protected readonly failed = computed(() => this.overview.overview()?.failed_restores ?? []);
  protected readonly safety = computed(() => this.overview.overview()?.safety_net ?? []);

  protected readonly emptyTitle = computed(() => {
    const organization = this.organization();
    return organization && organization.status !== 'verified'
      ? `No snapshot yet for ${organization.name}`
      : 'No changes in this window';
  });

  protected readonly emptyBody = computed(() =>
    this.organization()?.status !== 'verified'
      ? 'This organization is onboarded but its service token has not been verified and no initial snapshot has run. Configuration history and change monitoring begin after the first snapshot completes.'
      : 'Nothing was changed in the selected range. Widen the window or clear the impact filter.',
  );

  constructor() {
    // The as-of instant is an input to the read, not only to the banner: the
    // server ends the window there and leaves out what has no past.
    effect(() => {
      const organizationId = this.organizations.selected()?.id;
      const range = this.time.range();
      const asOf = this.time.asOf();
      if (!organizationId) {
        return;
      }
      untracked(() => {
        // A read the page has moved on from must not hold the shell skeleton
        // up or raise a banner about a window nobody is looking at.
        this.scope.abort();
        this.scope = new AbortController();
        void this.ui.track(
          'Loading overview',
          () => this.overview.load(organizationId, range, asOf),
          this.scope.signal,
        );
      });
    });

    inject(DestroyRef).onDestroy(() => this.scope.abort());
  }

  protected approvalMeta(requestedByEmail: string, requestedAt: string): string {
    const actor = requestedByEmail.split('@')[0].toUpperCase();
    return `${actor} · ${formatAgo(new Date(requestedAt))}`;
  }

  protected async open(id: string): Promise<void> {
    await this.router.navigate(['/changes'], { queryParams: { group: id } });
  }

  protected async planRestore(group: ChangeGroupSummary): Promise<void> {
    // The restore page resolves the change group into pre-selected targets so
    // the operator lands on step 1 with the right objects already chosen.
    await this.router.navigate(['/restore'], { queryParams: { changeGroup: group.id } });
  }

  protected async openImpact(group: ChangeGroupSummary): Promise<void> {
    await this.router.navigate(['/impact'], { queryParams: { session: group.monitoring_session_ids[0] } });
  }

  protected async openApproval(restoreOperationId: string): Promise<void> {
    await this.router.navigate(['/restore'], { queryParams: { operation: restoreOperationId, step: 'authorize' } });
  }

  protected async openCompensation(operationId: string): Promise<void> {
    await this.router.navigate(['/restore'], { queryParams: { operation: operationId, compensate: 1 } });
  }

  protected async openSettings(): Promise<void> {
    await this.router.navigate(['/settings'], { queryParams: { tab: 'organizations' } });
  }

  protected canRestore(): boolean {
    return this.auth.can('operator') && !this.time.isHistorical();
  }

  private toCard(group: ChangeGroupSummary) {
    // A past view withholds the outcome, so the card says so rather than
    // wearing the neutral tone that would read as "no impact".
    const known = group.impact_known !== false;
    const tone = toneOf(group.impact_severity);
    const prominent = known && group.impact_severity === 'critical';
    return {
      group,
      id: group.id,
      time: formatTime(new Date(group.occurred_at)),
      tone,
      prominent,
      level: known ? group.impact_label : 'IMPACT NOT SHOWN',
      title: group.title,
      summary: group.summary,
      audit: `AUDIT ${shortAudit(group.audit_id)}`,
      metrics: group.metrics.map((metric) => ({ ...metric, tone: toneOf(metric.severity) })),
      restorable: group.impact_severity === 'critical' || group.impact_severity === 'warning',
      inspectable: group.monitoring_session_ids.length > 0,
    };
  }
}

function shortAudit(auditId: string): string {
  const compact = auditId.replace(/-/g, '').toUpperCase();
  return compact.length > 7 ? `${compact.slice(0, 4)}…${compact.slice(-3)}` : compact;
}
