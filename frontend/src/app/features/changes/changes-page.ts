import {
  afterNextRender,
  ChangeDetectionStrategy,
  Component,
  computed,
  effect,
  ElementRef,
  inject,
  Injector,
  input,
  signal,
  untracked,
} from '@angular/core';
import { Router } from '@angular/router';

import { AuthService } from '../../core/auth.service';
import { ChangedObject, ChangeGroupSummary, RecoveryState } from '../../core/change-group.model';
import { ChangeGroupService, SeverityFilter } from '../../core/change-group.service';
import { formatCount, formatDate, formatDay, formatTime } from '../../core/format';
import { OrganizationContextService } from '../../core/organization-context.service';
import { TimeContextService } from '../../core/time-context.service';
import { Tone, toneOf } from '../../core/tone';
import { UiStateService } from '../../core/ui-state.service';
import { GuardianPanel } from './guardian-panel';
import { GuardianBadge } from '../../shared/guardian-badge';
import { ChangeConfiguration } from './change-configuration';
import { ChangeImpact } from './change-impact';
import { ChangeOutcome, ChangeSection } from './change-outcome';
import { RestorePage } from '../restore/restore-page';
import { MAX_PLAN_VERSIONS } from '../restore/restore.model';
import { RestoreService } from '../restore/restore.service';

/** Server-side paging keeps search and counts consistent across the full period. */
const PAGE_SIZE = 100;

/** The recovery word the design prints under the impact badge. */
const RECOVERY_LABEL: Record<RecoveryState, string> = {
  not_applicable: '',
  monitoring: 'monitoring',
  recovered: 'recovered',
  unrecovered: 'unrecovered',
  completed: 'completed',
};

/** One change group as the six columns of the table render it. */
interface GroupRow {
  id: string;
  group: ChangeGroupSummary;
  time: string;
  title: string;
  actor: string;
  objects: string;
  devices: string;
  impact: string;
  recovery: string;
  tone: Tone;
}

/** A day separator and the groups that fall under it. */
interface ChangeDay {
  key: string;
  label: string;
  rows: GroupRow[];
}

@Component({
  selector: 'app-changes-page',
  imports: [
    GuardianPanel,
    GuardianBadge,
    ChangeConfiguration,
    ChangeImpact,
    ChangeOutcome,
    RestorePage,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './changes-page.html',
  styleUrl: './changes-page.scss',
})
export class ChangesPage {
  private readonly router = inject(Router);
  private readonly ui = inject(UiStateService);
  private readonly organizations = inject(OrganizationContextService);
  private readonly auth = inject(AuthService);
  protected readonly changeGroups = inject(ChangeGroupService);
  protected readonly time = inject(TimeContextService);
  private readonly restores = inject(RestoreService);
  private readonly element = inject<ElementRef<HTMLElement>>(ElementRef);
  private readonly injector = inject(Injector);
  private focusDetail = false;
  private selectionRevision = 0;
  private pagingScope = '';
  protected readonly restoreOperation = signal('');
  protected readonly restoreBusy = signal(false);
  protected readonly restoreError = signal('');
  protected readonly detailError = signal(false);
  protected readonly listError = signal(false);
  protected readonly reload = signal(0);
  protected readonly increment = (n: number) => n + 1;
  protected readonly query = signal('');
  protected readonly skip = signal(0);
  protected readonly pageSize = PAGE_SIZE;
  protected readonly rawDetail = computed(() => {
    const value = this.changeGroups.detail();
    return value?.id === this.selectedId() ? value : null;
  });
  protected readonly restorable = computed(
    () => this.rawDetail()?.changed_objects.filter((o) => o.before_version_id) ?? [],
  );
  protected readonly skippedRestore = computed(
    () => (this.rawDetail()?.changed_objects.length ?? 0) - this.restorable().length,
  );

  /** `?group=<id>`, bound by the router. Overview and the notification drawer
   *  deep-link into this page that way. */
  readonly group = input<string>();
  readonly operation = input<string>();
  readonly section = input<ChangeSection>();
  protected readonly sections: { key: ChangeSection; label: string }[] = [
    { key: 'outcome', label: 'Outcome' },
    { key: 'configuration', label: 'Configuration' },
    { key: 'timeline', label: 'Timeline' },
    { key: 'evidence', label: 'Technical evidence' },
  ];
  protected readonly activeSection = computed<ChangeSection>(() =>
    this.sections.some((s) => s.key === this.section()) ? this.section()! : 'outcome',
  );

  /** `?actor=<name>`, bound by the router. Global search links an actor here so
   *  the page opens narrowed to that person's change groups. */
  readonly actor = input<string>();

  protected readonly severity = signal<SeverityFilter>('any');
  /**
   * Whether Guardian records anything for this feed at all. With Guardian off
   * every row carries `null`, and printing "no investigation recorded" against
   * all of them would be noise; where some row does carry one, a row without
   * one is worth saying.
   */
  protected readonly hasGuardian = computed(
    () =>
      !this.time.isHistorical() &&
      (!!this.rawDetail()?.guardian || this.changeGroups.items().some((group) => !!group.guardian)),
  );

  /** Derived rather than mirrored: the URL is the only thing that sets an
   *  actor, and a mirroring effect would fetch once more after correcting
   *  itself on the first pass. */
  protected readonly actorFilter = computed(() => this.actor() ?? null);
  private readonly allSeverities: { value: SeverityFilter; label: string }[] = [
    { value: 'any', label: 'All changes' },
    { value: 'critical', label: 'Critical' },
    { value: 'warning', label: 'Warning' },
    { value: 'none', label: 'No impact observed' },
  ];

  /**
   * Impact is today's verdict on a change, held in one mutable column. A past
   * window cannot be filtered by it — the rows would be the ones judged
   * critical now, offered as the critical changes of then — so the chips are
   * not offered there, and the API refuses the combination outright.
   */
  protected readonly severities = computed(() =>
    this.time.isHistorical() ? this.allSeverities.slice(0, 1) : this.allSeverities,
  );

  /** The impact filter in force: a chip picked at "now" is kept, but narrows no past window. */
  protected readonly appliedSeverity = computed<SeverityFilter>(() =>
    this.time.isHistorical() ? 'any' : this.severity(),
  );

  protected readonly selectedId = signal<string | null>(null);
  private selectedFor: string | null = null;
  private detailRequest = 0;
  protected readonly detailPending = signal(false);

  /** Ties each row's `aria-controls` to the inline detail panel. */
  protected readonly panelId = 'change-group-detail';

  protected readonly columns = ['TIME', 'CHANGE GROUP', 'ACTOR', 'OBJECTS', 'DEVICES', 'IMPACT'];

  protected readonly days = computed<ChangeDay[]>(() => {
    const groups = this.changeGroups.items();
    const days: ChangeDay[] = [];
    for (const group of groups) {
      const occurred = new Date(group.occurred_at);
      const day = formatDay(occurred);
      const current = days[days.length - 1];
      const bucket = current && current.key === day ? current : addDay(days, day);
      bucket.rows.push(toRow(group, occurred));
    }
    // The separator counts what the day actually holds, so a severity filter
    // narrows the counts rather than promising rows that are not there.
    return days.map((day) => ({ ...day, label: dayLabel(day) }));
  });

  protected readonly subtitle = computed(() => {
    const shown = this.changeGroups.items().length;
    if (shown === 0) {
      return 'No matching change groups';
    }
    const filtered = this.filtered() ? ' · filtered' : '';
    return `${formatCount(shown)} change group${shown === 1 ? '' : 's'}${filtered}`;
  });

  protected readonly footer = computed(() => {
    const shown = this.changeGroups.items().length;
    if (shown === 0) {
      return this.filtered()
        ? 'Clear the filters to see all groups'
        : 'No change groups in this window';
    }
    return `${this.skip() + 1}–${this.skip() + shown} of ${formatCount(this.changeGroups.total())} changes`;
  });

  /** True while the list is narrowed, so an empty table means nothing matched
   *  rather than nothing happened. */
  protected readonly filtered = computed(
    () => this.appliedSeverity() !== 'any' || this.actorFilter() !== null || !!this.query(),
  );

  /** The organization has nothing in the window, rather than nothing matching. */
  protected readonly isEmpty = computed(
    () => this.changeGroups.items().length === 0 && !this.filtered(),
  );

  protected readonly emptyTitle = computed(() => {
    const organization = this.organizations.selected();
    return organization && organization.status !== 'verified'
      ? `No snapshot yet for ${organization.name}`
      : 'No changes in this window';
  });

  protected readonly emptyBody = computed(() =>
    this.organizations.selected()?.status !== 'verified'
      ? 'This organization is onboarded but its service token has not been verified and no initial snapshot has run. Configuration history and change monitoring begin after the first snapshot completes.'
      : 'Nothing was changed in the selected range. Widen the window or clear the impact filter.',
  );

  /** The inline detail panel, once its fetch has landed for the selected row. */
  protected readonly panel = computed(() => {
    const detail = this.changeGroups.detail();
    const selected = this.selectedId();
    if (!detail || !selected || detail.id !== selected) {
      return null;
    }
    const occurred = new Date(detail.occurred_at);
    return {
      id: detail.id,
      guardian: detail.guardian ?? null,
      tone: toneOf(detail.impact_severity),
      level: detail.impact_known === false ? 'Impact not shown' : detail.impact_label,
      title: detail.title,
      audit: `AUDIT ${shortAudit(detail.audit_id)}`,
      byline: `${detail.actor ?? 'Unattributed'} · ${formatDate(occurred)} ${formatTime(occurred)} · delivered by ${detail.source}`,
      // A past view withholds the assessment, which is not the same as the
      // change never having had one: saying so would describe a group that
      // does have a live assessment falsely.
      assessment:
        detail.impact_known === false
          ? 'The assessment of this change is not shown at a past instant.'
          : (detail.deterministic_assessment ??
            'No deterministic assessment was recorded for this change group.'),
      evidence: detail.evidence.map((item, index) => ({
        key: index,
        label: item.label,
      })),
    };
  });

  constructor() {
    // The index is filtered server-side, so the severity chips and the shell's
    // range and as-of are all inputs to the same fetch.
    effect((cleanup) => {
      const organizationId = this.organizations.selected()?.id;
      const range = this.time.range();
      // A historical window carries no severity filter; the API refuses one.
      const severity = this.appliedSeverity();
      const actor = this.actorFilter();
      const asOf = this.time.asOf();
      const q = this.query();
      const scope = JSON.stringify([organizationId, range, actor, asOf]);
      if (scope !== this.pagingScope) {
        this.pagingScope = scope;
        this.skip.set(0);
      }
      const skip = this.skip();
      this.reload();
      const controller = new AbortController();
      cleanup(() => controller.abort());
      if (!organizationId) {
        return;
      }
      this.listError.set(false);
      void untracked(() =>
        this.ui
          .track(
            'Loading changes',
            () =>
              this.changeGroups.list(organizationId, {
                range,
                severity,
                actor: actor ?? undefined,
                asOf,
                limit: PAGE_SIZE,
                q,
                skip,
              }),
            controller.signal,
          )
          .then((result) => {
            if (!controller.signal.aborted) this.listError.set(!result);
          }),
      );
    });

    // A deep link arrives as a query parameter; selecting a row writes one back.
    effect(() => {
      const fromUrl = this.group() ?? null;
      const operation = this.operation() ?? '';
      untracked(() => {
        this.selectGroup(fromUrl);
        this.restoreOperation.set(operation);
      });
    });

    effect(() => {
      const organizationId = this.organizations.selected()?.id;
      const id = this.selectedId();
      // The instant is an input to the detail as much as to the table: an
      // expanded panel read at "now" would otherwise keep showing a live
      // assessment, its evidence and its devices after travelling back.
      this.time.asOf();
      if (!organizationId || !id) {
        untracked(() => this.changeGroups.clearDetail());
        return;
      }
      if (this.selectedFor === null) {
        // A link opened cold arrives before any organization is established.
        // It was written under the organization that then loads, so that
        // organization adopts it rather than discarding it as foreign.
        this.selectedFor = organizationId;
      }
      if (this.selectedFor !== organizationId) {
        // The group was selected under another organization; here it names
        // nothing. It goes, and the parameter with it, before a read for it
        // can fail or the detail cached for it can show.
        untracked(() => {
          this.selectedId.set(null);
          this.restoreOperation.set('');
          this.changeGroups.clearDetail();
          void this.router.navigate([], {
            queryParams: { group: null, operation: null },
            queryParamsHandling: 'merge',
            replaceUrl: true,
          });
        });
        return;
      }
      void untracked(() => this.loadDetail(organizationId, id));
    });
  }

  /** Record which organization a selection was made under, so a switch can tell it is foreign. */
  private selectGroup(id: string | null): void {
    if (id !== this.selectedId()) {
      this.selectionRevision++;
      this.restoreOperation.set('');
      this.restoreError.set('');
      this.restoreBusy.set(false);
    }
    this.selectedFor = this.organizations.selected()?.id ?? null;
    this.selectedId.set(id);
  }

  protected async select(id: string): Promise<void> {
    const next = this.selectedId() === id ? null : id;
    this.focusDetail = next !== null;
    this.selectGroup(next);
    await this.router.navigate([], {
      queryParams: { group: next, operation: null, section: null },
      queryParamsHandling: 'merge',
      replaceUrl: true,
    });
    if (!next)
      afterNextRender(
        () => {
          this.element.nativeElement
            .querySelector<HTMLElement>(`.row--group[data-group-id="${CSS.escape(id)}"]`)
            ?.focus();
        },
        { injector: this.injector },
      );
  }

  protected async clearActor(): Promise<void> {
    await this.router.navigate([], {
      queryParams: { actor: null },
      queryParamsHandling: 'merge',
      replaceUrl: true,
    });
  }

  protected async close(): Promise<void> {
    const selected = this.selectedId();
    if (selected) {
      await this.select(selected);
    }
  }

  /** Deep-link one changed object into History's A/B version comparison.
   *
   *  History names its two slots `a` and `b`, with A the earlier side, so the
   *  before and after versions have to be sent under those names to land
   *  already selected rather than on an unfiltered page.
   */
  protected async compare(object: ChangedObject): Promise<void> {
    await this.router.navigate(['/history'], {
      queryParams: {
        object: object.logical_object_id,
        a: object.before_version_id,
        b: object.after_version_id,
        fromChange: this.selectedId(),
      },
    });
  }

  protected async planRestore(id: string): Promise<void> {
    const org = this.organizations.selected()?.id;
    const versions = [...new Set(this.restorable().map((o) => o.before_version_id!))];
    if (!org || !versions.length || !this.canRestore() || this.restoreBusy()) return;
    if (versions.length > MAX_PLAN_VERSIONS) {
      // The plan request refuses a longer list, so trying again cannot help,
      // and a rollback that quietly restored only part of the change would
      // read as the whole of it.
      this.restoreError.set(
        `One rollback plan restores at most ${MAX_PLAN_VERSIONS} objects, and this change has ` +
          `${versions.length} to restore. Restore them in parts from the Restore center.`,
      );
      return;
    }
    this.restoreBusy.set(true);
    const revision = this.selectionRevision;
    this.restoreError.set('');
    try {
      const plan = await this.restores.createPlan(org, versions, 'non_destructive', true);
      if (
        revision === this.selectionRevision &&
        this.selectedId() === id &&
        this.organizations.selected()?.id === org
      )
        this.updateOperation(plan.id);
    } catch {
      if (
        revision === this.selectionRevision &&
        this.selectedId() === id &&
        this.organizations.selected()?.id === org
      )
        this.restoreError.set('The rollback plan could not be built. Try again.');
    } finally {
      if (
        revision === this.selectionRevision &&
        this.selectedId() === id &&
        this.organizations.selected()?.id === org
      )
        this.restoreBusy.set(false);
    }
  }

  protected updateOperation(id: string | null): void {
    this.restoreOperation.set(id ?? '');
    void this.router.navigate([], {
      queryParams: { operation: id },
      queryParamsHandling: 'merge',
      replaceUrl: true,
    });
  }
  protected closeRollback(): void {
    this.updateOperation(null);
  }

  protected showSection(section: ChangeSection): void {
    void this.router.navigate([], {
      queryParams: { section: section === 'outcome' ? null : section },
      queryParamsHandling: 'merge',
      replaceUrl: true,
    });
  }

  protected onSectionKey(event: KeyboardEvent, index: number): void {
    if (!['ArrowRight', 'ArrowLeft', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const next =
      event.key === 'Home'
        ? 0
        : event.key === 'End'
          ? this.sections.length - 1
          : (index + (event.key === 'ArrowRight' ? 1 : -1) + this.sections.length) %
            this.sections.length;
    this.showSection(this.sections[next].key);
    afterNextRender(
      () =>
        this.element.nativeElement
          .querySelector<HTMLElement>(`#change-tab-${this.sections[next].key}`)
          ?.focus(),
      { injector: this.injector },
    );
  }

  protected search(value: string): void {
    this.skip.set(0);
    this.query.set(value.trim());
  }
  protected filterSeverity(value: SeverityFilter): void {
    this.skip.set(0);
    this.severity.set(value);
  }
  protected retryDetail(): void {
    const org = this.organizations.selected()?.id,
      id = this.selectedId();
    if (org && id) void this.loadDetail(org, id);
  }

  protected jump(selector: string): void {
    const section = this.element.nativeElement.querySelector<HTMLElement>(selector);
    section?.scrollIntoView({ block: 'start' });
    const heading = section?.querySelector<HTMLElement>('h3');
    heading?.setAttribute('tabindex', '-1');
    heading?.focus({ preventScroll: true });
  }

  /** A restore is a write, so it is hidden for viewers and in historical mode. */
  protected canRestore(): boolean {
    return this.auth.can('operator') && !this.time.isHistorical();
  }

  /**
   * The detail fetch deliberately avoids `ui.track`: the shell hides the page
   * while it is loading, which would take away the row the user just clicked.
   * Failures stay in the panel with an explicit retry.
   */
  private async loadDetail(organizationId: string, id: string): Promise<void> {
    const request = ++this.detailRequest;
    // The panel shows what this read returns or nothing. Leaving the previous
    // detail up would keep a live assessment on screen while a historical read
    // is in flight — and for good, if it comes back 404 because the change had
    // not happened at the instant being viewed.
    this.changeGroups.clearDetail();
    this.detailError.set(false);
    this.detailPending.set(true);
    try {
      await this.changeGroups.load(organizationId, id, this.time.asOf());
      if (request === this.detailRequest && this.focusDetail) {
        this.focusDetail = false;
        afterNextRender(
          () => this.element.nativeElement.querySelector<HTMLElement>('.panel-title')?.focus(),
          { injector: this.injector },
        );
      }
    } catch {
      // A read for a row the user has already moved off must not clear the
      // spinner belonging to the current one, nor raise a banner about it.
      if (request === this.detailRequest) {
        this.detailError.set(true);
      }
    } finally {
      if (request === this.detailRequest) {
        this.detailPending.set(false);
      }
    }
  }
}

function addDay(days: ChangeDay[], key: string): ChangeDay {
  const day: ChangeDay = { key, label: key, rows: [] };
  days.push(day);
  return day;
}

function dayLabel(day: ChangeDay): string {
  const critical = day.rows.filter((row) => row.group.impact_severity === 'critical').length;
  const groups = `${day.rows.length} GROUP${day.rows.length === 1 ? '' : 'S'}`;
  return `${day.key} · ${groups}${critical > 0 ? ` · ${critical} CRITICAL` : ''}`;
}

function toRow(group: ChangeGroupSummary, occurred: Date): GroupRow {
  return {
    id: group.id,
    group,
    time: formatTime(occurred),
    title: group.title,
    actor: group.actor ?? 'Unattributed',
    objects: formatCount(group.object_count),
    devices: group.devices_label,
    impact: group.impact_known === false ? 'IMPACT NOT SHOWN' : group.impact_label,
    recovery: RECOVERY_LABEL[group.recovery_state],
    tone: toneOf(group.impact_severity),
  };
}

function shortAudit(auditId: string): string {
  const compact = auditId.replace(/-/g, '').toUpperCase();
  return compact.length > 7 ? `${compact.slice(0, 4)}…${compact.slice(-3)}` : compact;
}
