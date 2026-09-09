import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { Router } from '@angular/router';

import { AuthService } from '../../core/auth.service';
import { ChangedObject, ChangeGroupSummary, RecoveryState } from '../../core/change-group.model';
import { ChangeGroupService, SeverityFilter } from '../../core/change-group.service';
import { formatCount, formatDate, formatDay, formatTime } from '../../core/format';
import { OrganizationContextService } from '../../core/organization-context.service';
import { TimeContextService } from '../../core/time-context.service';
import { Tone, toneInk, toneOf } from '../../core/tone';
import { UiStateService } from '../../core/ui-state.service';

/** The table asks for one large page; the design has no paging control. */
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
  meta: string;
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
  imports: [],
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

  /** `?group=<id>`, bound by the router. Overview and the notification drawer
   *  deep-link into this page that way. */
  readonly group = input<string>();

  /** `?actor=<name>`, bound by the router. Global search links an actor here so
   *  the page opens narrowed to that person's change groups. */
  readonly actor = input<string>();

  protected readonly severity = signal<SeverityFilter>('any');

  /** Derived rather than mirrored: the URL is the only thing that sets an
   *  actor, and a mirroring effect would fetch once more after correcting
   *  itself on the first pass. */
  protected readonly actorFilter = computed(() => this.actor() ?? null);
  private readonly allSeverities: { value: SeverityFilter; label: string }[] = [
    { value: 'any', label: 'Impact: any' },
    { value: 'critical', label: 'Critical' },
    { value: 'warning', label: 'Warning' },
    { value: 'none', label: 'No impact' },
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
      return this.filtered() ? 'Clear the filters to see all groups' : 'No change groups in this window';
    }
    return `Showing ${formatCount(shown)} of ${formatCount(this.changeGroups.total())} · click a row for evidence`;
  });

  /** True while the list is narrowed, so an empty table means nothing matched
   *  rather than nothing happened. */
  protected readonly filtered = computed(
    () => this.severity() !== 'any' || this.actorFilter() !== null,
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
      tone: toneOf(detail.impact_severity),
      level: detail.impact_label,
      title: detail.title,
      audit: `AUDIT ${shortAudit(detail.audit_id)}`,
      byline: `${detail.actor ?? 'Unattributed'} · ${formatDate(occurred)} ${formatTime(occurred)} · delivered by ${detail.source}`,
      objectCount: formatCount(detail.object_count),
      objects: detail.changed_objects.map((object, index) => ({
        key: `${object.logical_object_id}-${index}`,
        object,
        event: object.event.toUpperCase(),
        name: object.object_name,
        kind: `${object.object_type.toUpperCase()} · ${object.scope.toUpperCase()}`,
        versions: versionRange(object),
        fields: fieldSummary(object),
      })),
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
        ink: toneInk(toneOf(item.severity)),
      })),
      sessionId: detail.monitoring_session_ids[0] ?? null,
    };
  });

  constructor() {
    // The index is filtered server-side, so the severity chips and the shell's
    // range and as-of are all inputs to the same fetch.
    effect(() => {
      const organizationId = this.organizations.selected()?.id;
      const range = this.time.range();
      // A historical window carries no severity filter; the API refuses one.
      const severity = this.time.isHistorical() ? 'any' : this.severity();
      const actor = this.actorFilter();
      const asOf = this.time.asOf();
      if (!organizationId) {
        return;
      }
      void untracked(() =>
        this.ui.track('Loading changes', () =>
          this.changeGroups.list(organizationId, {
            range,
            severity,
            actor: actor ?? undefined,
            asOf,
            limit: PAGE_SIZE,
          }),
        ),
      );
    });

    // A deep link arrives as a query parameter; selecting a row writes one back.
    effect(() => {
      const fromUrl = this.group() ?? null;
      untracked(() => this.selectGroup(fromUrl));
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
          this.changeGroups.clearDetail();
          void this.router.navigate([], {
            queryParams: { group: null },
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
    this.selectedFor = this.organizations.selected()?.id ?? null;
    this.selectedId.set(id);
  }

  protected async select(id: string): Promise<void> {
    const next = this.selectedId() === id ? null : id;
    this.selectGroup(next);
    await this.router.navigate([], {
      queryParams: { group: next },
      queryParamsHandling: 'merge',
      replaceUrl: true,
    });
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
      },
    });
  }

  protected async openImpact(sessionId: string): Promise<void> {
    await this.router.navigate(['/impact'], { queryParams: { session: sessionId } });
  }

  protected async planRestore(id: string): Promise<void> {
    await this.router.navigate(['/restore'], { queryParams: { changeGroup: id } });
  }

  /** A restore is a write, so it is hidden for viewers and in historical mode. */
  protected canRestore(): boolean {
    return this.auth.can('operator') && !this.time.isHistorical();
  }

  /**
   * The detail fetch deliberately avoids `ui.track`: the shell hides the page
   * while it is loading, which would take away the row the user just clicked.
   * Failures still surface in the shell's error banner.
   */
  private async loadDetail(organizationId: string, id: string): Promise<void> {
    const request = ++this.detailRequest;
    // The panel shows what this read returns or nothing. Leaving the previous
    // detail up would keep a live assessment on screen while a historical read
    // is in flight — and for good, if it comes back 404 because the change had
    // not happened at the instant being viewed.
    this.changeGroups.clearDetail();
    this.detailPending.set(true);
    try {
      await this.changeGroups.load(organizationId, id, this.time.asOf());
    } catch (cause) {
      // A read for a row the user has already moved off must not clear the
      // spinner belonging to the current one, nor raise a banner about it.
      if (request === this.detailRequest) {
        this.ui.fail(cause, 'Loading change group');
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
    meta: `AUDIT ${shortAudit(group.audit_id)} · ${group.source.toUpperCase()}`,
    actor: group.actor ?? 'Unattributed',
    objects: formatCount(group.object_count),
    devices: group.devices_label,
    impact: group.impact_known === false ? 'IMPACT NOT SHOWN' : group.impact_label,
    recovery: RECOVERY_LABEL[group.recovery_state],
    tone: toneOf(group.impact_severity),
  };
}

function versionRange(object: ChangedObject): string {
  if (object.before_version === null) {
    return object.after_version === null ? '' : `v${object.after_version}`;
  }
  return object.after_version === null
    ? `v${object.before_version} → deleted`
    : `v${object.before_version} → v${object.after_version}`;
}

/**
 * The design prints the changed fields inline. A template rewrite can touch
 * dozens, so long lists collapse to a count plus the first few names.
 */
function fieldSummary(object: ChangedObject): string {
  const fields = object.changed_fields;
  if (fields.length === 0) {
    return 'No field-level differences recorded';
  }
  if (fields.length <= 6) {
    return fields.join(', ');
  }
  return `${fields.length} fields · ${fields.slice(0, 3).join(', ')}…`;
}

function shortAudit(auditId: string): string {
  const compact = auditId.replace(/-/g, '').toUpperCase();
  return compact.length > 7 ? `${compact.slice(0, 4)}…${compact.slice(-3)}` : compact;
}
