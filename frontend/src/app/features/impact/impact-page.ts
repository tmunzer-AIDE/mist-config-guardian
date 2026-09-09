import { DeviceEvidence } from './device-evidence';
import {
  ChangeDetectionStrategy,
  Component,
  computed,
  effect,
  inject,
  input,
  signal,
  untracked,
} from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';

import { AuthService } from '../../core/auth.service';
import { formatCount, formatInstant, formatTime } from '../../core/format';
import { OrganizationContextService } from '../../core/organization-context.service';
import { TimeContextService } from '../../core/time-context.service';
import { Tone, toneInk, toneOf } from '../../core/tone';
import { UiStateService } from '../../core/ui-state.service';
import {
  ImpactSeverity,
  MetricDelta,
  MonitoringSession,
  STATUS_FILTERS,
  SeverityFilter,
  SleBar,
  StatusFilter,
  baselineConfidence,
  filterLabel,
  filterSessions,
  hasTrustedBaseline,
  metricDeltas,
  metricLabel,
  primaryMetric,
  readAiAssessment,
  sampleCount,
  severityLabel,
  shortAudit,
  sleSeries,
  statusLabel,
} from './monitoring.model';
import { MonitoringService } from './monitoring.service';
import { SleChart } from './sle-chart';
import { ConfigurationTimeline } from './configuration-timeline';

interface SessionRow {
  id: string;
  device: string;
  model: string;
  mac: string;
  site: string;
  at: string;
  status: string;
  severity: string;
  tone: Tone;
}

interface MetricRow extends MetricDelta {
  deltaInk: string;
  barInk: string;
  baselineLabel: string;
  latestLabel: string;
}

interface IncidentRow {
  key: string;
  tag: string;
  tone: Tone;
  label: string;
}

/** The rich no-evidence panel: one variant per way a window can carry no data. */
interface StatePanel {
  tone: Tone;
  tag: string;
  title: string;
  body: string;
  metaA: string;
  metaAValue: string;
  metaB: string;
  metaBValue: string;
  next: string;
}

const SEVERITIES: ImpactSeverity[] = ['none', 'info', 'warning', 'critical'];

/**
 * Impact monitoring: the session list and the selected session's evidence.
 *
 * Everything deterministic — the SLE series, the baseline comparison, the
 * incidents — renders from the session document alone. The AI assessment is
 * additive: its absence, or its failure, never withholds the evidence.
 */
@Component({
  selector: 'app-impact-page',
  imports: [DeviceEvidence, SleChart, ConfigurationTimeline],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './impact-page.html',
  styleUrl: './impact-page.scss',
})
export class ImpactPage {
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly ui = inject(UiStateService);
  private readonly organizations = inject(OrganizationContextService);
  private readonly monitoring = inject(MonitoringService);
  private readonly auth = inject(AuthService);
  protected readonly time = inject(TimeContextService);

  /** `?session=` — bound by the router's component input binding. */
  readonly session = input('');
  /** `?severity=` — set when another page deep-links a narrowed list. */
  readonly severity = input('');

  protected readonly filters = STATUS_FILTERS;
  protected readonly statusFilter = signal<StatusFilter>('all');
  private readonly picked = signal<string | null>(null);
  private readonly pickedAudit = signal<string | null>(null);
  /** The organization the deep link and its resolved session belong to. */
  private linkFor: string | null = null;
  /** A linked identifier from another organization, ignored until the router replaces it. */
  private foreignLink: string | null = null;

  protected readonly severityFilter = computed<SeverityFilter>(() => {
    const requested = this.severity();
    return SEVERITIES.find((value) => value === requested) ?? 'any';
  });

  protected readonly total = computed(() => this.monitoring.total());
  protected readonly hasMore = computed(() => this.monitoring.sessions().length < this.total());
  protected readonly loadingMore = signal(false);
  protected async loadMore(): Promise<void> {
    const org = this.organizations.selected()?.id;
    if (!org || this.loadingMore()) return;
    this.loadingMore.set(true);
    try {
      await this.monitoring.loadMore(org, {
        status:
          this.statusFilter() === 'all'
            ? undefined
            : (this.statusFilter() as Exclude<StatusFilter, 'all'>),
        severity:
          this.severityFilter() === 'any' ? undefined : (this.severityFilter() as ImpactSeverity),
      });
    } catch (cause) {
      this.ui.fail(cause, 'Loading more monitoring windows');
    } finally {
      this.loadingMore.set(false);
    }
  }

  /** Sessions after both filters, in the order the API returned them. */
  protected readonly visible = computed(() =>
    filterSessions(this.monitoring.sessions(), this.statusFilter(), this.severityFilter()),
  );

  protected readonly rows = computed<SessionRow[]>(() => this.visible().map((item) => toRow(item)));
  protected readonly groups = computed(() => {
    const groups = new Map<
      string,
      { key: string; title: string; audit: string; rows: SessionRow[] }
    >();
    for (const session of this.visible()) {
      for (const audit of session.audit_ids.length
        ? session.audit_ids
        : ['uncorrelated:' + session.id]) {
        const ref = session.change_groups?.find((change) => change.audit_id === audit);
        const group = groups.get(audit) ?? {
          key: audit,
          title:
            ref?.title ??
            (session.audit_ids.length ? 'Configuration change' : 'Uncorrelated device change'),
          audit: session.audit_ids.length ? shortAudit(audit) : 'No audit ID supplied',
          rows: [],
        };
        group.rows.push(toRow(session));
        groups.set(audit, group);
      }
    }
    return [...groups.values()].map((group) => ({
      ...group,
      critical: group.rows.filter((row) => row.severity === 'CRITICAL').length,
      warning: group.rows.filter((row) => row.severity === 'WARNING').length,
    }));
  });

  protected readonly selected = computed<MonitoringSession | null>(() => {
    const wanted = this.picked() ?? this.session();
    if (wanted) {
      // Resolved against the whole loaded page, not the filtered rows: narrowing
      // the list hides the row but must not blank the evidence beside it.
      const loaded = this.monitoring.sessions().find((item) => item.id === wanted);
      if (loaded) {
        return loaded;
      }
      // A deep link can name a session the server-side filter excluded; the
      // service fetches that one by ID so the link still lands on its evidence.
      const resolved = this.monitoring.resolved();
      if (resolved && resolved.id === wanted) {
        return resolved;
      }
    }
    return this.visible()[0] ?? null;
  });

  protected readonly selectedId = computed(() => this.selected()?.id ?? null);

  protected readonly detail = computed(() => {
    const session = this.selected();
    if (!session) {
      return null;
    }
    return {
      tone: toneOf(session.impact_severity),
      severity: severityLabel(session.impact_severity),
      device: session.device_name || session.device_mac,
      meta: `${session.device_mac} · ${session.device_type} · ${session.site_id}`,
      status: statusLabel(session.status),
      summary: session.deterministic_summary ?? '',
      window: windowLabel(session),
      samples: formatCount(sampleCount(session)),
      audit: auditLabel(session),
      warnings: session.warnings,
    };
  });

  protected readonly metrics = computed<MetricRow[]>(() => {
    const session = this.selected();
    if (!session) {
      return [];
    }
    return metricDeltas(session).map((metric) => ({
      ...metric,
      deltaInk: toneInk(metric.delta === 0 ? 'none' : metric.delta < 0 ? 'crit' : 'ok'),
      barInk: toneInk(metric.tone),
      baselineLabel: `BASELINE ${Math.round(metric.baseline)}%`,
      latestLabel: `LATEST ${Math.round(metric.latest)}%`,
    }));
  });

  protected readonly chart = computed(() => {
    const session = this.selected();
    if (!session || session.observations.length === 0) {
      return null;
    }
    const metric = primaryMetric(session);
    if (!metric) {
      return null;
    }
    const bars = sleSeries(session, metric);
    if (bars.length === 0) {
      return null;
    }
    return {
      bars,
      tone: toneOf(session.impact_severity),
      metric: metricLabel(metric),
      axis: axisFor(bars, session),
      labels: bars.map((bar) => formatTime(new Date(bar.at))),
    };
  });

  protected readonly incidents = computed<IncidentRow[]>(() =>
    (this.selected()?.incidents ?? []).map((incident) => ({
      key: `${incident.event_type}·${incident.occurred_at}`,
      tag: incident.resolved ? 'RESOLVED' : 'OPEN',
      tone: incident.resolved ? 'ok' : toneOf(incident.severity),
      label: incidentLabel(
        incident.event_type,
        incident.occurred_at,
        incident.resolved,
        incident.resolved_at,
      ),
    })),
  );

  protected readonly ai = computed(() => readAiAssessment(this.selected()?.ai_assessment ?? null));
  protected readonly aiError = computed(() => this.selected()?.ai_assessment_error ?? null);

  /**
   * The verdict line for a window that produced evidence and found nothing.
   *
   * "No impact detected" is a claim about the network; it is only honest when
   * the baseline was solid, so a thin baseline reads as insufficient evidence.
   */
  protected readonly verdict = computed(() => {
    const session = this.selected();
    if (!session || this.metrics().length === 0 || session.impact_severity !== 'none') {
      return null;
    }
    const trusted = hasTrustedBaseline(session);
    const confidence = baselineConfidence(session);
    return {
      tone: (trusted ? 'ok' : 'none') as Tone,
      tag: trusted ? 'NO IMPACT DETECTED' : 'INSUFFICIENT EVIDENCE',
      detail: trusted
        ? `Baseline confidence ${confidence} — every monitored metric stayed inside the noise band.`
        : `Baseline confidence ${confidence} — the comparison is too thin to rule impact in or out.`,
    };
  });

  /**
   * The design's `sessHasData`: a real baseline-versus-latest comparison exists.
   *
   * It gates the summary paragraph and the action panel, because a session
   * without a comparison prints its summary — and its one action — inside the
   * state panel instead, and printing both would say the same thing twice.
   */
  protected readonly hasData = computed(() => this.metrics().length > 0);

  protected readonly collectionErrors = computed(() => {
    const session = this.selected();
    if (!session) return [];
    const latest = session.observations.at(-1);
    return [
      ...(session.baseline?.errors ?? []).map((error) => 'Baseline: ' + error),
      ...(latest?.errors ?? []).map((error) => 'Latest: ' + error),
    ];
  });

  protected readonly noTrafficMetrics = computed(() => {
    const session = this.selected();
    return [
      ...new Set([
        ...(session?.baseline?.no_data ?? []),
        ...(session?.observations.at(-1)?.no_data ?? []),
      ]),
    ].map(metricLabel);
  });

  /** Rich no-evidence panel, standing in for the chart and the comparison. */
  protected readonly state = computed<StatePanel | null>(() => {
    const session = this.selected();
    if (!session || this.hasData()) {
      return null;
    }
    return statePanel(session);
  });

  /** Right-hand column: the optional assessment and the actions. */
  protected readonly showAside = computed(
    () => this.hasData() || this.ai() !== null || this.aiError() !== null,
  );

  /** The two-column body renders only when one of its panels has something. */
  protected readonly showBody = computed(
    () => this.hasData() || this.incidents().length > 0 || this.showAside(),
  );

  protected readonly changeGroupId = computed(() => {
    const session = this.selected();
    const picked = session?.change_groups?.find((group) => group.audit_id === this.pickedAudit());
    if (picked) return picked.id;
    // A shared window opened by URL has no exclusive originating change.
    if ((session?.audit_ids.length ?? 0) > 1) return null;
    return session?.change_group_id ?? null;
  });

  /**
   * Monitoring is live evidence with no historical projection.
   *
   * Every session, incident, sample and assessment on this page describes what
   * monitoring knows now. There is no versioned record to reconstruct any of
   * it at a past instant, so rather than present today's evidence under a
   * historical banner the page says it has nothing to show there.
   */
  protected readonly historical = computed(() => this.time.isHistorical());

  constructor() {
    effect((onCleanup) => {
      const org = this.organizations.selected()?.id;
      const selected = this.selectedId();
      if (!org || !selected || this.historical()) return;
      let busy = false;
      const timer = setInterval(async () => {
        if (busy) return;
        busy = true;
        try {
          await this.monitoring.loadSession(org, selected);
        } finally {
          busy = false;
        }
      }, 30_000);
      onCleanup(() => clearInterval(timer));
    });
    effect(() => {
      const organizationId = this.organizations.selected()?.id;
      this.organizations.revision();
      const status = this.statusFilter();
      const severity = this.severityFilter();
      if (this.time.isHistorical()) {
        untracked(() => this.monitoring.reset());
        return;
      }
      if (!organizationId) {
        return;
      }
      void untracked(() =>
        this.ui.track('Loading monitoring sessions', () =>
          this.monitoring.load(organizationId, {
            status: status === 'all' ? undefined : status,
            severity: severity === 'any' ? undefined : severity,
          }),
        ),
      );
    });

    // A row pick and the bound `session` parameter both name a selection; the
    // one that changed most recently wins. A pick writes itself to the URL, so
    // the parameter arriving as the pick is not news; a parameter arriving
    // from elsewhere — a notification, a search result — supersedes the pick,
    // rather than being overridden by it and rewritten back.
    effect(() => {
      const linked = this.session();
      untracked(() => {
        if (this.picked() !== null && this.picked() !== linked) {
          this.picked.set(null);
        }
      });
    });

    // Resolve a deep link that points outside the loaded page. The link, and
    // the session it resolved to, belong to the organization it was opened under.
    effect(() => {
      const organizationId = this.organizations.selected()?.id;
      const linked = this.session();
      const picked = this.picked();
      if (!organizationId) {
        return;
      }
      if (this.linkFor === null) {
        // A link opened cold arrives before any organization is established;
        // the one that then loads is the one it was written under.
        this.linkFor = organizationId;
      }
      if (this.linkFor !== organizationId) {
        // Under another organization the identifier names nothing. The session
        // resolved for it, the rows read with it, the pick and the parameter go
        // now, before a read for it can be issued, and the identifier is
        // ignored until the router has replaced it.
        this.linkFor = organizationId;
        this.foreignLink = linked || null;
        untracked(() => {
          this.monitoring.forgetOrganization();
          this.picked.set(null);
          if (linked) {
            void this.router.navigate([], {
              relativeTo: this.route,
              queryParams: { session: null },
              queryParamsHandling: 'merge',
              replaceUrl: true,
            });
          }
        });
        return;
      }
      const wanted = picked ?? (linked === this.foreignLink ? '' : linked);
      const known = this.monitoring.sessions().some((item) => item.id === wanted);
      if (!wanted || known) {
        return;
      }
      if (this.time.isHistorical()) {
        // The list is empty here by design, so a link to a session outside it
        // would resolve every time — and the monitoring endpoint answers with
        // the session as it stands now, which is the whole thing this page
        // stops showing at a past instant.
        return;
      }
      if (untracked(() => this.monitoring.resolved()?.id) === wanted) {
        return;
      }
      void untracked(() => this.monitoring.loadSession(organizationId, wanted));
    });

    // Reflect the selection back onto the URL so the view is linkable.
    effect(() => {
      const current = this.selectedId();
      if (!current || current === this.session()) {
        return;
      }
      void untracked(() =>
        this.router.navigate([], {
          relativeTo: this.route,
          queryParams: { session: current },
          queryParamsHandling: 'merge',
          replaceUrl: true,
        }),
      );
    });
  }

  protected filterLabel(filter: StatusFilter): string {
    return filterLabel(filter);
  }

  protected setFilter(filter: StatusFilter): void {
    this.statusFilter.set(filter);
  }

  protected select(id: string, audit: string | null = null): void {
    this.pickedAudit.set(audit);
    this.picked.set(id);
  }

  /** Up and down arrows move the selection and carry focus with it. */
  protected onListKey(event: KeyboardEvent): void {
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') {
      return;
    }
    const list = event.currentTarget as HTMLElement;
    const rows = [...list.querySelectorAll<HTMLButtonElement>('.row')].filter(
      (row) => row.closest<HTMLDetailsElement>('details')?.open !== false,
    );
    if (!rows.length) return;
    event.preventDefault();
    const focused = rows.findIndex((row) => row === event.target);
    const current =
      focused >= 0
        ? focused
        : rows.findIndex((row) => row.dataset['sessionId'] === this.selectedId());
    const step = event.key === 'ArrowDown' ? 1 : -1;
    const next = Math.min(rows.length - 1, Math.max(0, (current < 0 ? 0 : current) + step));
    const id = rows[next].dataset['sessionId'];
    if (id) this.select(id, rows[next].dataset['auditId'] ?? null);
    rows[next].focus();
  }

  /** Restores are writes: never offered in historical mode or below operator. */
  protected canRestore(): boolean {
    return this.auth.can('operator') && !this.time.isHistorical();
  }

  protected async openChangeGroup(): Promise<void> {
    const group = this.changeGroupId();
    if (!group) {
      return;
    }
    await this.router.navigate(['/changes'], { queryParams: { group } });
  }

  protected async planRestore(): Promise<void> {
    const group = this.changeGroupId();
    if (!group || !this.canRestore()) {
      return;
    }
    await this.router.navigate(['/history/restore'], { queryParams: { changeGroup: group } });
  }
}

function toRow(session: MonitoringSession): SessionRow {
  return {
    id: session.id,
    device: session.device_name || session.device_mac,
    model: session.device_type,
    mac: session.device_mac,
    site: session.site_id,
    at: formatInstant(new Date(session.config_applied_at ?? session.created_at)),
    status: statusLabel(session.status),
    severity: severityLabel(session.impact_severity),
    tone: toneOf(session.impact_severity),
  };
}

function windowLabel(session: MonitoringSession): string {
  const started = session.monitoring_started_at;
  if (!started) {
    return 'not started';
  }
  const end = session.completed_at ?? session.monitoring_ends_at;
  const from = formatTime(new Date(started));
  if (session.status === 'monitoring' || !end) {
    return `${from} → open`;
  }
  return `${from} → ${formatTime(new Date(end))}`;
}

function auditLabel(session: MonitoringSession): string {
  const [first, ...rest] = session.audit_ids;
  if (!first) {
    return 'none';
  }
  return rest.length > 0 ? `${shortAudit(first)} +${rest.length}` : shortAudit(first);
}

function incidentLabel(
  eventType: string,
  occurredAt: string,
  resolved: boolean,
  resolvedAt: string | null,
): string {
  const when = formatTime(new Date(occurredAt));
  if (!resolved) {
    return `${eventType} at ${when} — unresolved`;
  }
  const closed = resolvedAt ? ` at ${formatTime(new Date(resolvedAt))}` : '';
  return `${eventType} at ${when} — resolved${closed}`;
}

/** Five axis slots, offset from the configuration instant, as the design shows. */
function axisFor(bars: SleBar[], session: MonitoringSession): string[] {
  const first = Date.parse(bars[0].at);
  const last = Date.parse(bars[bars.length - 1].at);
  const applied = session.config_applied_at ? Date.parse(session.config_applied_at) : first;
  const live = session.status === 'monitoring' || session.status === 'awaiting_config';
  return [
    offsetLabel(first - applied),
    offsetLabel((first + applied) / 2 - applied),
    'CHANGE',
    offsetLabel((applied + last) / 2 - applied),
    live ? 'NOW' : offsetLabel(last - applied),
  ];
}

function offsetLabel(deltaMs: number): string {
  const minutes = Math.round(deltaMs / 60_000);
  const sign = minutes < 0 ? '−' : '+';
  const magnitude = Math.abs(minutes);
  return magnitude < 60 ? `${sign}${magnitude}M` : `${sign}${Math.round(magnitude / 60)}H`;
}

function statePanel(session: MonitoringSession): StatePanel {
  const summary = session.deterministic_summary ?? '';
  const applied = session.config_applied_at
    ? formatInstant(new Date(session.config_applied_at))
    : 'not recorded';
  const samples = sampleCount(session);
  const confidence = baselineConfidence(session);
  switch (session.status) {
    case 'awaiting_config':
      return {
        tone: 'info',
        tag: 'AWAITING CONFIGURATION',
        title: 'Waiting for the device to report',
        body:
          summary ||
          'The device has not reported a post-change configuration yet, so no baseline comparison has begun.',
        metaA: 'Change applied',
        metaAValue: applied,
        metaB: 'Samples so far',
        metaBValue: `${samples} collected`,
        next: 'Monitoring starts on its own once the device reports a post-change configuration and the first SLE samples have landed. Nothing to do here.',
      };
    case 'monitoring':
      return {
        tone: 'info',
        tag: 'MONITORING',
        title: 'Waiting for the first comparable sample',
        body:
          summary ||
          'Monitoring is open, but no observation has yet been captured that can be compared against the baseline.',
        metaA: 'Window',
        metaAValue: windowLabel(session),
        metaB: 'Samples so far',
        metaBValue: `${samples} collected`,
        next: 'The comparison appears as soon as the device reports SLE samples for the new configuration. The selected device refreshes every 30 seconds.',
      };
    case 'failed':
      return {
        tone: 'crit',
        tag: 'FAILED',
        title: 'Monitoring could not complete',
        body:
          summary ||
          'Monitoring aborted before it collected enough samples for a baseline comparison.',
        metaA: 'Window',
        metaAValue: windowLabel(session),
        metaB: 'Samples collected',
        metaBValue: `${samples} — too few for a baseline`,
        next: 'Bring the device back online, then re-run monitoring from the change group. Until then this change has no impact verdict.',
      };
    case 'completed':
      return {
        tone: 'none',
        tag: 'INSUFFICIENT EVIDENCE',
        title: 'The window closed without a comparison',
        body:
          summary ||
          'Monitoring closed without a baseline and a later observation to compare, so this change has no impact verdict either way.',
        metaA: 'Window',
        metaAValue: windowLabel(session),
        metaB: 'Baseline confidence',
        metaBValue: `${confidence} · ${samples} sample${samples === 1 ? '' : 's'}`,
        next: 'Re-run monitoring from the change group if the device is reporting again, or read the configuration diff to judge the change on its contents.',
      };
  }
}
