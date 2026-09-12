import { DeviceEvidence } from './device-evidence';
import { evidenceValue } from './site-impact.model';
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
import { Subscription } from 'rxjs';

import { AuthService } from '../../core/auth.service';
import { formatCount, formatInstant, formatTime } from '../../core/format';
import { OrganizationContextService } from '../../core/organization-context.service';
import { TimeContextService } from '../../core/time-context.service';
import { Tone, toneInk, toneOf } from '../../core/tone';
import {
  MetricDelta,
  MonitoringSession,
  baselineConfidence,
  hasTrustedBaseline,
  metricDeltas,
  metricLabel,
  primaryMetric,
  readAiAssessment,
  sampleCount,
  shortAudit,
  sleSeries,
  axisFor,
  baselineWindowLabel,
  statusLabel,
} from './monitoring.model';
import { MonitoringService } from './monitoring.service';
import { SleChart } from './sle-chart';
import { ConfigurationTimeline } from './configuration-timeline';

interface MetricRow extends MetricDelta {
  deltaInk: string;
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
  title: string;
  body: string;
  next: string;
}

/**
 * Evidence for exactly the session named in the URL.
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
  protected readonly evidenceValue = evidenceValue;
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly organizations = inject(OrganizationContextService);
  private readonly monitoring = inject(MonitoringService);
  private readonly auth = inject(AuthService);
  protected readonly time = inject(TimeContextService);

  /** `?session=` — bound by the router's component input binding. */
  readonly session = input('');
  protected readonly selected = signal<MonitoringSession | null>(null);
  protected readonly loading = signal(false);
  protected readonly failure = signal('');
  private readonly retryCount = signal(0);
  private linkFor: string | null = null;
  private foreignLink: string | null = null;

  protected readonly detail = computed(() => {
    const session = this.selected();
    if (!session) {
      return null;
    }
    return {
      device: session.device_name || session.device_mac,
      meta: `${session.device_mac} · ${session.device_type}`,
      status: statusLabel(session.status),
      summary: session.deterministic_summary ?? '',
      window: windowLabel(session),
      samples: formatCount(sampleCount(session)),
      baselineWindow: baselineWindowLabel(session),
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
    if (session.assessment) {
      return { tone: 'ok' as Tone, tag: 'NO IMPACT DETECTED', detail: session.assessment.summary };
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

  /** A real baseline-versus-latest network-metric comparison exists. */
  protected readonly hasData = computed(() => this.metrics().length > 0);

  protected readonly collectionErrors = computed(() => {
    const session = this.selected();
    if (!session) return [];
    if (session.assessment?.collection_errors) return session.assessment.collection_errors;
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

  protected readonly changeGroupId = computed(() => {
    const session = this.selected();
    if ((session?.audit_ids.length ?? 0) > 1) return null;
    return session?.change_group_id ?? session?.change_groups?.[0]?.id ?? null;
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
      this.organizations.revision();
      this.retryCount();
      const linked = this.session();
      const historical = this.historical();
      this.selected.set(null);
      this.failure.set('');
      this.loading.set(false);
      if (!org) return;
      if (this.linkFor && this.linkFor !== org) {
        this.foreignLink = linked || null;
        this.linkFor = org;
        void this.router.navigate([], {
          relativeTo: this.route, queryParams: { session: null },
          queryParamsHandling: 'merge', replaceUrl: true,
        });
        return;
      }
      this.linkFor = org;
      if (!linked || linked === this.foreignLink || historical) return;
      let request: Subscription | undefined;
      let busy = false;
      const read = () => {
        if (busy) return;
        busy = true;
        this.loading.set(!untracked(() => this.selected()));
        request = this.monitoring.get(org, linked).subscribe({
          next: (session) => {
            this.selected.set(session);
            this.failure.set('');
            this.loading.set(false);
            busy = false;
          },
          error: () => {
            this.failure.set(untracked(() => this.selected())
              ? 'Could not refresh evidence. The last successful reading is shown.'
              : 'This monitoring session could not be loaded. It may have been removed or be unavailable.');
            this.loading.set(false);
            busy = false;
          },
        });
      };
      read();
      const timer = setInterval(read, 30_000);
      onCleanup(() => { clearInterval(timer); request?.unsubscribe(); });
    });
  }

  protected retry(): void { this.retryCount.update((n) => n + 1); }

  protected async backToImpact(): Promise<void> {
    const session = this.selected();
    await this.router.navigate(['/impact'], {
      queryParams: session ? {
        site: session.site_id,
        device: session.device_mac.replace(/[^a-fA-F0-9]/g, '').toLowerCase(),
        change: this.changeGroupId(),
      } : {},
    });
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

function windowLabel(session: MonitoringSession): string {
  const started = session.monitoring_started_at;
  if (!started) {
    return 'not started';
  }
  const end = session.completed_at ?? session.monitoring_ends_at;
  if (session.status === 'monitoring' || !end) {
    return `${formatInstant(new Date(started))} → ongoing`;
  }
  return `${formatInstant(new Date(started))} → ${formatInstant(new Date(end))}`;
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

function statePanel(session: MonitoringSession): StatePanel {
  switch (session.status) {
    case 'awaiting_config':
      return {
        tone: 'info',
        title: 'Waiting for the device to report',
        body:
          'The device has not reported a post-change configuration yet, so no baseline comparison has begun.',
        next: 'Monitoring starts on its own once the device reports a post-change configuration and the first SLE samples have landed. Nothing to do here.',
      };
    case 'monitoring':
      return {
        tone: 'info',
        title: 'Waiting for the first comparable sample',
        body:
          'Monitoring is open, but no observation has yet been captured that can be compared against the baseline.',
        next: 'The comparison appears as soon as the device reports SLE samples for the new configuration. The selected device refreshes every 30 seconds.',
      };
    case 'failed':
      return {
        tone: 'crit',
        title: 'Monitoring could not complete',
        body:
          'Monitoring aborted before it collected enough samples for a baseline comparison.',
        next: 'Check device connectivity and collection errors. Missing network metrics do not erase the device findings above.',
      };
    case 'completed':
      return {
        tone: 'none',
        title: 'No network-metric comparison available',
        body:
          'There are not enough network-metric samples to compare before and after. Device changes are assessed separately above.',
        next: 'Use the device findings above and the configuration diff for context. Missing metrics do not establish that the network is healthy.',
      };
  }
}
