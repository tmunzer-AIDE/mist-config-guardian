import {
  ChangeDetectionStrategy,
  Component,
  computed,
  effect,
  inject,
  input,
  output,
  signal,
} from '@angular/core';
import { catchError, forkJoin, of } from 'rxjs';
import { ChangeGroupDetail } from '../../core/change-group.model';
import { OrganizationContextService } from '../../core/organization-context.service';
import { formatInstant } from '../../core/format';
import { MonitoringService } from '../impact/monitoring.service';
import { MonitoringSession, metricLabel, readAiAssessment } from '../impact/monitoring.model';
import { evidenceValue } from '../impact/site-impact.model';
import { ConfigurationTimeline } from '../impact/configuration-timeline';
import { DeviceEvidence } from '../impact/device-evidence';
import { changeOutcome, interpretationNeedsReview } from './change-outcome.model';

export type ChangeSection = 'outcome' | 'configuration' | 'timeline' | 'evidence';
const MAX_WINDOWS = 20;

@Component({
  selector: 'app-change-outcome',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ConfigurationTimeline, DeviceEvidence],
  templateUrl: './change-outcome.html',
  styleUrl: './change-outcome.scss',
})
export class ChangeOutcome {
  readonly detail = input.required<ChangeGroupDetail>();
  readonly view = input<ChangeSection>('outcome');
  readonly canRestore = input(false);
  readonly restoreBusy = input(false);
  readonly rollback = output<void>();
  readonly openSection = output<ChangeSection>();
  private readonly api = inject(MonitoringService);
  private readonly orgs = inject(OrganizationContextService);
  protected readonly sessions = signal<MonitoringSession[]>([]);
  protected readonly pending = signal(false);
  protected readonly unavailable = signal(0);
  protected readonly refresh = signal(0);
  protected readonly outcome = computed(() => changeOutcome(this.detail(), this.sessions()));
  protected readonly commentary = computed(() =>
    this.sessions()
      .map((session) => ({
        session,
        ai: readAiAssessment(session.ai_assessment),
        needsReview: interpretationNeedsReview(session),
      }))
      .filter((item) => !!item.ai || !!item.session.ai_assessment_error),
  );
  protected readonly windowsOmitted = computed(() =>
    Math.max(0, new Set(this.detail().monitoring_session_ids).size - MAX_WINDOWS),
  );
  protected readonly metric = metricLabel;
  protected readonly value = evidenceValue;
  protected readonly at = (value: string | null) =>
    value ? formatInstant(new Date(value)) : 'Not recorded';
  protected retry(): void {
    this.refresh.update((n) => n + 1);
  }

  constructor() {
    effect((cleanup) => {
      const detail = this.detail(),
        org = this.orgs.selected()?.id;
      this.refresh();
      this.sessions.set([]);
      this.unavailable.set(0);
      this.pending.set(false);
      if (!org || detail.impact_known === false || detail.impact_validation === 'excluded') return;
      const important =
        detail.site_impacts
          ?.flatMap((site) => site.devices)
          .filter((device) => ['critical', 'warning'].includes(device.severity))
          .map((device) => device.session_id) ?? [];
      const ids = [...new Set([...important, ...detail.monitoring_session_ids])]
        .filter((id) => detail.monitoring_session_ids.includes(id))
        .slice(0, MAX_WINDOWS);
      if (!ids.length) return;
      this.pending.set(true);
      const subscription = forkJoin(
        ids.map((id) => this.api.get(org, id).pipe(catchError(() => of(null)))),
      ).subscribe((results) => {
        const sessions = results.filter((s, i): s is MonitoringSession => !!s && s.id === ids[i]);
        this.sessions.set(sessions);
        this.unavailable.set(ids.length - sessions.length);
        this.pending.set(false);
      });
      cleanup(() => subscription.unsubscribe());
    });
  }
}
