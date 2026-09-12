import { HttpClient } from '@angular/common/http';
import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { orgPath } from '../../core/api';
import { formatInstant } from '../../core/format';
import { OrganizationContextService } from '../../core/organization-context.service';
import { AuditImpactSummary, SHADOW_LABELS } from '../../core/audit-impact.model';
import { DeploymentEvidence } from '../../core/deployment-evidence.model';
import { PortSnapshot, PortSnapshotComponent } from '../../shared/port-snapshot';
import { DeploymentEvidenceComponent } from '../../shared/deployment-evidence';
import { DispatchLog, DispatchLogComponent } from '../../shared/dispatch-log';
import { AgentCheckpoint, AgentInvestigationComponent, ModelActivity } from '../../shared/agent-investigation';

interface ShadowAssessment {
  impact: 'info' | 'none' | 'warning';
  confidence: 'low' | 'medium';
  coverage: 'complete' | 'partial' | 'unmapped';
  gaps: string[];
  findings: {
    target_handle: string;
    state: string;
    baseline_clients: number | null;
    disconnected_clients: number | null;
    serving_ap_macs: string[];
    explanation: string;
  }[];
}

export interface ShadowReport {
  mode: 'shadow';
  id: string;
  audit_id: string;
  status: string;
  stop_reason?: string;
  revision: number;
  changed_at: string;
  expires_at: string;
  calls_used: number;
  calls_limit: number;
  assessment: ShadowAssessment | null;
  shadow_impact?: AuditImpactSummary | null;
  deployment?: DeploymentEvidence | null;
  dispatch_log?: DispatchLog | null;
  agent?: AgentCheckpoint | null;
  model_activity?: ModelActivity | null;
  targets: { handle: string; site_id: string; wlan_id: string }[];
  checks: {
    check_id: string;
    port?: PortSnapshot | null;
    device_mac?: string | null;
    port_id?: string | null;
    target_handle: string;
    window: { start: string; end: string };
    captured_at: string;
    state: string;
    row_count: number;
    reason: string;
    dispatch_denial?: 'credentials_unavailable' | 'credentials_changed' | 'window_expired' |
      'lease_lost' | 'budget_exhausted' | 'journal_full' | 'reservation_rejected' | null;
  }[];
}

@Component({
  selector: 'app-shadow-investigation',
  imports: [PortSnapshotComponent, DeploymentEvidenceComponent, DispatchLogComponent, AgentInvestigationComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <button class="cg-btn" type="button" (click)="load()" [disabled]="pending()">Review shadow evidence</button>
    @if (pending()) { <p role="status">Loading investigation evidence…</p> }
    @if (message()) { <p role="status">{{ message() }}</p> }
    @if (report(); as report) {
      <section aria-label="Shadow investigation evidence">
        <h3>Change investigation · evaluation preview</h3>
        <p>This preview is available for review before the new engine supplies published impact verdicts.</p>
        @if (report.stop_reason) { <p role="status">{{ report.stop_reason }}</p> }
        <p>Revision {{ report.revision }} · {{ report.status }} · {{ at(report.changed_at) }}–{{ at(report.expires_at) }}</p>
        @if (report.assessment; as assessment) {
          <p class="ratings"><strong>Impact: {{ impactLabel() }}</strong> · <strong>Confidence: {{ assessment.confidence }}</strong></p>
          <p>Session-evidence coverage: {{ assessment.coverage }}. Failed joins and unrecorded sessions are not covered.</p>
          @for (finding of assessment.findings; track finding.target_handle) {
            <article>
              <h4>WLAN {{ wlan(finding.target_handle) }}</h4>
              <p>{{ finding.explanation }}</p>
              <dl>
                <dt>Clients in historical baseline</dt><dd>{{ finding.baseline_clients ?? 'Unknown' }}</dd>
                <dt>Observed client disconnects</dt><dd>{{ finding.disconnected_clients ?? 'Unknown' }}</dd>
                <dt>APs serving those clients</dt><dd>{{ finding.serving_ap_macs.join(', ') || 'Not established' }}</dd>
              </dl>
              <p class="muted">A serving AP entry does not mean that the AP failed.</p>
            </article>
          }
          @if (assessment.gaps.length) {
            <h4>Evidence gaps</h4>
            <ul>@for (gap of assessment.gaps; track $index) { <li>{{ gap }}</li> }</ul>
          }
        } @else { <p>{{ report.status === "incomplete" ? "No assessment could be completed." : "Waiting for the initial evidence checkpoint." }}</p> }
        <app-deployment-evidence [evidence]="report.deployment" />
        <details>
          <summary>Collection checks · {{ report.calls_used }}/{{ report.calls_limit }} requests used</summary>
          <div class="checks">
            <table>
              <caption>Bounded evidence checks</caption>
              <thead><tr><th>Check / interval</th><th>State</th><th>Rows</th><th>Details</th></tr></thead>
              <tbody>@for (check of report.checks; track $index) {
                <tr><td>{{ check.check_id }}<br>{{ check.device_mac }} {{ check.port_id }}<br>{{ at(check.window.start) }}–{{ at(check.window.end) }}</td>
                  <td>{{ check.state === 'dispatch_denied' ? 'Not dispatched' : check.state }}</td>
                  <td>{{ check.row_count }}</td><td>{{ check.reason || 'Collected' }}<app-port-snapshot [port]="check.port" /></td></tr>
              }</tbody>
            </table>
          </div>
        </details>
        <app-dispatch-log [log]="report.dispatch_log" />
        <app-agent-investigation [checkpoint]="report.agent" [activity]="report.model_activity"
          [organizationId]="organizationId()" [groupId]="groupId()" />
      </section>
    }
  `,
  styles: `
    :host { display: block; margin-top: 1rem; }
    section { border-top: 1px solid var(--border); margin-top: 1rem; padding-top: 1rem; overflow-wrap: anywhere; }
    h3, h4 { margin: .75rem 0; } p { margin: .6rem 0; line-height: 1.5; }
    article { padding: .5rem 0; } dl { display: grid; grid-template-columns: 1fr 1fr; gap: .5rem; }
    dd { margin: 0; } .muted { opacity: .75; } .checks { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; margin: .75rem 0; }
    th, td { padding: .5rem; text-align: left; border-bottom: 1px solid var(--border); }
    th:nth-child(2), td:nth-child(2), th:nth-child(3), td:nth-child(3) { white-space: nowrap; }
    caption { text-align: left; padding: .5rem; } summary { cursor: pointer; }
  `,
})
export class ShadowInvestigation {
  readonly groupId = input.required<string>();
  private readonly organizations = inject(OrganizationContextService);
  private readonly http = inject(HttpClient);
  protected readonly organizationId = computed(() => this.organizations.selected()?.id);
  private request = 0;
  protected readonly pending = signal(false);
  protected readonly report = signal<ShadowReport | null>(null);
  protected readonly message = signal('');
  protected readonly at = (value: string) => formatInstant(new Date(value));
  protected readonly impactLabel = computed(() => {
    const projection = this.report()?.shadow_impact;
    if (projection) return SHADOW_LABELS[projection.result];
    const band = this.report()?.assessment?.impact;
    if (band === 'none' && this.report()?.assessment?.coverage !== 'complete') return 'Insufficient evidence';
    return band === 'info' ? 'Insufficient evidence' : band === 'none' ? 'No observed disconnect' : 'Possible disruption';
  });

  constructor() {
    effect(() => {
      this.groupId();
      this.organizations.selected()?.id;
      this.request++;
      this.report.set(null);
      this.message.set('');
      this.pending.set(false);
    });
  }

  protected wlan(handle: string): string {
    return this.report()?.targets.find((item) => item.handle === handle)?.wlan_id ?? 'Unknown identity';
  }

  protected async load(): Promise<void> {
    const organization = this.organizations.selected()?.id;
    if (!organization) return;
    const request = ++this.request;
    this.pending.set(true);
    this.message.set('');
    this.report.set(null);
    try {
      const report = await firstValueFrom(this.http.get<ShadowReport | null>(
        orgPath(organization, `/change-groups/${this.groupId()}/investigation`),
      ));
      if (request !== this.request) return;
      this.report.set(report);
      if (!report) this.message.set('No shadow investigation was recorded for this change.');
    } catch {
      if (request === this.request) this.message.set('Investigation evidence could not be loaded.');
    } finally {
      if (request === this.request) this.pending.set(false);
    }
  }
}
