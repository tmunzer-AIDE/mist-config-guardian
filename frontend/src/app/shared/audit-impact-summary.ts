import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { AuditImpactSummary, SHADOW_LABELS } from '../core/audit-impact.model';
import { formatInstant } from '../core/format';

@Component({
  selector: 'app-audit-impact-summary',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (assessment(); as value) {
      <div class="shadow" aria-label="Shadow audit assessment">
        <strong>Shadow · {{ labels[value.result] }}</strong>
        @if (value.confidence || value.coverage) {
          <span>Confidence: {{ value.confidence ?? 'unknown' }} · Session coverage: {{ value.coverage ?? 'unknown' }}</span>
        }
        @if (value.report_id) {
          <span>Revision {{ value.revision }} @if (!compact()) { · {{ value.policy_version }} }</span>
        }
        @if (!compact() && value.evaluated_at) { <span>Evidence as of {{ at(value.evaluated_at) }} · {{ value.status }}</span> }
        @if (!compact() && (value.gap_count || value.unmapped_count)) {
          <span>{{ value.gap_count }} {{ value.gap_count === 1 ? 'gap' : 'gaps' }} · {{ value.unmapped_count }} unmapped attributes</span>
        }
        @if (value.stop_reason) { <span>{{ value.stop_reason }}</span> }
      </div>
    }
  `,
  styles: `
    :host { display: block; }
    .shadow { display: grid; gap: .25rem; margin: .6rem 0; font-size: .75rem;
      line-height: 1.4; overflow-wrap: anywhere; }
    strong { font-weight: 600; } span { opacity: .8; }
  `,
})
export class AuditImpactSummaryComponent {
  readonly assessment = input<AuditImpactSummary | null | undefined>(null);
  readonly compact = input(false);
  protected readonly labels = SHADOW_LABELS;
  protected readonly at = (value: string) => formatInstant(new Date(value));
}
