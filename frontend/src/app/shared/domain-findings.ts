import { ChangeDetectionStrategy, Component, input } from '@angular/core';

export interface DomainFinding {
  rule_id: string; target_handle: string; state: string; impact: string; current_impact: string;
  confidence: string; attribution: string; device_mac: string | null; port_id: string | null;
  service: string; occurred_at: string | null; recovered_at: string | null; explanation: string;
}

@Component({
  selector: 'app-domain-findings',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (findings()?.length) {
      <h4>Scoped service findings</h4>
      <p>These findings concern the stated service. A port finding does not establish failure of a neighboring AP.</p>
      @for (finding of findings(); track $index) {
        <article><strong>{{ finding.service }} · {{ finding.device_mac }} {{ finding.port_id }}</strong>
          <p>Peak: {{ finding.impact === 'info' ? 'Insufficient evidence' : finding.impact }} · Current: {{ finding.current_impact === 'info' ? 'Insufficient evidence' : finding.current_impact }}</p>
          <p>Confidence: {{ finding.confidence }} · Attribution: {{ finding.attribution }} · {{ finding.state }}</p>
          <p>{{ finding.explanation }}</p>
          @if (finding.occurred_at) { <p>Observed: {{ finding.occurred_at }}</p> }
          @if (finding.recovered_at) { <p>Recovered: {{ finding.recovered_at }}</p> }
        </article>
      }
    }
  `,
  styles: `:host { display:block; } article { border-block-end:1px solid var(--border); padding:.5rem 0; }`,
})
export class DomainFindingsComponent { readonly findings = input<DomainFinding[] | null>(); }
