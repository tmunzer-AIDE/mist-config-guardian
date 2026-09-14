import { ModelRequestDetailsComponent } from './model-request-details';
import { ChangeDetectionStrategy, Component, input } from '@angular/core';

export interface McpCheckpoint {
  source: 'mcp_agent'; state: string; reason: string;
  conclusion: null | { summary: string; impact: string; confidence: string; coverage: string;
    findings: { statement: string; evidence: string[]; limitations: string[] }[];
    gaps: string[] };
  evidence: { id: string; tool: string; state: string; arguments: unknown; data: unknown;
    error: string | null; captured_at: string }[];
}
export interface McpDispatch {
  id: string; tool: string; state: string; reserved_at: string; finished_at: string | null;
  candidate_revision: number; error: string | null;
}

@Component({
  selector: 'app-mcp-investigation',
  imports: [ModelRequestDetailsComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (checkpoint(); as agent) {
      <section aria-label="MCP agent investigation">
        <h3>AI findings · Mist MCP</h3>
        <p>{{ agent.state }}{{ agent.reason ? ': ' + agent.reason : '' }}</p>
        @if (agent.conclusion; as conclusion) {
          @for (finding of conclusion.findings; track $index) {
            <article><p>{{ finding.statement }}</p>
              <p>Evidence: {{ finding.evidence.join(', ') }}</p>
              <ul>@for (limitation of finding.limitations; track $index) { <li>{{ limitation }}</li> }</ul>
            </article>
          }
        }
        <details><summary>MCP requests and retained evidence</summary>
          <p>Responses are bounded and redacted. Missing or partial evidence does not establish health.</p>
          @for (evidence of agent.evidence; track evidence.id) {
            <details><summary>{{ evidence.tool }} · {{ evidence.state }} · {{ evidence.id }}</summary>
              <p>Captured {{ evidence.captured_at }}{{ evidence.error ? ' · ' + evidence.error : '' }}</p>
              <h4>Request</h4><pre>{{ json(evidence.arguments) }}</pre>
              <h4>Response</h4><pre>{{ json(evidence.data) }}</pre>
            </details>
          }
        </details>
      </section>
    }
    @if (dispatches().length) {
      <details><summary>Live MCP dispatch log · {{ dispatches().length }} reservations</summary>
        <p>Reserved means outcome unknown. This log may include attempts outside the published revision.</p>
        <div class="scroll"><table><thead><tr><th>Tool</th><th>Revision</th><th>State</th><th>Reserved / finished</th></tr></thead>
          <tbody>@for (row of dispatches(); track row.id) {
            <tr><td>{{ row.tool }}
              <app-model-request-details [organizationId]="organizationId()" [groupId]="groupId()"
                [requestId]="row.id" requestKind="mcp-requests" /></td><td>{{ row.candidate_revision }}</td>
              <td>{{ row.state === 'reserved' ? 'Outcome unknown' : row.state }} {{ row.error }}</td>
              <td>{{ row.reserved_at }} / {{ row.finished_at ?? 'Not recorded' }}</td></tr>
          }</tbody>
        </table></div>
      </details>
    }
  `,
  styles: `:host { display:block; } section, details, article { margin:1rem 0; overflow-wrap:anywhere; }
    summary { cursor:pointer; } pre { white-space:pre-wrap; max-height:24rem; overflow:auto; }
    .scroll { overflow:auto; } table { width:100%; border-collapse:collapse; } td,th { padding:.5rem; text-align:left; border-bottom:1px solid var(--border); }`,
})
export class McpInvestigationComponent {
  readonly organizationId = input<string>();
  readonly groupId = input<string>();
  readonly checkpoint = input<McpCheckpoint | null>();
  readonly dispatches = input<McpDispatch[]>([]);
  protected readonly json = (value: unknown) => JSON.stringify(value, null, 2);
}
