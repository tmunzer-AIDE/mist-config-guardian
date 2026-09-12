import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { PortSnapshot, PortSnapshotComponent } from './port-snapshot';
import { ManagedNeighbor, ManagedNeighborComponent } from './managed-neighbor';
import { PortEvent, PortEventsComponent } from './port-events';
import { ModelRequestDetailsComponent } from './model-request-details';

interface Proposal {
  summary: string;
  hypotheses: { target_handle: string; statement: string; supporting_checks: string[];
    counterevidence_checks: string[]; limitations: string[] }[];
  open_questions: string[];
}
export interface AgentCheckpoint {
  source: 'model_proposal';
  state: string;
  reason: string;
  proposal: Proposal | null;
  memory: { source_revision: number; proposal: Proposal } | null;
  observations: { ref: string; target_handle: string; state: string; sampled_clients: number | null;
    captured_at?: string | null; observed_disconnects: number | null; port?: PortSnapshot | null;
    port_events?: PortEvent[]; omitted_events?: number;
    managed_neighbor?: ManagedNeighbor | null; gap: string; window: { start: string; end: string } }[];
}
export interface ModelActivity {
  source: 'live_investigation_root';
  calls_used: number;
  calls_limit: number;
  input_bytes_reserved: number;
  input_bytes_limit: number;
  records: { id: string; candidate_revision: number; model: string; state: string; reserved_at: string;
    finished_at: string | null; request_tokens: number | null; response_tokens: number | null;
    input_hash: string }[];
}

@Component({
  selector: 'app-agent-investigation',
  imports: [PortEventsComponent, ManagedNeighborComponent, ModelRequestDetailsComponent, PortSnapshotComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (checkpoint(); as agent) {
      <section aria-label="Agent investigation proposal">
        <h3>Agent investigation · shadow proposal</h3>
        <p>Model explanations are hypotheses for review. Evidence references are validated;
          they do not prove attribution. Impact and confidence above come from the deterministic assessment.</p>
        <p>{{ agent.state === 'complete' ? 'Proposal ready for review' : agent.state }}{{ agent.reason ? ': ' + agent.reason : '' }}</p>
        @if (agent.proposal; as proposal) {
          <p>{{ proposal.summary }}</p>
          @for (hypothesis of proposal.hypotheses; track $index) {
            <article><h4>Hypothesis · target {{ hypothesis.target_handle }}</h4>
              <p>{{ hypothesis.statement }}</p>
              <p>Supporting checks: {{ hypothesis.supporting_checks.join(', ') || 'None cited' }}</p>
              <p>Counterevidence checks: {{ hypothesis.counterevidence_checks.join(', ') || 'None cited' }}</p>
              <ul>@for (limitation of hypothesis.limitations; track $index) { <li>{{ limitation }}</li> }</ul>
            </article>
          }
          @if (proposal.open_questions.length) {
            <h4>Open questions and missing capabilities</h4>
            <ul>@for (question of proposal.open_questions; track $index) { <li>{{ question }}</li> }</ul>
          }
        }
        <details><summary>Evidence supplied to the agent</summary>
          <div class="scroll"><table><thead><tr><th>Check reference</th><th>Window</th><th>State</th><th>Sampled clients</th><th>Observed disconnects</th></tr></thead>
            <tbody>@for (evidence of agent.observations; track evidence.ref) {
              <tr><td>{{ evidence.ref }}</td><td>{{ evidence.window.start }}–{{ evidence.window.end }}</td>
                <td>{{ evidence.state }} {{ evidence.gap }}<app-port-snapshot [port]="evidence.port" /><app-port-events [events]="evidence.port_events" [omitted]="evidence.omitted_events ?? 0" /><app-managed-neighbor [neighbor]="evidence.managed_neighbor" [capturedAt]="evidence.captured_at" /></td><td>{{ evidence.sampled_clients ?? '—' }}</td><td>{{ evidence.observed_disconnects ?? '—' }}</td></tr>
            }</tbody></table></div>
          <p>Counts describe returned samples; incomplete samples cannot establish absence of impact.</p>
        </details>
        @if (agent.memory; as memory) {
          <details><summary>Saved context · source revision {{ memory.source_revision }}</summary>
            <p>This is a model proposal retained as context, not fresh evidence.</p><p>{{ memory.proposal.summary }}</p>
          </details>
        }
      </section>
    }
    @if (activity(); as activity) {
      <details><summary>Live model activity · {{ activity.calls_used }}/{{ activity.calls_limit }} requests reserved</summary>
        <p>Current investigation activity may include attempts outside this published revision.
          A reserved request has an unknown outcome and may not have reached the provider.</p>
        <p>Input bytes reserved: {{ activity.input_bytes_reserved }}/{{ activity.input_bytes_limit }}.
          Missing token usage is unknown, not zero.</p>
        @for (request of activity.records; track request.id) {
          <details><summary>{{ request.model }} · {{ request.state === 'reserved' ? 'Outcome unknown' : request.state }} · candidate revision {{ request.candidate_revision }}</summary>
            <p>Request {{ request.id }} · reserved {{ request.reserved_at }} · result {{ request.finished_at ?? 'Not recorded' }}</p>
            <p>Tokens: input {{ request.request_tokens ?? 'Unknown' }} · output {{ request.response_tokens ?? 'Unknown' }}</p>
            <p>Input fingerprint: {{ request.input_hash }}</p>
            <app-model-request-details [organizationId]="organizationId()" [groupId]="groupId()" [requestId]="request.id" />
          </details>
        }
      </details>
    }
  `,
  styles: `
    :host { display: block; margin-top: 1rem; } p { line-height: 1.5; }
    section, article, details { margin-top: .75rem; overflow-wrap: anywhere; }
    summary { cursor: pointer; } pre { white-space: pre-wrap; max-height: 20rem; overflow: auto; }
    .scroll { overflow: auto; max-height: 24rem; }
    table { width: 100%; border-collapse: collapse; font-size: .85rem; }
    th, td { text-align: left; vertical-align: top; padding: .5rem; border-bottom: 1px solid var(--border); }
  `,
})
export class AgentInvestigationComponent {
  readonly organizationId = input<string>();
  readonly groupId = input<string>();
  readonly checkpoint = input<AgentCheckpoint | null>();
  readonly activity = input<ModelActivity | null>();
}
