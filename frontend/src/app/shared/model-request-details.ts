import { HttpClient } from '@angular/common/http';
import { ChangeDetectionStrategy, Component, effect, inject, input, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { orgPath } from '../core/api';

export interface ModelRequestDetails {
  request_id: string;
  input_state: 'available' | 'legacy' | 'unavailable';
  input_json: string | null;
  action_state: 'available' | 'legacy' | 'unavailable' | 'not_recorded';
  action: unknown;
}

@Component({
  selector: 'app-model-request-details',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <button type="button" class="cg-btn" (click)="load()" [disabled]="pending() || !organizationId() || !groupId()">
      {{ pending() ? 'Loading request details…' : 'Load request context and action' }}
    </button>
    @if (message()) { <p role="status">{{ message() }}</p> }
    @if (details(); as details) {
      @if (details.input_state === 'legacy' || details.action_state === 'legacy') {
        <p>Legacy embedded payload: no independently recorded content digest is available.</p>
      }
      <details><summary>Bounded input context · {{ details.input_state }}</summary>
        <pre>{{ details.input_json ?? 'Input context is unavailable or could not be verified.' }}</pre></details>
      <details><summary>Validated model action · {{ details.action_state }}</summary>
        <pre>{{ details.action ? json(details.action) : 'No verified action is available.' }}</pre></details>
    }
  `,
  styles: `:host { display: block; } button, details { margin-top: .5rem; }
    summary { cursor: pointer; } pre { white-space: pre-wrap; overflow-wrap: anywhere; max-height: 20rem; overflow: auto; }`,
})
export class ModelRequestDetailsComponent {
  readonly organizationId = input<string>();
  readonly groupId = input<string>();
  readonly requestId = input.required<string>();
  private readonly http = inject(HttpClient);
  private generation = 0;
  protected readonly pending = signal(false);
  protected readonly message = signal('');
  protected readonly details = signal<ModelRequestDetails | null>(null);
  protected readonly json = (value: unknown) => JSON.stringify(value, null, 2);

  constructor() {
    effect(() => {
      this.organizationId(); this.groupId(); this.requestId();
      this.generation++;
      this.pending.set(false); this.message.set(''); this.details.set(null);
    });
  }

  protected async load(): Promise<void> {
    const organization = this.organizationId(), group = this.groupId(), request = this.requestId();
    if (!organization || !group || this.pending()) return;
    const generation = ++this.generation;
    this.pending.set(true); this.message.set(''); this.details.set(null);
    try {
      const details = await firstValueFrom(this.http.get<ModelRequestDetails | null>(orgPath(organization,
        `/change-groups/${encodeURIComponent(group)}/investigation/model-requests/${encodeURIComponent(request)}`)));
      if (generation !== this.generation) return;
      if (details?.request_id === request) this.details.set(details);
      else this.message.set('Request details are not available.');
    } catch {
      if (generation === this.generation) this.message.set('Request details could not be loaded.');
    } finally {
      if (generation === this.generation) this.pending.set(false);
    }
  }
}
