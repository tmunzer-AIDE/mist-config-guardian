import { HttpClient } from '@angular/common/http';
import { ChangeDetectionStrategy, Component, effect, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { firstValueFrom } from 'rxjs';
import { AuthService } from '../core/auth.service';
import { orgPath } from '../core/api';

interface Acceptance {
  eligible: boolean; total: number; held_out: number; true_positive: number; false_negative: number;
  false_positive: number; true_negative: number; critical_misses: number; abstentions: number;
  recall: number | null; precision: number | null; specificity: number | null; reasons: string[];
}
@Component({
  selector: 'app-impact-adjudication', imports: [FormsModule], changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <details><summary>Human review and release readiness</summary>
      <p>Review the current completed checkpoint against independent outage records. Labels are recorded with your account and the exact evidence revision. Model proposals are not ground truth.</p>
      @if (auth.can('administrator') && terminal() && reportId()) {
        <form (ngSubmit)="submit()">
          <label>Observed outcome <select name="label" [(ngModel)]="label">
            <option value="uncertain">Uncertain</option><option value="benign">Benign change</option>
            <option value="noncritical_outage">Noncritical outage</option><option value="critical_outage">Critical outage</option>
          </select></label>
          <label>Independent evidence and rationale <textarea name="rationale" [(ngModel)]="rationale" minlength="10" maxlength="1500" required></textarea></label>
          <label><input type="checkbox" name="attested" [(ngModel)]="attested" /> I reviewed the evidence independently for current revision {{ revision() }}.</label>
          <button class="cg-btn" type="submit" [disabled]="busy() || !attested || rationale.trim().length < 10">Record review</button>
        </form>
      } @else { <p>Recording a label requires an administrator and a completed investigation.</p> }
      <button class="cg-btn" type="button" (click)="read()" [disabled]="busy()">Check acceptance counts</button>
      @if (message()) { <p role="status">{{ message() }}</p> }
      @if (result(); as result) {
        <p><strong>{{ result.eligible ? 'Acceptance set passed · manual release still required' : 'Promotion blocked' }}</strong></p>
        <p>{{ result.total }} reviewed changes · {{ result.held_out }} in the fixed held-out subset.</p>
        <p>TP {{ result.true_positive }} · FN {{ result.false_negative }} · FP {{ result.false_positive }} · TN {{ result.true_negative }}
          · Critical misses {{ result.critical_misses }} · Abstentions {{ result.abstentions }}</p>
        <p>Recall {{ percent(result.recall) }} · Precision {{ percent(result.precision) }} · Specificity {{ percent(result.specificity) }}. Small samples do not establish statistical calibration.</p>
        <ul>@for (reason of result.reasons; track $index) { <li>{{ reason }}</li> }</ul>
      }
    </details>
  `,
  styles: `:host { display:block; margin:1rem 0; } summary { cursor:pointer; } p { line-height:1.5; } form,label { display:grid; gap:.5rem; margin:.6rem 0; } textarea { min-height:6rem; }`,
})
export class ImpactAdjudicationComponent {
  readonly organizationId = input<string | undefined>(); readonly groupId = input.required<string>();
  readonly reportId = input<string | null | undefined>(); readonly revision = input.required<number>(); readonly terminal = input(false);
  protected readonly auth = inject(AuthService); private readonly http = inject(HttpClient);
  protected readonly result = signal<Acceptance | null>(null); protected readonly busy = signal(false); protected readonly message = signal('');
  protected label = 'uncertain'; protected rationale = ''; protected attested = false; private generation = 0;
  constructor() { effect(() => { this.organizationId(); this.groupId(); this.reportId(); this.revision(); this.generation++;
    this.result.set(null); this.busy.set(false); this.message.set(''); this.label = 'uncertain'; this.rationale = ''; this.attested = false;
  }); }
  protected percent(value: number | null): string { return value === null ? 'Unavailable' : `${Math.round(value * 100)}%`; }
  protected async read(): Promise<void> {
    const org = this.organizationId(); if (!org) return;
    const generation = this.generation; this.busy.set(true);
    try { const result = await firstValueFrom(this.http.get<Acceptance>(orgPath(org, `/change-groups/${this.groupId()}/investigation/acceptance`)));
      if (generation === this.generation) this.result.set(result);
    } catch { if (generation === this.generation) this.message.set('Acceptance evidence is unavailable; promotion remains blocked.'); }
    finally { if (generation === this.generation) this.busy.set(false); }
  }
  protected async submit(): Promise<void> {
    const org = this.organizationId(); if (!org || !this.attested || !this.terminal() || !this.reportId() || this.rationale.trim().length < 10) return;
    const generation = this.generation; this.busy.set(true);
    try { await firstValueFrom(this.http.post(orgPath(org, `/change-groups/${this.groupId()}/investigation/adjudication`), {
      report_id: this.reportId(), revision: this.revision(), label: this.label, rationale: this.rationale.trim(), human_reviewed: true,
    })); if (generation === this.generation) { this.message.set('Human review recorded.'); this.attested = false; }
    } catch { if (generation === this.generation) this.message.set('Review was not recorded. Refresh the report; an existing label or changed publication may prevent submission.'); }
    finally { if (generation === this.generation) this.busy.set(false); }
  }
}
