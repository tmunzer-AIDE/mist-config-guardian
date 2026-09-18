import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';

import { formatInstant } from '../core/format';
import {
  COVERAGE_LABEL,
  earlyNote,
  GuardianSummary,
  guardianHeadline,
  guardianState,
  guardianTone,
  RECOVERY_LABEL,
  sourceLabel,
} from '../core/guardian.model';

/**
 * One audit's Guardian result, in one badge.
 *
 * It never colours an unknown answer as a clean one: only a published result
 * takes a severity tone, and "not recorded", "could not be read" and "still
 * investigating" each say what they are instead of falling back to none.
 *
 * An early result is labelled as early wherever it is shown, including when the
 * investigation has already finished without a final one — otherwise a partial
 * answer would read as a settled verdict.
 *
 * `summary` left unset renders nothing at all, which is how a page says it did
 * not ask; `null` renders "no investigation recorded", which is an answer.
 */
@Component({
  selector: 'app-guardian-badge',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (shown()) {
      <div class="guardian" [attr.data-tone]="tone()" aria-label="Guardian investigation result">
        <strong>Guardian · {{ headline() }}</strong>
        @if (early(); as note) {
          <span class="early">{{ note }}</span>
        }
        @if (result(); as result) {
          <span
            >Peak: {{ result.peak }} · Current: {{ result.current }}
            @if (recovery()) {
              · {{ recovery() }}
            }</span
          >
          <span>Confidence: {{ result.confidence }} · Deterministic coverage: {{ coverage() }}</span>
          @if (!compact()) {
            <span>{{ result.summary }}</span>
            <span>Evidence as of {{ at(result.evaluated_at) }} · Sources: {{ sources() }}</span>
          }
        } @else {
          <span>{{ explanation() }}</span>
        }
        @if (reason(); as reason) {
          <span>{{ reason }}</span>
        }
      </div>
    }
  `,
  styles: `
    :host { display: block; }
    .guardian { display: grid; gap: .25rem; margin: .6rem 0; font-size: .75rem;
      line-height: 1.4; overflow-wrap: anywhere; }
    strong { font-weight: 600; } span { opacity: .8; }
    .early { font-weight: 600; opacity: 1; }
    [data-tone='crit'] strong { color: var(--tone-critical-ink); }
    [data-tone='warn'] strong { color: var(--tone-warning-ink); }
  `,
})
export class GuardianBadge {
  readonly summary = input<GuardianSummary | null | undefined>(undefined);
  readonly compact = input(false);

  /** Unset means the page asked nothing; every other value is an answer worth printing. */
  protected readonly shown = computed(() => this.summary() !== undefined);
  protected readonly state = computed(() => guardianState(this.summary()));
  protected readonly headline = computed(() => guardianHeadline(this.state()));
  protected readonly tone = computed(() => guardianTone(this.state()));
  protected readonly result = computed(() => {
    const state = this.state();
    return state.kind === 'result' ? state.result : null;
  });
  protected readonly early = computed(() => {
    const state = this.state();
    return state.kind === 'result' ? earlyNote(state) : null;
  });
  protected readonly recovery = computed(() => {
    const result = this.result();
    return result ? RECOVERY_LABEL[result.recovery] : '';
  });
  protected readonly coverage = computed(() => {
    const result = this.result();
    return result ? COVERAGE_LABEL[result.coverage] : '';
  });
  protected readonly sources = computed(() => {
    const result = this.result();
    const sources = (result?.sources ?? []).map(sourceLabel);
    return sources.length ? sources.join(', ') : 'none recorded';
  });

  /** Why there is no result, said from the state rather than from a default. */
  protected readonly explanation = computed(() => {
    switch (this.state().kind) {
      case 'not_recorded':
        return 'No Guardian investigation was recorded for this change.';
      case 'unavailable':
        return 'The stored result could not be read. This is not a clean result: nothing is known here.';
      case 'pending':
        return 'Guardian is still collecting evidence. No result has been published yet.';
      default:
        return 'The investigation finished without publishing a result.';
    }
  });

  /** The root's own reason, shown beside whatever state it explains. */
  protected readonly reason = computed(() => {
    const state = this.state();
    return state.kind === 'not_recorded' || state.kind === 'unavailable' ? null : state.reason;
  });

  protected readonly at = (value: string) => formatInstant(new Date(value));
}
