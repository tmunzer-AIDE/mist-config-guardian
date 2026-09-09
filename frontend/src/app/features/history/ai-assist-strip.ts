import { ChangeDetectionStrategy, Component, computed, input, output } from '@angular/core';

import { Tone } from '../../core/tone';
import { AiAssistCard, AiDiffSummary, AiCardLevel, cardTone } from './ai-assist.service';

/** The AI strip's states, in the order an operator meets them. */
export type AiState = 'idle' | 'generating' | 'generated' | 'unavailable' | 'failed';

/**
 * The advisory AI strip above a comparison.
 *
 * Presentational only: it owns no requests and no availability logic, so an
 * unavailable endpoint renders as a quiet inline note beside a comparison that
 * is computed and complete either way.
 */
@Component({
  selector: 'app-ai-assist-strip',
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './ai-assist-strip.html',
  styleUrl: './ai-assist-strip.scss',
})
export class AiAssistStrip {
  /** False when AI is known to be off, or answered 409 for this comparison. */
  readonly offered = input.required<boolean>();
  readonly state = input.required<AiState>();
  readonly prompt = input.required<string>();
  /** The API's own disclaimer once it has answered; its wording before that. */
  readonly disclaimer = input.required<string>();
  readonly note = input('');
  readonly meta = input('');
  readonly summary = input<AiDiffSummary | null>(null);
  readonly question = input('');
  readonly answer = input<string | null>(null);
  readonly asking = input(false);
  readonly canAsk = input(false);
  readonly questionMaxLength = input(500);

  /** True to ask the provider to ignore any cached summary. */
  readonly run = output<boolean>();
  readonly ask = output<void>();
  readonly questionChange = output<string>();
  readonly openSettings = output<void>();

  protected readonly intent = computed<AiAssistCard[]>(
    () => this.summary()?.cards.filter((card) => card.kind === 'intent') ?? [],
  );
  protected readonly flags = computed<AiAssistCard[]>(
    () => this.summary()?.cards.filter((card) => card.kind === 'flag') ?? [],
  );

  protected toneOfLevel(level: AiCardLevel): Tone {
    return cardTone(level);
  }

  protected onQuestion(event: Event): void {
    this.questionChange.emit((event.target as HTMLInputElement).value);
  }
}
