import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { computed, inject, Injectable, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { API_ROOT } from '../../core/api';
import { Tone } from '../../core/tone';

export type AiCardKind = 'intent' | 'flag';
export type AiCardLevel = 'info' | 'warn' | 'crit';

/**
 * One advisory item beside the prose summary: a stated intent, or something
 * flagged for review. `field` cites a diff entry path when the model named one.
 */
export interface AiAssistCard {
  kind: AiCardKind;
  level: AiCardLevel;
  text: string;
  field: string | null;
}

export interface AiDiffSummary {
  summary: string;
  model: string;
  generated_at: string;
  cards: AiAssistCard[];
  duration_ms: number;
  cached: boolean;
  disclaimer: string;
}

export interface AiDiffFollowup {
  question: string;
  answer: string;
  model: string;
  generated_at: string;
  duration_ms: number;
  disclaimer: string;
}

export interface AiSettings {
  enabled: boolean;
  base_url: string;
  model: string;
  api_key_set: boolean;
  api_key_last_four: string | null;
  max_response_tokens: number;
  automatic_summaries: boolean;
  last_test_at: string | null;
  last_test_ok: boolean | null;
  last_test_detail: string | null;
}

export interface AiSummaryRequest {
  organization_id: string;
  from_version_id: string;
  to_version_id: string;
  regenerate?: boolean;
}

export interface AiFollowupRequest {
  organization_id: string;
  from_version_id: string;
  to_version_id: string;
  question: string;
}

/**
 * The outcome of an AI call.
 *
 * AI is advisory: nothing on the page depends on it, so failures never reach the
 * shell error banner. `unavailable` is the API's 409 — disabled or unconfigured.
 * `failed` is its 502, a provider that did not answer.
 */
export type AiOutcome<T> =
  | { status: 'ok'; value: T }
  | { status: 'unavailable'; message: string }
  | { status: 'failed'; message: string };

/** Availability as far as this browser can tell. */
export type AiAvailability = 'unknown' | 'enabled' | 'disabled';

/** The API's own wording, shown before a first response supplies its copy. */
export const AI_DISCLAIMER = 'Field names and values only — secrets are never sent.';

/** The API caps a follow-up question at this length. */
export const AI_QUESTION_MAX_LENGTH = 500;

/**
 * AI assist for diff explanation.
 *
 * `/ai/settings` is administrator-only, so for everyone else availability stays
 * `unknown`: the page offers the control and lets a 409 answer the question,
 * rather than hiding a feature that may well be configured.
 */
@Injectable({ providedIn: 'root' })
export class AiAssistService {
  private readonly http = inject(HttpClient);

  private readonly settingsState = signal<AiSettings | null>(null);
  private readonly resolvedState = signal(false);
  private readonly refusedState = signal(false);

  readonly settings = this.settingsState.asReadonly();
  readonly resolved = this.resolvedState.asReadonly();

  /** True once a call answered 409; the page then shows the quiet note. */
  readonly refused = this.refusedState.asReadonly();

  readonly availability = computed<AiAvailability>(() => {
    if (this.refusedState()) {
      return 'disabled';
    }
    const settings = this.settingsState();
    if (settings === null) {
      return 'unknown';
    }
    return settings.enabled ? 'enabled' : 'disabled';
  });

  /** Whether a summary should be produced without the operator asking. */
  readonly automatic = computed(
    () => this.availability() === 'enabled' && (this.settingsState()?.automatic_summaries ?? false),
  );

  /** Resolve AI availability once per session. Never throws. */
  /** Which session resolved this; a read outliving it is discarded. */
  private generation = 0;

  async loadSettings(force = false): Promise<void> {
    if (this.resolvedState() && !force) {
      return;
    }
    const generation = this.generation;
    try {
      const settings = await firstValueFrom(this.http.get<AiSettings>(`${API_ROOT}/ai/settings`));
      if (generation === this.generation) {
        this.settingsState.set(settings);
      }
    } catch {
      // 403 for non-administrators, or an unreachable endpoint. Availability is
      // unknown; deterministic diffing is unaffected either way.
      if (generation === this.generation) {
        this.settingsState.set(null);
      }
    } finally {
      if (generation === this.generation) {
        this.resolvedState.set(true);
      }
    }
  }

  async summarise(request: AiSummaryRequest): Promise<AiOutcome<AiDiffSummary>> {
    // Availability is session state: a summary asked for before a sign-out
    // must not report on it afterwards, whether it succeeds or is refused.
    const generation = this.generation;
    try {
      const value = await firstValueFrom(
        this.http.post<AiDiffSummary>(`${API_ROOT}/ai/diff-summary`, request),
      );
      if (generation === this.generation) {
        this.refusedState.set(false);
      }
      return { status: 'ok', value };
    } catch (cause) {
      return this.degrade(cause, generation);
    }
  }

  async followUp(request: AiFollowupRequest): Promise<AiOutcome<AiDiffFollowup>> {
    const generation = this.generation;
    try {
      const value = await firstValueFrom(
        this.http.post<AiDiffFollowup>(`${API_ROOT}/ai/diff-followup`, request),
      );
      return { status: 'ok', value };
    } catch (cause) {
      return this.degrade(cause, generation);
    }
  }

  reset(): void {
    this.generation += 1;
    this.settingsState.set(null);
    this.resolvedState.set(false);
    this.refusedState.set(false);
  }

  private degrade<T>(cause: unknown, generation: number): AiOutcome<T> {
    if (cause instanceof HttpErrorResponse) {
      if (cause.status === 409) {
        if (generation === this.generation) {
          this.refusedState.set(true);
        }
        return {
          status: 'unavailable',
          message: 'AI assist is not configured for this deployment.',
        };
      }
      if (cause.status === 502) {
        return { status: 'failed', message: 'The AI provider did not answer.' };
      }
      return { status: 'failed', message: `The AI endpoint answered HTTP ${cause.status}.` };
    }
    return { status: 'failed', message: 'The AI endpoint did not answer.' };
  }
}

/** Tone for a flag card's level. */
export function cardTone(level: AiCardLevel): Tone {
  if (level === 'crit') {
    return 'crit';
  }
  return level === 'warn' ? 'warn' : 'info';
}

/** `1.4s` — the design's rendering of an AI call's duration. */
export function formatDurationMs(value: number): string {
  if (value < 1000) {
    return `${Math.max(0, Math.round(value))}ms`;
  }
  return `${(value / 1000).toFixed(1)}s`;
}
