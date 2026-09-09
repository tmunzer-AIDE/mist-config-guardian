import { ChangeDetectionStrategy, Component, input, output } from '@angular/core';

import { Tone } from '../../core/tone';

/** One compact change card, shown when the API reports `chips` mode. */
export interface ChangeCard {
  key: string;
  field: string;
  before: string;
  after: string;
  note: string;
  secret: boolean;
}

/** One high blast-radius entry, ranked by the API. */
export interface NotableFinding {
  key: string;
  kind: string;
  tone: Tone;
  field: string;
  note: string;
}

export interface EntryRow {
  key: string;
  field: string;
  kind: string;
  tone: Tone;
  before: string;
  after: string;
  removed: boolean;
}

export interface SectionView {
  key: string;
  name: string;
  path: string;
  changed: number;
  countLabel: string;
  notable: number;
  open: boolean;
  loading: boolean;
  /** False while the section's entry bodies have not been fetched yet. */
  loaded: boolean;
  rows: EntryRow[];
  more: string;
}

export interface RawRow {
  index: number;
  before: string;
  after: string;
}

/**
 * The deterministic body of a comparison: compact change cards or the sectioned
 * view, plus the redacted side-by-side JSON.
 *
 * Presentational only — the parent owns every fetch, including the lazy load of
 * a section's entries when it is first opened.
 */
@Component({
  selector: 'app-diff-panel',
  imports: [],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './diff-panel.html',
  styleUrl: './diff-panel.scss',
})
export class DiffPanel {
  /** The API's `mode`, already resolved by the parent. */
  readonly compact = input.required<boolean>();
  readonly sectioned = input.required<boolean>();
  readonly changed = input(0);
  readonly cards = input<readonly ChangeCard[]>([]);
  readonly notable = input<readonly NotableFinding[]>([]);
  readonly sections = input<readonly SectionView[]>([]);
  readonly rawLabel = input('');
  readonly rawExpanded = input(false);
  readonly rawLoading = input(false);
  readonly rawRows = input<readonly RawRow[]>([]);

  readonly openSection = output<string>();
  readonly expandSection = output<string>();
  readonly toggleRaw = output<void>();
}
