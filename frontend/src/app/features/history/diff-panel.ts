import { NgTemplateOutlet } from '@angular/common';
import { afterNextRender, ChangeDetectionStrategy, Component, ElementRef, inject, Injector, input, output, signal, viewChild } from '@angular/core';

import { Tone } from '../../core/tone';
import { RawRow } from './raw-diff';

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

/**
 * The deterministic body of a comparison: compact change cards or the sectioned
 * view, plus the redacted side-by-side JSON.
 *
 * Presentational only — the parent owns every fetch, including the lazy load of
 * a section's entries when it is first opened.
 */
@Component({
  selector: 'app-diff-panel',
  imports: [NgTemplateOutlet],
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

  protected readonly fullScreen = signal(false);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
  private readonly injector = inject(Injector);
  private readonly dialog = viewChild.required<ElementRef<HTMLDialogElement>>('rawDialog');
  private scrollPosition = 0;
  protected enlarge(): void {
    this.rememberPosition();
    this.fullScreen.set(true);
    this.dialog().nativeElement.showModal();
    this.restoreView(this.scrollPosition);
  }
  protected shrink(): void {
    this.rememberPosition();
    this.dialog().nativeElement.close();
  }
  protected rememberPosition(): void {
    this.scrollPosition = this.host.nativeElement.querySelector('.raw-grid')?.scrollTop ?? 0;
  }
  protected closed(): void {
    this.fullScreen.set(false);
    this.restoreView(this.scrollPosition);
  }
  private restoreView(scrollTop: number): void {
    afterNextRender(() => {
      const grid = this.host.nativeElement.querySelector('.raw-grid');
      if (grid) grid.scrollTop = scrollTop;
      this.host.nativeElement.querySelector<HTMLButtonElement>('.raw-size')?.focus({ preventScroll: true });
    }, { injector: this.injector });
  }
}
