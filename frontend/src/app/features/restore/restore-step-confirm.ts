import { ChangeDetectionStrategy, Component, computed, input, output } from '@angular/core';

import { RestoreMode } from './restore.model';

/** The one object and version a focused restore is about. */
export interface RestoreFocus {
  versionId: string;
  objectName: string;
  objectKind: string;
  versionLabel: string;
  observedAt: string;
  actor: string;
}

/**
 * Step 1, for a restore that already knows its object.
 *
 * Arriving from an object's version history names both the object and the
 * version, so there is nothing to pick. The catalogue picker cannot even
 * express what such a link asks for — it only ever lists each object's newest
 * version — so showing it made the choice look unmade and buried the action
 * below several hundred rows. Anyone who did mean to restore more than one
 * object can still open the picker from here.
 */
@Component({
  selector: 'app-restore-step-confirm',
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './restore-step-confirm.html',
  styleUrl: './restore-step-confirm.scss',
})
export class RestoreStepConfirm {
  readonly focus = input<RestoreFocus | null>(null);
  /** Stands in until the object's versions have loaded, so the card never waits. */
  readonly fallbackLabel = input('');
  readonly mode = input.required<RestoreMode>();
  readonly includeDependencies = input.required<boolean>();
  readonly readOnly = input.required<boolean>();
  readonly readOnlyNote = input.required<string>();
  readonly busy = input.required<boolean>();

  readonly modePicked = output<RestoreMode>();
  readonly dependenciesToggled = output<boolean>();
  readonly planRequested = output<void>();
  readonly pickerRequested = output<void>();

  protected readonly objectName = computed(() => this.focus()?.objectName ?? this.fallbackLabel());
  protected readonly objectKind = computed(() => this.focus()?.objectKind ?? '');
  protected readonly versionLabel = computed(() => this.focus()?.versionLabel ?? '');
  protected readonly observedAt = computed(() => this.focus()?.observedAt ?? '');
  protected readonly actor = computed(() => this.focus()?.actor ?? '');
  protected readonly canPlan = computed(() => !this.readOnly() && !this.busy());

  /**
   * What the plan will reach beyond this object, said accurately.
   *
   * Only a restore with dependencies excluded touches this object alone. With
   * them included the planner brings every related object to the same moment,
   * and in exact mode it deletes the ones that did not exist then — so a flat
   * "nothing else is touched" would be a promise the plan does not keep.
   */
  protected readonly scopeNote = computed(() => {
    if (!this.includeDependencies()) {
      return 'Only this object is written — nothing else is touched.';
    }
    return this.mode() === 'exact'
      ? 'Objects it depends on are taken to the same moment, and any that did not exist then are deleted.'
      : 'Objects it depends on are taken to the same moment if they have changed since. Nothing is deleted.';
  });
}
