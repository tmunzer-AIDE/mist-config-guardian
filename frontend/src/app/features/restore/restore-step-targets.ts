import { ChangeDetectionStrategy, Component, computed, input, output } from '@angular/core';

import { formatInstant } from '../../core/format';
import {
  appliedCount,
  RestoreMode,
  restoreModeLabel,
  RestoreOperation,
  restoreStatusLabel,
  restoreStatusTone,
  RestoreTarget,
  shortOperationId,
  TargetScope,
} from './restore.model';

export interface TargetTypeOption {
  value: string;
  label: string;
  count: number;
}

export interface TargetSiteOption {
  value: string;
  label: string;
}

/** One removable chip in the persistent SELECTED row. */
export interface SelectedPill {
  id: string;
  label: string;
}

const SCOPES: { value: TargetScope; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'org', label: 'Organization' },
  { value: 'site', label: 'Site' },
];

/**
 * Step 1 — choose the object versions to restore.
 *
 * Filters narrow what the list shows; the selection is held above and survives
 * every filter change, which is why the selected pills are rendered from their
 * own list rather than from the visible rows.
 */
@Component({
  selector: 'app-restore-step-targets',
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './restore-step-targets.html',
  styleUrl: './restore-step-targets.scss',
})
export class RestoreStepTargets {
  readonly targets = input.required<RestoreTarget[]>();
  readonly pills = input.required<SelectedPill[]>();
  readonly selectedIds = input.required<string[]>();
  readonly typeOptions = input.required<TargetTypeOption[]>();
  readonly siteOptions = input.required<TargetSiteOption[]>();
  readonly scope = input.required<TargetScope>();
  readonly siteId = input.required<string>();
  readonly objectType = input.required<string>();
  readonly query = input.required<string>();
  /** Every restorable object in the organization, before any filter. */
  readonly total = input.required<number>();
  /** Objects matching the current filters, which can exceed one page. */
  readonly matched = input.required<number>();
  /** The row window this page shows, already formatted as "n-m of N". */
  readonly pageLabel = input.required<string>();
  readonly pageSize = input.required<number>();
  readonly pageSizes = input.required<readonly number[]>();
  readonly hasPrevPage = input.required<boolean>();
  readonly hasNextPage = input.required<boolean>();
  readonly mode = input.required<RestoreMode>();
  readonly includeDependencies = input.required<boolean>();
  readonly history = input.required<RestoreOperation[]>();
  readonly readOnly = input.required<boolean>();
  readonly readOnlyNote = input.required<string>();
  readonly busy = input.required<boolean>();
  readonly changeGroupTitle = input<string | null>(null);

  readonly scopePicked = output<TargetScope>();
  readonly sitePicked = output<string>();
  readonly typePicked = output<string>();
  readonly queryChanged = output<string>();
  readonly targetToggled = output<string>();
  readonly targetRemoved = output<string>();
  readonly cleared = output<void>();
  readonly filtersCleared = output<void>();
  readonly changeGroupCleared = output<void>();
  readonly pageSizePicked = output<number>();
  readonly nextPageRequested = output<void>();
  readonly previousPageRequested = output<void>();
  readonly modePicked = output<RestoreMode>();
  readonly dependenciesToggled = output<boolean>();
  readonly planRequested = output<void>();
  readonly operationPicked = output<string>();

  protected readonly scopes = SCOPES;

  private readonly selection = computed(() => new Set(this.selectedIds()));
  protected readonly showing = computed(() => this.targets().length);
  protected readonly canPlan = computed(
    () => this.selectedIds().length > 0 && !this.readOnly() && !this.busy(),
  );
  protected readonly filtered = computed(
    () =>
      this.scope() !== 'all' ||
      this.siteId() !== '' ||
      this.objectType() !== '' ||
      this.query() !== '',
  );
  protected readonly noMatches = computed(() => this.targets().length === 0 && this.filtered());
  protected readonly isEmpty = computed(() => this.targets().length === 0 && !this.filtered());

  protected readonly rows = computed(() =>
    this.targets().map((target) => ({
      id: target.version_id,
      name: target.name,
      kind: kindOf(target),
      version: `v${target.version}`,
      at: instant(target.observed_at),
      selected: this.selection().has(target.version_id),
    })),
  );

  protected readonly historyRows = computed(() =>
    this.history().map((operation) => ({
      id: operation.id,
      label: shortOperationId(operation.id),
      status: restoreStatusLabel(operation.status),
      tone: restoreStatusTone(operation.status),
      meta: `${restoreModeLabel(operation.mode)} · ${appliedCount(operation)} of ${operation.actions.length} actions`,
      at: `${instant(operation.created_at)} · ${operation.credential_actor ?? 'unattributed'}`,
    })),
  );

  protected inputValue(event: Event): string {
    return (event.target as HTMLInputElement).value;
  }

  protected selectValue(event: Event): string {
    return (event.target as HTMLSelectElement).value;
  }

  protected numericValue(event: Event): number {
    return Number((event.target as HTMLSelectElement).value);
  }
}

function kindOf(target: RestoreTarget): string {
  if (target.scope === 'org') {
    return `${target.object_type.toUpperCase()} · ORG SCOPE`;
  }
  const site = target.site_name ?? target.site_mist_id ?? '';
  return site
    ? `${target.object_type.toUpperCase()} · SITE ${site.toUpperCase()}`
    : `${target.object_type.toUpperCase()} · SITE`;
}

function instant(value: string): string {
  const at = new Date(value);
  return Number.isNaN(at.getTime()) ? value : formatInstant(at);
}
