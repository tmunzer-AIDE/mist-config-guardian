import {
  ChangeDetectionStrategy,
  Component,
  computed,
  DestroyRef,
  effect,
  inject,
  input,
  signal,
  untracked,
} from '@angular/core';
import { Router } from '@angular/router';

import { AuthService } from '../../core/auth.service';
import { ChangeGroupService } from '../../core/change-group.service';
import { OrganizationContextService } from '../../core/organization-context.service';
import { TimeContextService } from '../../core/time-context.service';
import { UiStateService } from '../../core/ui-state.service';
import { RestoreStepAuthorize } from './restore-step-authorize';
import { RestoreStepExecute } from './restore-step-execute';
import { RestoreStepPlan } from './restore-step-plan';
import { RestoreStepTargets, SelectedPill, TargetSiteOption, TargetTypeOption } from './restore-step-targets';
import {
  ApprovalRequest,
  blocksExecution,
  isRestoreInFlight,
  isRestoreTerminal,
  RestoreMode,
  RestoreOperation,
  RestoreTarget,
  RestoreTargetQuery,
  RestoreVerification,
  shortOperationId,
  TargetScope,
} from './restore.model';
import { RestoreService } from './restore.service';

export type RestoreStepName = 'targets' | 'plan' | 'authorize' | 'execute';

const STEP_ORDER: readonly RestoreStepName[] = ['targets', 'plan', 'authorize', 'execute'];

const STEP_LABELS: Record<RestoreStepName, string> = {
  targets: '1 · Select targets',
  plan: '2 · Review plan',
  authorize: '3 · Authorize',
  execute: '4 · Execute',
};

/** Poll cadence while the worker owns the operation. */
export const POLL_INTERVAL_MS = 2000;

/** Upper bound on polls so a stuck worker cannot keep a tab requesting forever. */
export const MAX_POLL_ATTEMPTS = 300;

/** Page sizes the picker offers. The targets endpoint caps a page at 200. */
export const TARGET_PAGE_SIZES: readonly number[] = [25, 50, 100];

/** Rows per page before anyone chooses. */
export const DEFAULT_TARGET_PAGE_SIZE = 25;

export const HISTORICAL_NOTE =
  'You are viewing a past point in time, so restores are read-only here. Return to now to plan, authorize, or run one.';

export const ROLE_NOTE = 'Planning a restore requires the operator role.';

export const ADMINISTRATOR_NOTE =
  'Authorizing a restore requires the administrator role and a recent multi-factor check. An operator can build and review the plan, then hand it to an administrator.';

/**
 * Router query parameters are written to inputs even when they are absent, and
 * they arrive as `undefined` then — which overwrites the declared default. Every
 * deep-link input therefore normalises the missing case to an empty string.
 */
function fromQuery(value: string | undefined): string {
  return value ?? '';
}

/**
 * The four-step restore flow.
 *
 * Planning is side-effect free: nothing is written until step 3 exchanges a
 * separate administrator token for an execution. The token lives in the
 * authorize step's own signal, is passed straight to the request, and is never
 * held here, in a service, in storage, or in the URL.
 */
@Component({
  selector: 'app-restore-page',
  imports: [RestoreStepTargets, RestoreStepPlan, RestoreStepAuthorize, RestoreStepExecute],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './restore-page.html',
  styleUrl: './restore-page.scss',
})
export class RestorePage {
  private readonly restores = inject(RestoreService);
  private readonly changeGroups = inject(ChangeGroupService);
  private readonly organizations = inject(OrganizationContextService);
  private readonly router = inject(Router);
  private readonly ui = inject(UiStateService);
  private readonly auth = inject(AuthService);
  protected readonly time = inject(TimeContextService);

  // ---- deep links, bound by the router's component input binding ----------
  /** `?versions=a,b,c` — pre-select these object versions. */
  readonly versions = input('', { transform: fromQuery });
  /** `?changeGroup=<id>` — pre-select the versions that group replaced. */
  readonly changeGroup = input('', { transform: fromQuery });
  /** `?operation=<id>` — open an existing restore operation. */
  readonly operation = input('', { transform: fromQuery });
  /** `?step=<name>` — land on a named step when it is reachable. */
  readonly step = input('', { transform: fromQuery });
  /** `?compensate=1` — open compensation for the named operation. */
  readonly compensate = input('', { transform: fromQuery });

  /** Every deep-link input as one value, so a change to any of them is one change. */
  private readonly deepLink = computed<DeepLink>(() => ({
    versions: this.versions(),
    changeGroup: this.changeGroup(),
    operation: this.operation(),
    step: this.step(),
    compensate: this.compensate(),
  }));

  protected readonly currentStep = signal<RestoreStepName>('targets');

  // ---- step 1 state -------------------------------------------------------
  protected readonly targets = signal<RestoreTarget[]>([]);
  /** Objects matching the current filters, which can exceed one page. */
  protected readonly matched = signal(0);
  /** Every restorable object, captured from the first unfiltered read. */
  protected readonly catalogTotal = signal(0);
  protected readonly typeFacets = signal<TargetTypeOption[]>([]);
  protected readonly siteFacets = signal<TargetSiteOption[]>([]);
  protected readonly selectedIds = signal<string[]>([]);
  /**
   * Labels for selected version ids, accumulated as targets load.
   *
   * The selection outlives any filter, and a deep link can name a version that
   * is not the newest one the picker lists, so the label cannot be looked up in
   * the visible rows alone.
   */
  private readonly labels = signal<Record<string, string>>({});
  protected readonly pageSize = signal(DEFAULT_TARGET_PAGE_SIZE);
  protected readonly skip = signal(0);
  protected readonly pageSizes = TARGET_PAGE_SIZES;

  protected readonly scope = signal<TargetScope>('all');
  protected readonly siteId = signal('');
  protected readonly objectType = signal('');
  protected readonly query = signal('');
  protected readonly changeGroupTitle = signal<string | null>(null);
  protected readonly history = signal<RestoreOperation[]>([]);

  // ---- plan and run state -------------------------------------------------
  protected readonly mode = signal<RestoreMode>('non_destructive');
  protected readonly includeDependencies = signal(true);
  protected readonly activeOperation = signal<RestoreOperation | null>(null);
  protected readonly verification = signal<RestoreVerification | null>(null);
  protected readonly compensationPlan = signal<RestoreOperation | null>(null);
  protected readonly compensating = signal(false);
  protected readonly busy = signal(false);
  protected readonly polling = signal(false);
  protected readonly pollExhausted = signal(false);

  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private pollAttempts = 0;
  /** The deep link last applied, keyed with its organization.
   *
   *  The router reuses this component when only the query parameters change,
   *  so a link can arrive while the page is already open and must be applied
   *  again. A re-run for an organization refresh carries the same link and
   *  must not re-apply it over whatever the user has done since. The
   *  organization is part of the key because every identifier in a link
   *  belongs to one. */
  private appliedLink: string | null = null;
  private appliedOrganization: string | null = null;
  /** The organization and revision the rail was last read for. */
  private loadedRail: string | null = null;
  /**
   * The selection on screen, as something async work can be scoped to.
   *
   * It is replaced whenever what the page shows changes hands: a link, an
   * operation, a restart, an organization. A Promise cannot be cancelled, so
   * every async path captures the signal before it awaits and drops its result
   * if the signal has been aborted since; the shell's loading and error state
   * are scoped to it as well.
   */
  private selection = new AbortController();
  /** Target and rail reads are sequenced on their own: a filter change is not a new selection. */
  private targetsRequest = 0;
  private historyRequest = 0;
  /** Their loading and error state is scoped too: a superseded read reports nothing. */
  private targetsScope = new AbortController();
  private railScope = new AbortController();
  /** The organization the filters, rows, facets and rail belong to. */
  private filtersFor: string | null = null;
  /** The poll tick in flight, so the interval cannot overlap its own reads. */
  private pollInFlight: AbortSignal | null = null;

  protected readonly readOnly = computed(
    () => this.time.isHistorical() || !this.auth.can('operator'),
  );
  protected readonly readOnlyNote = computed(() =>
    this.time.isHistorical() ? HISTORICAL_NOTE : ROLE_NOTE,
  );

  /** Execution is administrator-only and step-up authenticated on the API. */
  protected readonly canAuthorize = computed(
    () => !this.readOnly() && this.auth.can('administrator'),
  );
  protected readonly authorizeNote = computed(() =>
    this.readOnly() ? this.readOnlyNote() : ADMINISTRATOR_NOTE,
  );

  protected readonly typeOptions = computed<TargetTypeOption[]>(() => {
    const facets = this.typeFacets();
    const all = facets.reduce((sum, facet) => sum + facet.count, 0);
    return [{ value: '', label: 'All types', count: all }, ...facets];
  });

  protected readonly siteOptions = computed<TargetSiteOption[]>(() => [
    { value: '', label: 'All sites' },
    ...this.siteFacets(),
  ]);

  protected readonly selectedPills = computed<SelectedPill[]>(() => {
    const known = this.labels();
    return this.selectedIds().map((id) => ({
      id,
      label: known[id] ?? `version ${shortOperationId(id)}`,
    }));
  });

  /** The 1-based row window this page shows, as "n-m of N". */
  protected readonly pageLabel = computed(() => {
    const total = this.matched();
    if (total === 0) {
      return '0 of 0';
    }
    const first = this.skip() + 1;
    const last = Math.min(this.skip() + this.targets().length, total);
    return `${first}\u2013${last} of ${total}`;
  });

  protected readonly hasPrevPage = computed(() => this.skip() > 0);
  protected readonly hasNextPage = computed(
    () => this.skip() + this.targets().length < this.matched(),
  );

  protected readonly preflightErrors = computed(
    () => this.activeOperation()?.preflight_errors ?? [],
  );
  protected readonly blockedByPreflight = computed(() => this.preflightErrors().length > 0);

  protected readonly approval = computed<ApprovalRequest | null>(
    () => this.activeOperation()?.approval ?? null,
  );

  /** The approval gate: a non-null approval that has not been granted blocks execution. */
  protected readonly blockedByApproval = computed(() => blocksExecution(this.approval()));

  protected readonly steps = computed(() => {
    const currentIndex = STEP_ORDER.indexOf(this.currentStep());
    return STEP_ORDER.map((name, index) => ({
      name,
      label: STEP_LABELS[name],
      current: index === currentIndex,
      done: index < currentIndex,
      // Completed steps stay reachable; later steps are only reached by acting.
      reachable: this.stepAvailable(name),
    }));
  });

  constructor() {
    // Targets reload whenever the organization or any filter changes; the facet
    // counts belong to the filter set that produced them.
    effect(() => {
      const organizationId = this.organizations.selected()?.id;
      this.organizations.revision();
      if (organizationId && this.filtersFor !== null && this.filtersFor !== organizationId) {
        // A site or type filter names something in the organization it was set
        // under, and the rows, facets and rail were read from it. They go
        // before this read is built, so the read carries none of them and a
        // failure cannot leave the previous organization's rows on screen.
        untracked(() => this.forgetOrganization());
      }
      this.filtersFor = organizationId ?? this.filtersFor;
      const query: RestoreTargetQuery = {
        scope: this.scope(),
        siteId: this.siteId() || undefined,
        objectType: this.objectType() || undefined,
        q: this.query() || undefined,
        skip: this.skip(),
        limit: this.pageSize(),
      };
      if (!organizationId) {
        return;
      }
      untracked(() => {
        this.targetsScope.abort();
        this.targetsScope = new AbortController();
        void this.ui.track(
          'Loading restore targets',
          () => this.loadTargets(organizationId, query),
          this.targetsScope.signal,
        );
      });
    });

    // History and the deep links are independent of the filter row. The link
    // is read here, tracked, rather than inside the bootstrap: the router
    // reuses this component when only the query parameters change, so a
    // second notification opened from this page has to land the way the
    // first one did.
    effect(() => {
      const organizationId = this.organizations.selected()?.id;
      const revision = this.organizations.revision();
      const link = this.deepLink();
      if (!organizationId) {
        return;
      }
      untracked(() => this.bootstrap(organizationId, revision, link));
    });

    inject(DestroyRef).onDestroy(() => {
      // Nothing still in flight may report to a page that is gone.
      this.stopPolling();
      this.selection.abort();
      this.targetsScope.abort();
      this.railScope.abort();
    });
  }

  // ---- loading ------------------------------------------------------------

  private async loadTargets(organizationId: string, query: RestoreTargetQuery): Promise<void> {
    const request = ++this.targetsRequest;
    const response = await this.restores.targets(organizationId, query);
    // Answers arrive in any order; only the latest request describes the
    // filters and organization on screen.
    if (request !== this.targetsRequest) {
      return;
    }
    const items = response.items ?? [];
    this.targets.set(items);
    this.matched.set(response.total ?? items.length);
    this.typeFacets.set(
      (response.types ?? []).map((facet) => ({
        value: facet.type,
        label: facet.type,
        count: facet.count,
      })),
    );
    this.siteFacets.set(
      (response.sites ?? []).map((site) => ({ value: site.id, label: site.name })),
    );
    if (isUnfiltered(query)) {
      this.catalogTotal.set(response.total ?? items.length);
    }
    this.rememberLabels(items.map((item) => [item.version_id, `${item.name} · v${item.version}`]));
  }

  /**
   * Decide synchronously what the URL asks for, then do the reading.
   *
   * The decision cannot wait on a request: a link that arrives while an
   * earlier one is still loading must supersede it, which the generation
   * token arranges once the key is recorded here and not after an await.
   */
  private bootstrap(organizationId: string, revision: number, link: DeepLink): void {
    void this.loadRail(organizationId, revision);

    const key = linkKey(organizationId, link);
    if (key === this.appliedLink) {
      return;
    }
    const previous = this.appliedOrganization;
    this.appliedLink = key;
    this.appliedOrganization = organizationId;
    const token = this.reset();

    if (previous !== null && previous !== organizationId && !isEmptyLink(link)) {
      // The identifiers in the link belong to the organization it was written
      // for; under another one they name nothing. The URL is cleared rather
      // than left to fail, and the effect re-runs with the empty link.
      void this.router.navigate(['/history/restore'], { queryParams: {} });
      return;
    }
    void this.applyLink(organizationId, link, token);
  }

  private async loadRail(organizationId: string, revision: number): Promise<void> {
    const key = `${organizationId}:${revision}`;
    if (key === this.loadedRail) {
      return;
    }
    this.loadedRail = key;
    this.railScope.abort();
    this.railScope = new AbortController();
    await this.ui.track('Loading recent restores', () => this.loadHistory(organizationId), this.railScope.signal);
  }

  private async applyLink(organizationId: string, link: DeepLink, token: AbortSignal): Promise<void> {
    const versionIds = link.versions
      .split(',')
      .map((value) => value.trim())
      .filter((value) => value.length > 0);
    if (versionIds.length > 0) {
      this.selectedIds.set(versionIds);
    }

    if (link.changeGroup) {
      await this.ui.track(
        'Loading the change group',
        () => this.applyChangeGroup(organizationId, link.changeGroup, token),
        token,
      );
      if (this.stale(token)) {
        return;
      }
    }

    if (link.operation) {
      const opened = await this.openOperation(link.operation, link.compensate === '1');
      if (!opened) {
        return;
      }
    }

    if (isStepName(link.step) && this.stepAvailable(link.step)) {
      this.currentStep.set(link.step);
    }
  }

  private stale(signal: AbortSignal): boolean {
    return signal.aborted;
  }

  /** Forget the operation on screen and everything derived from it. Returns the new scope. */
  private clearOperation(): AbortSignal {
    this.stopPolling();
    this.activeOperation.set(null);
    this.verification.set(null);
    this.compensationPlan.set(null);
    this.compensating.set(false);
    this.pollExhausted.set(false);
    // Whatever was busy was busy for the previous selection.
    this.busy.set(false);
    if (this.currentStep() !== 'targets') {
      this.currentStep.set('targets');
    }
    this.selection.abort();
    this.selection = new AbortController();
    return this.selection.signal;
  }

  /** Everything read from, or set for, the previous organization. */
  private forgetOrganization(): void {
    this.scope.set('all');
    this.siteId.set('');
    this.objectType.set('');
    this.query.set('');
    this.skip.set(0);
    this.targets.set([]);
    this.matched.set(0);
    this.catalogTotal.set(0);
    this.typeFacets.set([]);
    this.siteFacets.set([]);
    this.labels.set({});
    this.history.set([]);
  }

  /** Back to an empty picker: the operation, the selection, the change group. */
  private reset(): AbortSignal {
    const token = this.clearOperation();
    this.selectedIds.set([]);
    this.changeGroupTitle.set(null);
    return token;
  }

  /**
   * Make the URL say what the page shows, without re-applying it.
   *
   * The link the navigation will produce is recorded as applied first, so the
   * effect that watches the URL sees nothing new to do.
   */
  private canonicalize(organizationId: string, operationId: string | null, replaceUrl = false): void {
    this.appliedLink = linkKey(organizationId, { ...EMPTY_LINK, operation: operationId ?? '' });
    this.appliedOrganization = organizationId;
    void this.router.navigate(['/history/restore'], {
      queryParams: operationId ? { operation: operationId } : {},
      replaceUrl,
    });
  }

  /**
   * Pre-select the versions a change group replaced.
   *
   * Restoring "what this change group did" means going back to the version each
   * object held before it, which is not the version the picker lists — the
   * picker offers the newest version of every object. The selection is therefore
   * carried by id, with the label taken from the group's own object list.
   */
  private async applyChangeGroup(organizationId: string, groupId: string, token: AbortSignal): Promise<void> {
    const detail = await this.changeGroups.load(organizationId, groupId);
    if (this.stale(token)) {
      return;
    }
    this.changeGroupTitle.set(detail.title);
    const chosen: string[] = [];
    const labels: [string, string][] = [];
    for (const object of detail.changed_objects) {
      const versionId = object.before_version_id;
      if (!versionId) {
        continue;
      }
      chosen.push(versionId);
      labels.push([
        versionId,
        object.before_version === null
          ? object.object_name
          : `${object.object_name} · v${object.before_version}`,
      ]);
    }
    this.rememberLabels(labels);
    if (chosen.length > 0) {
      this.selectedIds.set(chosen);
    }
  }

  private rememberLabels(entries: [string, string][]): void {
    if (entries.length === 0) {
      return;
    }
    this.labels.update((current) => {
      const next = { ...current };
      for (const [id, label] of entries) {
        next[id] = label;
      }
      return next;
    });
  }

  private async loadHistory(organizationId: string): Promise<void> {
    const request = ++this.historyRequest;
    const response = await this.restores.list(organizationId, 0, 10);
    // The initial read, a refresh and the reload after a run can all be in
    // flight. Only the latest describes the rail on screen; a slow answer for
    // a previous organization is older by construction.
    if (request !== this.historyRequest || organizationId !== this.organizations.selected()?.id) {
      return;
    }
    this.history.set(response.items ?? []);
  }

  // ---- step 1 -------------------------------------------------------------

  protected setScope(scope: TargetScope): void {
    this.scope.set(scope);
    this.firstPage();
    if (scope !== 'site') {
      this.siteId.set('');
    }
  }

  protected setSite(siteId: string): void {
    this.siteId.set(siteId);
    this.firstPage();
  }

  protected setType(objectType: string): void {
    this.objectType.set(objectType);
    this.firstPage();
  }

  protected setQuery(query: string): void {
    this.query.set(query.trim());
    this.firstPage();
  }

  protected clearFilters(): void {
    this.scope.set('all');
    this.siteId.set('');
    this.objectType.set('');
    this.query.set('');
    this.firstPage();
  }

  // ---- paging -------------------------------------------------------------
  protected setPageSize(size: number): void {
    this.pageSize.set(size);
    // The window a page number names moves with its size, so the only offset
    // that still means the same thing after a resize is the first one.
    this.firstPage();
  }

  protected nextPage(): void {
    if (this.hasNextPage()) {
      this.skip.update((skip) => skip + this.pageSize());
    }
  }

  protected previousPage(): void {
    if (this.hasPrevPage()) {
      this.skip.update((skip) => Math.max(0, skip - this.pageSize()));
    }
  }

  /**
   * Return to the first page.
   *
   * Every filter change calls this: a narrower filter can leave fewer matches
   * than the current offset, which would otherwise show an empty page for a
   * filter that does match objects.
   */
  private firstPage(): void {
    this.skip.set(0);
  }

  protected toggleTarget(versionId: string): void {
    this.selectedIds.update((ids) =>
      ids.includes(versionId) ? ids.filter((id) => id !== versionId) : [...ids, versionId],
    );
    this.invalidatePlan();
  }

  protected removeTarget(versionId: string): void {
    this.selectedIds.update((ids) => ids.filter((id) => id !== versionId));
    this.invalidatePlan();
  }

  protected clearSelection(): void {
    this.selectedIds.set([]);
    this.invalidatePlan();
  }

  protected clearChangeGroup(): void {
    this.changeGroupTitle.set(null);
    this.clearSelection();
  }

  protected setMode(mode: RestoreMode): void {
    if (mode === this.mode()) {
      return;
    }
    if (this.activeOperation() && this.currentStep() !== 'targets') {
      // A plan can only take a new mode by being rebuilt from its versions. One
      // with no versions to rebuild from keeps its mode: the old action list —
      // deletes included — must not execute under a label it does not match.
      if (this.selectedIds().length === 0) {
        return;
      }
      void this.rebuildPlan(mode);
      return;
    }
    this.mode.set(mode);
    this.invalidatePlan();
  }

  /**
   * Replace the plan with one built in another mode.
   *
   * The old plan goes before the new one is asked for, and the mode shown
   * changes only once the new one exists: an exact plan may delete objects a
   * non-destructive plan leaves alone, so at no point may an action list be
   * executable under a label it does not match — not while the rebuild is in
   * flight, and not after it fails.
   */
  private async rebuildPlan(mode: RestoreMode): Promise<void> {
    this.clearOperation();
    await this.buildPlan(mode);
  }

  protected setIncludeDependencies(include: boolean): void {
    this.includeDependencies.set(include);
    this.invalidatePlan();
  }

  private invalidatePlan(): void {
    this.clearOperation();
    this.forgetLink();
  }

  /** The link described a selection the user has now changed; a refresh must not restore it. */
  private forgetLink(): void {
    const organizationId = this.organizations.selected()?.id;
    if (!organizationId || this.appliedLink === linkKey(organizationId, EMPTY_LINK)) {
      return;
    }
    this.canonicalize(organizationId, null, true);
  }

  // ---- step 2 -------------------------------------------------------------

  protected async buildPlan(mode: RestoreMode = this.mode()): Promise<void> {
    const organizationId = this.organizations.selected()?.id;
    const versionIds = this.selectedIds();
    if (!organizationId || versionIds.length === 0 || this.readOnly() || this.busy()) {
      return;
    }
    const token = this.selection.signal;
    this.busy.set(true);
    const operation = await this.ui.track(
      'Building a side-effect-free plan',
      () => this.restores.createPlan(organizationId, versionIds, mode, this.includeDependencies()),
      token,
    );
    if (this.stale(token)) {
      return;
    }
    this.busy.set(false);
    if (!operation) {
      return;
    }
    this.clearOperation();
    this.activeOperation.set(operation);
    // The mode is the plan's: it is committed with the plan, never ahead of it.
    this.mode.set(mode);
    this.currentStep.set('plan');
    // The plan is a record now; a refresh should return to it, not to the picker.
    this.canonicalize(organizationId, operation.id, true);
  }

  protected goToAuthorize(): void {
    if (this.blockedByPreflight() || !this.activeOperation()) {
      return;
    }
    this.currentStep.set('authorize');
  }

  protected backToTargets(): void {
    this.currentStep.set('targets');
  }

  // ---- step 3 -------------------------------------------------------------

  protected async execute(token: string): Promise<void> {
    const organizationId = this.organizations.selected()?.id;
    const operation = this.activeOperation();
    if (!organizationId || !operation || !this.canAuthorize() || this.busy()) {
      return;
    }
    if (this.blockedByPreflight() || this.blockedByApproval()) {
      return;
    }
    const generation = this.selection.signal;
    this.busy.set(true);
    const queued = await this.ui.track(
      'Authorizing the restore',
      () => this.restores.execute(organizationId, operation.id, token),
      generation,
    );
    if (this.stale(generation)) {
      return;
    }
    this.busy.set(false);
    if (!queued) {
      return;
    }
    const current = this.clearOperation();
    this.activeOperation.set(queued);
    this.currentStep.set('execute');
    if (isRestoreInFlight(queued.status)) {
      this.startPolling();
    } else {
      await this.afterRun(organizationId, queued, current);
    }
  }

  protected async requestApproval(): Promise<void> {
    const organizationId = this.organizations.selected()?.id;
    const operation = this.activeOperation();
    if (!organizationId || !operation || this.readOnly() || this.busy()) {
      return;
    }
    const token = this.selection.signal;
    this.busy.set(true);
    const approval = await this.ui.track(
      'Requesting approval',
      () => this.restores.requestApproval(organizationId, operation.id),
      token,
    );
    if (this.stale(token)) {
      return;
    }
    this.busy.set(false);
    if (approval) {
      this.activeOperation.set({ ...operation, approval });
    }
  }

  protected async refreshApproval(): Promise<void> {
    const organizationId = this.organizations.selected()?.id;
    const operation = this.activeOperation();
    const approval = this.approval();
    if (!organizationId || !operation || !approval || this.busy()) {
      return;
    }
    const token = this.selection.signal;
    this.busy.set(true);
    const fresh = await this.ui.track(
      'Checking the approval',
      () => this.restores.approval(organizationId, approval.id),
      token,
    );
    if (this.stale(token)) {
      return;
    }
    this.busy.set(false);
    if (fresh) {
      this.activeOperation.set({ ...operation, approval: fresh });
    }
  }

  // ---- step 4 -------------------------------------------------------------

  private startPolling(): void {
    const operation = this.activeOperation();
    if (this.pollTimer !== null || !operation || !isRestoreInFlight(operation.status)) {
      return;
    }
    this.pollAttempts = 0;
    this.pollExhausted.set(false);
    this.polling.set(true);
    // Each tick carries the generation it was started under. Clearing the
    // interval does not reach a read already in flight; the token does.
    const selection = this.selection.signal;
    this.pollTimer = setInterval(() => void this.poll(selection), POLL_INTERVAL_MS);
  }

  private stopPolling(): void {
    if (this.pollTimer !== null) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
    this.polling.set(false);
  }

  private async poll(token: AbortSignal): Promise<void> {
    // A stale tick belongs to an operation no longer shown. It must not touch
    // the timer either: whoever moved on may have started a new one.
    if (this.stale(token)) {
      return;
    }
    // A read slower than the interval would otherwise overlap the next tick,
    // and the older answer could land last and turn a completed run back into
    // a running one.
    if (this.pollInFlight === token) {
      return;
    }
    this.pollInFlight = token;
    try {
      await this.pollOnce(token);
    } finally {
      if (this.pollInFlight === token) {
        this.pollInFlight = null;
      }
    }
  }

  private async pollOnce(token: AbortSignal): Promise<void> {
    const organizationId = this.organizations.selected()?.id;
    const operation = this.activeOperation();
    if (!organizationId || !operation) {
      this.stopPolling();
      return;
    }
    this.pollAttempts += 1;
    if (this.pollAttempts > MAX_POLL_ATTEMPTS) {
      this.stopPolling();
      this.pollExhausted.set(true);
      return;
    }
    try {
      const next = await this.restores.get(organizationId, operation.id);
      if (this.stale(token)) {
        return;
      }
      this.activeOperation.set(next);
      if (!isRestoreInFlight(next.status)) {
        this.stopPolling();
        await this.afterRun(organizationId, next, token);
        if (this.stale(token)) {
          return;
        }
        // A run that just finished belongs in the rail beside the picker.
        await this.refreshHistory(organizationId);
      }
    } catch {
      // A transient read failure must not leave the page polling a dead URL.
      if (!this.stale(token)) {
        this.stopPolling();
      }
    }
  }

  /** Read the post-run checks, which only a successful run records. */
  private async afterRun(organizationId: string, operation: RestoreOperation, token: AbortSignal): Promise<void> {
    if (operation.status !== 'completed' && operation.status !== 'compensated') {
      return;
    }
    try {
      const verification = await this.restores.verification(organizationId, operation.id);
      if (!this.stale(token)) {
        this.verification.set(verification);
      }
    } catch {
      // Verification is recorded by the worker; a run that never reached it
      // simply leaves the panel out rather than raising a banner.
      if (!this.stale(token)) {
        this.verification.set(null);
      }
    }
  }

  private async refreshHistory(organizationId: string): Promise<void> {
    try {
      await this.loadHistory(organizationId);
    } catch {
      // The rail is a convenience; a failed refresh must not mask the result.
    }
  }

  protected async refreshOperation(): Promise<void> {
    const organizationId = this.organizations.selected()?.id;
    const operation = this.activeOperation();
    if (!organizationId || !operation || this.busy()) {
      return;
    }
    const token = this.selection.signal;
    this.busy.set(true);
    const next = await this.ui.track(
      'Refreshing the restore',
      () => this.restores.get(organizationId, operation.id),
      token,
    );
    if (this.stale(token)) {
      return;
    }
    this.busy.set(false);
    if (!next) {
      return;
    }
    this.activeOperation.set(next);
    if (isRestoreInFlight(next.status)) {
      this.startPolling();
    } else {
      await this.afterRun(organizationId, next, token);
    }
  }

  protected async planCompensation(): Promise<void> {
    const organizationId = this.organizations.selected()?.id;
    const operation = this.activeOperation();
    if (!organizationId || !operation || !this.canAuthorize() || this.busy()) {
      return;
    }
    const token = this.selection.signal;
    this.busy.set(true);
    const plan = await this.ui.track(
      'Planning compensation',
      () => this.restores.planCompensation(organizationId, operation.id),
      token,
    );
    if (this.stale(token)) {
      return;
    }
    this.busy.set(false);
    if (plan) {
      this.compensationPlan.set(plan);
      this.compensating.set(true);
    }
  }

  protected async runCompensation(token: string): Promise<void> {
    const organizationId = this.organizations.selected()?.id;
    const operation = this.activeOperation();
    if (!organizationId || !operation || !this.canAuthorize() || this.busy()) {
      return;
    }
    const generation = this.selection.signal;
    this.busy.set(true);
    const queued = await this.ui.track(
      'Running compensation',
      () => this.restores.executeCompensation(organizationId, operation.id, token),
      generation,
    );
    if (this.stale(generation)) {
      return;
    }
    this.busy.set(false);
    if (!queued) {
      return;
    }
    const current = this.clearOperation();
    this.activeOperation.set(queued);
    this.currentStep.set('execute');
    this.canonicalize(organizationId, queued.id, true);
    if (isRestoreInFlight(queued.status)) {
      this.startPolling();
    } else {
      await this.afterRun(organizationId, queued, current);
    }
  }

  protected cancelCompensation(): void {
    this.compensationPlan.set(null);
    this.compensating.set(false);
  }

  protected restart(): void {
    const organizationId = this.organizations.selected()?.id;
    this.reset();
    if (organizationId) {
      this.canonicalize(organizationId, null);
    }
  }

  // ---- navigation ---------------------------------------------------------

  protected goTo(name: RestoreStepName): void {
    if (!this.stepAvailable(name)) {
      return;
    }
    this.currentStep.set(name);
  }

  private stepAvailable(name: RestoreStepName): boolean {
    if (name === 'targets') {
      return true;
    }
    const operation = this.activeOperation();
    if (!operation) {
      return false;
    }
    if (name === 'plan') {
      return true;
    }
    if (name === 'authorize') {
      // An empty plan has nothing to authorize, and a preflight error means the
      // plan no longer describes the organization it was computed against.
      return this.preflightErrors().length === 0 && (operation.actions ?? []).length > 0;
    }
    return operation.status !== 'planned';
  }

  /**
   * Put the operation's own inputs back into the picker.
   *
   * The requested versions are used as requested, not reconstructed from the
   * action list: that list drops a chosen version already in effect and adds
   * dependencies and forced deletes nobody chose. An operation planned before
   * the inputs were recorded gets an empty selection, which is what makes its
   * mode immutable (see setMode).
   */
  private seedSelection(operation: RestoreOperation): void {
    this.selectedIds.set([...new Set(operation.requested_version_ids ?? [])]);
    const actions = operation.actions ?? [];
    this.rememberLabels(actions.map((action) => [action.source_version_id, action.object_name]));
  }

  /** The rail is a navigation: the URL names the operation, and the page follows it. */
  protected async pickOperation(operationId: string): Promise<void> {
    const organizationId = this.organizations.selected()?.id;
    if (!organizationId) {
      return;
    }
    this.canonicalize(organizationId, operationId);
    await this.openOperation(operationId);
  }

  /**
   * Show one operation in place of whatever was shown.
   *
   * The page is cleared before the read, so a failed read leaves nothing
   * rather than the previous operation frozen under a URL naming this one.
   * Returns whether the operation is on screen and still the current one.
   */
  private async openOperation(operationId: string, compensate = false): Promise<boolean> {
    const organizationId = this.organizations.selected()?.id;
    if (!organizationId) {
      return false;
    }
    const token = this.clearOperation();
    const operation = await this.ui.track(
      'Loading the restore operation',
      () => this.restores.get(organizationId, operationId),
      token,
    );
    if (!operation || this.stale(token)) {
      return false;
    }
    this.activeOperation.set(operation);
    this.mode.set(operation.mode);
    this.includeDependencies.set(operation.include_dependencies);
    // The plan's inputs come back with it: changing the mode rebuilds it from
    // the same versions, and "back to targets" shows what it restores rather
    // than an empty picker.
    this.seedSelection(operation);
    if (isRestoreInFlight(operation.status) || isRestoreTerminal(operation.status)) {
      this.currentStep.set('execute');
      if (isRestoreInFlight(operation.status)) {
        this.startPolling();
      } else {
        await this.afterRun(organizationId, operation, token);
        if (this.stale(token)) {
          return false;
        }
      }
    } else {
      this.currentStep.set('plan');
    }
    if (compensate && this.canAuthorize()) {
      await this.planCompensation();
      if (this.stale(token)) {
        return false;
      }
    }
    return true;
  }

  protected async openImpact(sessionId: string): Promise<void> {
    await this.router.navigate(['/impact'], { queryParams: { session: sessionId } });
  }

  protected async openSnapshot(): Promise<void> {
    // The restored state is the current version of every object it touched, so
    // History opens on its object list. A snapshot is not addressable there
    // yet, and passing its identifier only looked as though it were.
    await this.router.navigate(['/history']);
  }
}

/** The five query parameters the page reads, normalized by `fromQuery`. */
interface DeepLink {
  versions: string;
  changeGroup: string;
  operation: string;
  step: string;
  compensate: string;
}

const EMPTY_LINK: DeepLink = { versions: '', changeGroup: '', operation: '', step: '', compensate: '' };

function linkKey(organizationId: string, link: DeepLink): string {
  return JSON.stringify([
    organizationId,
    link.versions,
    link.changeGroup,
    link.operation,
    link.step,
    link.compensate,
  ]);
}

function isEmptyLink(link: DeepLink): boolean {
  return linkKey('', link) === linkKey('', EMPTY_LINK);
}

function isStepName(value: string): value is RestoreStepName {
  return (STEP_ORDER as readonly string[]).includes(value);
}

function isUnfiltered(query: RestoreTargetQuery): boolean {
  return (
    (query.scope ?? 'all') === 'all' && !query.siteId && !query.objectType && !query.q
  );
}
