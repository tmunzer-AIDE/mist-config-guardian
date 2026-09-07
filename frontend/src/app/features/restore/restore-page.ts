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

/** The targets endpoint caps a page at 200; the picker asks for the whole cap. */
const TARGET_PAGE_SIZE = 200;

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
  private deepLinkApplied = false;

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

  /** True when the filtered match count exceeds the page the picker holds. */
  protected readonly capped = computed(() => this.matched() > this.targets().length);

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
      const query: RestoreTargetQuery = {
        scope: this.scope(),
        siteId: this.siteId() || undefined,
        objectType: this.objectType() || undefined,
        q: this.query() || undefined,
        limit: TARGET_PAGE_SIZE,
      };
      if (!organizationId) {
        return;
      }
      void untracked(() =>
        this.ui.track('Loading restore targets', () => this.loadTargets(organizationId, query)),
      );
    });

    // History and the deep links are independent of the filter row.
    effect(() => {
      const organizationId = this.organizations.selected()?.id;
      this.organizations.revision();
      if (!organizationId) {
        return;
      }
      void untracked(() => this.bootstrap(organizationId));
    });

    inject(DestroyRef).onDestroy(() => this.stopPolling());
  }

  // ---- loading ------------------------------------------------------------

  private async loadTargets(organizationId: string, query: RestoreTargetQuery): Promise<void> {
    const response = await this.restores.targets(organizationId, query);
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

  private async bootstrap(organizationId: string): Promise<void> {
    await this.ui.track('Loading recent restores', () => this.loadHistory(organizationId));
    if (this.deepLinkApplied) {
      return;
    }
    this.deepLinkApplied = true;

    const versionIds = this.versions()
      .split(',')
      .map((value) => value.trim())
      .filter((value) => value.length > 0);
    if (versionIds.length > 0) {
      this.selectedIds.set(versionIds);
    }

    const group = this.changeGroup();
    if (group) {
      await this.ui.track('Loading the change group', () =>
        this.applyChangeGroup(organizationId, group),
      );
    }

    const operationId = this.operation();
    if (operationId) {
      await this.openOperation(operationId, this.compensate() === '1');
    }

    const requested = this.step();
    if (isStepName(requested) && this.stepAvailable(requested)) {
      this.currentStep.set(requested);
    }
  }

  /**
   * Pre-select the versions a change group replaced.
   *
   * Restoring "what this change group did" means going back to the version each
   * object held before it, which is not the version the picker lists — the
   * picker offers the newest version of every object. The selection is therefore
   * carried by id, with the label taken from the group's own object list.
   */
  private async applyChangeGroup(organizationId: string, groupId: string): Promise<void> {
    const detail = await this.changeGroups.load(organizationId, groupId);
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
    const response = await this.restores.list(organizationId, 0, 10);
    this.history.set(response.items ?? []);
  }

  // ---- step 1 -------------------------------------------------------------

  protected setScope(scope: TargetScope): void {
    this.scope.set(scope);
    if (scope !== 'site') {
      this.siteId.set('');
    }
  }

  protected setSite(siteId: string): void {
    this.siteId.set(siteId);
  }

  protected setType(objectType: string): void {
    this.objectType.set(objectType);
  }

  protected setQuery(query: string): void {
    this.query.set(query.trim());
  }

  protected clearFilters(): void {
    this.scope.set('all');
    this.siteId.set('');
    this.objectType.set('');
    this.query.set('');
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
    this.mode.set(mode);
    // The plan is mode-specific: an exact plan may delete objects a
    // non-destructive plan leaves alone, so the old action list cannot stand.
    if (this.activeOperation() && this.currentStep() !== 'targets') {
      void this.buildPlan();
      return;
    }
    this.invalidatePlan();
  }

  protected setIncludeDependencies(include: boolean): void {
    this.includeDependencies.set(include);
    this.invalidatePlan();
  }

  private invalidatePlan(): void {
    this.stopPolling();
    this.activeOperation.set(null);
    this.verification.set(null);
    this.compensationPlan.set(null);
    this.compensating.set(false);
    if (this.currentStep() !== 'targets') {
      this.currentStep.set('targets');
    }
  }

  // ---- step 2 -------------------------------------------------------------

  protected async buildPlan(): Promise<void> {
    const organizationId = this.organizations.selected()?.id;
    const versionIds = this.selectedIds();
    if (!organizationId || versionIds.length === 0 || this.readOnly() || this.busy()) {
      return;
    }
    this.busy.set(true);
    const operation = await this.ui.track('Building a side-effect-free plan', () =>
      this.restores.createPlan(organizationId, versionIds, this.mode(), this.includeDependencies()),
    );
    this.busy.set(false);
    if (!operation) {
      return;
    }
    this.activeOperation.set(operation);
    this.verification.set(null);
    this.currentStep.set('plan');
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
    this.busy.set(true);
    const queued = await this.ui.track('Authorizing the restore', () =>
      this.restores.execute(organizationId, operation.id, token),
    );
    this.busy.set(false);
    if (!queued) {
      return;
    }
    this.activeOperation.set(queued);
    this.currentStep.set('execute');
    if (isRestoreInFlight(queued.status)) {
      this.startPolling();
    } else {
      await this.afterRun(organizationId, queued);
    }
  }

  protected async requestApproval(): Promise<void> {
    const organizationId = this.organizations.selected()?.id;
    const operation = this.activeOperation();
    if (!organizationId || !operation || this.readOnly() || this.busy()) {
      return;
    }
    this.busy.set(true);
    const approval = await this.ui.track('Requesting approval', () =>
      this.restores.requestApproval(organizationId, operation.id),
    );
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
    this.busy.set(true);
    const fresh = await this.ui.track('Checking the approval', () =>
      this.restores.approval(organizationId, approval.id),
    );
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
    this.pollTimer = setInterval(() => void this.poll(), POLL_INTERVAL_MS);
  }

  private stopPolling(): void {
    if (this.pollTimer !== null) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
    this.polling.set(false);
  }

  private async poll(): Promise<void> {
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
      this.activeOperation.set(next);
      if (!isRestoreInFlight(next.status)) {
        this.stopPolling();
        await this.afterRun(organizationId, next);
        // A run that just finished belongs in the rail beside the picker.
        await this.refreshHistory(organizationId);
      }
    } catch {
      // A transient read failure must not leave the page polling a dead URL.
      this.stopPolling();
    }
  }

  /** Read the post-run checks, which only a successful run records. */
  private async afterRun(organizationId: string, operation: RestoreOperation): Promise<void> {
    if (operation.status !== 'completed' && operation.status !== 'compensated') {
      return;
    }
    try {
      this.verification.set(await this.restores.verification(organizationId, operation.id));
    } catch {
      // Verification is recorded by the worker; a run that never reached it
      // simply leaves the panel out rather than raising a banner.
      this.verification.set(null);
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
    this.busy.set(true);
    const next = await this.ui.track('Refreshing the restore', () =>
      this.restores.get(organizationId, operation.id),
    );
    this.busy.set(false);
    if (!next) {
      return;
    }
    this.activeOperation.set(next);
    if (isRestoreInFlight(next.status)) {
      this.startPolling();
    } else {
      await this.afterRun(organizationId, next);
    }
  }

  protected async planCompensation(): Promise<void> {
    const organizationId = this.organizations.selected()?.id;
    const operation = this.activeOperation();
    if (!organizationId || !operation || !this.canAuthorize() || this.busy()) {
      return;
    }
    this.busy.set(true);
    const plan = await this.ui.track('Planning compensation', () =>
      this.restores.planCompensation(organizationId, operation.id),
    );
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
    this.busy.set(true);
    const queued = await this.ui.track('Running compensation', () =>
      this.restores.executeCompensation(organizationId, operation.id, token),
    );
    this.busy.set(false);
    if (!queued) {
      return;
    }
    this.activeOperation.set(queued);
    this.compensationPlan.set(null);
    this.compensating.set(false);
    if (isRestoreInFlight(queued.status)) {
      this.startPolling();
    } else {
      await this.afterRun(organizationId, queued);
    }
  }

  protected cancelCompensation(): void {
    this.compensationPlan.set(null);
    this.compensating.set(false);
  }

  protected restart(): void {
    this.selectedIds.set([]);
    this.invalidatePlan();
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

  protected async openOperation(operationId: string, compensate = false): Promise<void> {
    const organizationId = this.organizations.selected()?.id;
    if (!organizationId) {
      return;
    }
    const operation = await this.ui.track('Loading the restore operation', () =>
      this.restores.get(organizationId, operationId),
    );
    if (!operation) {
      return;
    }
    this.activeOperation.set(operation);
    this.mode.set(operation.mode);
    this.includeDependencies.set(operation.include_dependencies);
    this.compensationPlan.set(null);
    this.compensating.set(false);
    if (isRestoreInFlight(operation.status) || isRestoreTerminal(operation.status)) {
      this.currentStep.set('execute');
      if (isRestoreInFlight(operation.status)) {
        this.startPolling();
      } else {
        await this.afterRun(organizationId, operation);
      }
    } else {
      this.currentStep.set('plan');
    }
    if (compensate && this.canAuthorize()) {
      await this.planCompensation();
    }
  }

  protected async openImpact(sessionId: string): Promise<void> {
    await this.router.navigate(['/impact'], { queryParams: { session: sessionId } });
  }

  protected async openSnapshot(snapshotId: string): Promise<void> {
    await this.router.navigate(['/history'], { queryParams: { snapshot: snapshotId } });
  }
}

function isStepName(value: string): value is RestoreStepName {
  return (STEP_ORDER as readonly string[]).includes(value);
}

function isUnfiltered(query: RestoreTargetQuery): boolean {
  return (
    (query.scope ?? 'all') === 'all' && !query.siteId && !query.objectType && !query.q
  );
}
