import { ChangeDetectionStrategy, Component, computed, effect, inject, signal, untracked } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { RestorePage } from '../restore/restore-page';
import { ObjectFacets } from './history.model';
import { ActivatedRoute, Router } from '@angular/router';

import { AuthService } from '../../core/auth.service';
import { formatInstant } from '../../core/format';
import { OrganizationContextService } from '../../core/organization-context.service';
import { TimeContextService } from '../../core/time-context.service';
import { Tone } from '../../core/tone';
import { UiStateService } from '../../core/ui-state.service';
import { AiAssistStrip, AiState } from './ai-assist-strip';
import {
  AI_DISCLAIMER,
  AI_QUESTION_MAX_LENGTH,
  AiAssistService,
  AiDiffSummary,
  formatDurationMs,
} from './ai-assist.service';
import {
  ChangeCard,
  DiffPanel,
  NotableFinding,
  RawRow,
  SectionView,
} from './diff-panel';
import {
  ConfigurationDiff,
  DiffEntry,
  DiffExportFormat,
  DiffSection,
  diffValue,
  entryTone,
  RawConfigurationDiff,
  renderDocument,
  SECTION_PAGE_SIZE,
  sectionCountLabel,
} from './diff.model';
import { DiffService } from './diff.service';
import {
  ConfigurationObject,
  ConfigurationVersion,
  eventTone,
  objectGroupLabel,
  objectKindLabel,
  shortMistId,
} from './history.model';
import { HistoryService } from './history.service';

/** Which end of the comparison a version is pinned to. */
/** Objects fetched per read of the rail. */
const OBJECT_PAGE_SIZE = 50;

/** How long typing pauses before the term is sent to the server. */
const SEARCH_DEBOUNCE_MS = 250;

export type AbSlot = 'a' | 'b';

interface ObjectRow {
  id: string;
  name: string;
  version: string;
  meta: string;
  deleted: boolean;
  selected: boolean;
}

interface ObjectGroup {
  label: string;
  items: ObjectRow[];
}

interface VersionRow {
  id: string;
  label: string;
  event: string;
  tone: Tone;
  at: string;
  actor: string;
  isA: boolean;
  isB: boolean;
}

/**
 * Configuration history: objects, their captured versions, and the deterministic
 * comparison between any two of them.
 *
 * Everything on this page except the AI assist strip is computed by the API, so
 * an unconfigured or failing AI endpoint degrades to a quiet inline note and
 * never blocks the comparison or reaches the shell error banner.
 */
@Component({
  selector: 'app-history-page',
  imports: [AiAssistStrip, DiffPanel, RestorePage],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './history-page.html',
  styleUrl: './history-page.scss',
  host: { '(document:keydown)': 'onKeydown($event)' },
})
export class HistoryPage {
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly ui = inject(UiStateService);
  private readonly organizations = inject(OrganizationContextService);
  private readonly auth = inject(AuthService);
  private readonly history = inject(HistoryService);
  private readonly diffs = inject(DiffService);
  private readonly ai = inject(AiAssistService);
  protected readonly time = inject(TimeContextService);

  protected readonly questionMaxLength = AI_QUESTION_MAX_LENGTH;
  protected readonly objectPageSize = OBJECT_PAGE_SIZE;

  protected readonly library = signal(!this.route.snapshot.queryParamMap.has('object'));
  protected readonly routeParams = toSignal(this.route.queryParamMap, { initialValue: this.route.snapshot.queryParamMap });
  protected readonly restoreOpen = computed(() => this.auth.can('operator') && (
    this.routeParams().get('restore') === '1' || this.routeParams().has('operation') ||
    this.routeParams().has('versions') || this.routeParams().has('changeGroup')
  ));
  protected readonly facets = signal<ObjectFacets>({ types: [], sites: [] });
  protected readonly typeFilter = signal('');
  protected readonly siteFilter = signal('');
  protected readonly scopeFilter = signal<'' | 'org' | 'site'>('');
  private facetRequest = 0;
  protected readonly catalogue = computed(() => this.objects().map(object => ({
    ...object,
    typeLabel: object.object_type.replaceAll('_', ' '),
    siteLabel: object.scope === 'org' ? 'Organization' : this.facets().sites.find(site => site.id === object.site_mist_id)?.name ?? object.site_mist_id ?? 'Unknown site',
    updated: formatInstant(new Date(object.updated_at)),
  })));

  protected setFilter(kind: 'type' | 'site' | 'scope', event: Event): void {
    const value = (event.target as HTMLSelectElement).value;
    if (kind === 'type') this.typeFilter.set(value);
    if (kind === 'site') this.siteFilter.set(value);
    if (kind === 'scope') this.scopeFilter.set(value as '' | 'org' | 'site');
  }

  protected async browseObjects(): Promise<void> {
    this.library.set(true);
    await this.closeRestore();
  }

  protected async closeRestore(): Promise<void> {
    await this.router.navigate(['/history'], { queryParamsHandling: 'merge', queryParams: {
      restore: null, versions: null, operation: null, changeGroup: null, step: null, compensate: null,
    } });
  }

  protected async restoreActivity(): Promise<void> {
    await this.router.navigate(['/history'], { queryParamsHandling: 'merge', queryParams: {
      restore: '1', versions: null, operation: null, changeGroup: null, step: null, compensate: null,
    } });
  }

  // ------------------------------------------------------------------ state
  /** What is in the search box right now. */
  protected readonly query = signal('');
  /**
   * The term the list on screen was read for.
   *
   * Searching is server-side — the rail holds one page, not the catalogue, so
   * a term the browser could filter against would only ever find what had
   * already been fetched. It trails `query` by a keystroke pause so typing a
   * word is one request rather than one per letter.
   */
  private readonly searchTerm = signal('');
  private searchDebounce: ReturnType<typeof setTimeout> | null = null;
  protected readonly showDeleted = signal(false);
  protected readonly objectsLoaded = signal(false);
  /** Objects matching the current filters, which is more than the rail holds. */
  protected readonly objectsTotal = signal(0);
  protected readonly loadingMore = signal(false);

  private readonly objects = signal<ConfigurationObject[]>([]);
  /**
   * The selected object when the loaded page does not contain it.
   *
   * The rail is one page of many, so the object being compared can sit outside
   * it — a link naming one that sorts later, or a search that hides it. The
   * comparison is still labelled from this.
   */
  private readonly offPageObject = signal<ConfigurationObject | null>(null);
  /** The id being resolved right now, so a re-run cannot ask for it twice. */
  private resolvingObjectId: string | null = null;
  /**
   * Bumped whenever an object resolution starts or is abandoned.
   *
   * Every write the resolver makes is checked against it, so an answer for an
   * object nobody is looking at any more — including a failure, which has no
   * value of its own to compare — cannot touch what is on screen.
   */
  private objectDetailRequest = 0;
  private readonly versions = signal<ConfigurationVersion[]>([]);
  protected readonly selectedObjectId = signal<string | null>(null);
  private objectsRequest = 0;
  /** The organization the object list was last read for; selections are valid only under it. */
  private loadedOrganization: string | null = null;
  protected readonly versionAId = signal<string | null>(null);
  protected readonly versionBId = signal<string | null>(null);

  private readonly diff = signal<ConfigurationDiff | null>(null);
  private readonly notableEntries = signal<DiffEntry[]>([]);
  /** Section key to its entry bodies, filled in as sections are opened. */
  private readonly sectionEntries = signal<Record<string, DiffEntry[]>>({});
  private readonly expandedSections = signal<Record<string, boolean>>({});
  protected readonly diffLoading = signal(false);
  protected readonly openSection = signal<string | null>(null);
  protected readonly loadingSection = signal<string | null>(null);

  protected readonly raw = signal<RawConfigurationDiff | null>(null);
  protected readonly rawExpanded = signal(false);
  protected readonly rawLoading = signal(false);

  protected readonly exportOpen = signal(false);
  protected readonly exporting = signal(false);

  protected readonly aiState = signal<AiState>('idle');
  protected readonly aiSummary = signal<AiDiffSummary | null>(null);
  protected readonly aiNote = signal('');
  protected readonly question = signal('');
  protected readonly answer = signal<string | null>(null);
  protected readonly asking = signal(false);

  /** Bumped on every pair change so a stale in-flight response cannot land. */
  private diffToken = 0;

  // -------------------------------------------------------------- selections
  protected readonly objectGroups = computed<ObjectGroup[]>(() => {
    // Every object held has already been matched by the server, so grouping is
    // all that is left to do here.
    const selected = this.selectedObjectId();
    const groups = new Map<string, ObjectRow[]>();
    for (const object of this.objects()) {
      const label = objectGroupLabel(object);
      const rows = groups.get(label) ?? [];
      rows.push({
        id: object.id,
        name: object.name,
        version: `v${object.current_version}`,
        meta: objectMeta(object),
        deleted: object.is_deleted,
        selected: object.id === selected,
      });
      groups.set(label, rows);
    }
    return [...groups.entries()].map(([label, items]) => ({ label, items }));
  });

  protected readonly noObjects = computed(
    () => this.objectsLoaded() && this.objectsTotal() === 0 && this.searchTerm() === '',
  );
  protected readonly noMatches = computed(
    () => this.objectsLoaded() && this.objectsTotal() === 0 && this.searchTerm() !== '',
  );
  protected readonly hasMoreObjects = computed(() => this.objects().length < this.objectsTotal());
  /** "Showing n of N", so a partial rail never reads as the whole catalogue. */
  protected readonly objectCountLabel = computed(
    () => `Showing ${this.objects().length} of ${this.objectsTotal()}`,
  );

  protected readonly selectedObject = computed(() => {
    const id = this.selectedObjectId();
    if (id === null) {
      return null;
    }
    return (
      this.objects().find((object) => object.id === id) ??
      (this.offPageObject()?.id === id ? this.offPageObject() : null)
    );
  });

  protected readonly objectKind = computed(() => {
    const object = this.selectedObject();
    return object ? `${objectKindLabel(object)} · ${shortMistId(object.current_mist_id)}` : '';
  });

  protected readonly versionRows = computed<VersionRow[]>(() => {
    const a = this.versionAId();
    const b = this.versionBId();
    return this.versions().map((version) => ({
      id: version.id,
      label: `v${version.version}`,
      event: version.event.toUpperCase(),
      tone: eventTone(version.event),
      at: formatInstant(new Date(version.observed_at)),
      actor: version.actor ?? 'system',
      isA: version.id === a,
      isB: version.id === b,
    }));
  });

  protected readonly pairA = computed(() => this.pairLabel('A', this.versionAId()));
  protected readonly pairB = computed(() => this.pairLabel('B', this.versionBId()));

  // -------------------------------------------------------------- comparison
  protected readonly hasDiff = computed(() => this.diff() !== null);
  protected readonly counts = computed(() => this.diff()?.counts ?? null);
  /** The API's own summary line; the page never recomputes the arithmetic. */
  protected readonly summary = computed(() => this.diff()?.summary ?? '');
  protected readonly truncated = computed(() => this.diff()?.truncated ?? false);

  /** The API decides between compact change cards and the sectioned view. */
  protected readonly isCompact = computed(() => this.diff()?.mode === 'chips');
  protected readonly isSectioned = computed(() => this.diff()?.mode === 'sections');

  protected readonly changeCards = computed<ChangeCard[]>(() =>
    (this.diff()?.entries ?? []).map((entry, index) => ({
      key: `${entry.field}:${index}`,
      field: entry.field,
      before: diffValue(entry.before),
      after: diffValue(entry.after),
      note: entry.note,
      secret: entry.secret || entry.secret_unknown,
    })),
  );

  protected readonly notable = computed<NotableFinding[]>(() =>
    this.notableEntries().map((entry, index) => ({
      key: `${entry.field}:${index}`,
      kind: entry.kind,
      tone: entryTone(entry.kind),
      field: entry.field,
      note: entry.note,
    })),
  );

  protected readonly sections = computed<SectionView[]>(() => {
    const diff = this.diff();
    if (!diff) {
      return [];
    }
    const cache = this.sectionEntries();
    const expanded = this.expandedSections();
    const open = this.openSection();
    const loading = this.loadingSection();
    return diff.sections.map((section) => {
      const entries = entriesOf(section, cache);
      const loaded = section.entries_included || section.key in cache;
      const visible = expanded[section.key] ? entries : entries.slice(0, SECTION_PAGE_SIZE);
      const hidden = entries.length - visible.length;
      return {
        key: section.key,
        name: section.name,
        path: section.path,
        changed: section.counts.changed,
        countLabel: sectionCountLabel(section),
        notable: section.notable,
        open: open === section.key,
        loading: loading === section.key,
        loaded,
        rows: visible.map((entry, index) => ({
          key: `${section.key}:${entry.field}:${index}`,
          field: entry.field,
          kind: entry.secret_unknown ? 'PROTECTED' : entry.kind,
          tone: entry.secret ? 'none' : entryTone(entry.kind),
          before: diffValue(entry.before),
          after: diffValue(entry.after),
          removed: entry.kind === 'REMOVED',
        })),
        more: hidden > 0 ? `Show ${hidden} more ${hidden === 1 ? 'change' : 'changes'} in ${section.name}` : '',
      };
    });
  });

  protected readonly rawLabel = computed(() => {
    const lines = this.raw()?.line_count ?? null;
    const count = lines === null ? '' : `${lines} lines · `;
    return `RAW JSON · ${count}side by side, secrets redacted`;
  });

  protected readonly rawRows = computed<RawRow[]>(() => {
    const raw = this.raw();
    if (!raw) {
      return [];
    }
    const before = renderDocument(raw.before);
    const after = renderDocument(raw.after);
    const length = Math.max(before.length, after.length);
    return Array.from({ length }, (_, index) => ({
      index: index + 1,
      before: before[index] ?? '',
      after: after[index] ?? '',
    }));
  });

  // ---------------------------------------------------------------------- ai
  protected readonly aiOffered = computed(
    () => this.ai.availability() !== 'disabled' && this.aiState() !== 'unavailable',
  );

  protected readonly aiPrompt = computed(() => {
    const changed = this.counts()?.changed ?? 0;
    return changed > 0 ? `Summarise these ${changed} changes` : 'Summarise this version';
  });

  /** The API's disclaimer once it has answered; its own wording before that. */
  protected readonly disclaimer = computed(() => this.aiSummary()?.disclaimer ?? AI_DISCLAIMER);

  protected readonly aiMeta = computed(() => {
    const summary = this.aiSummary();
    if (!summary) {
      return '';
    }
    const changed = this.counts()?.changed ?? 0;
    const took = summary.cached ? 'cache' : formatDurationMs(summary.duration_ms);
    return `Summarised ${changed} ${changed === 1 ? 'change' : 'changes'} in ${took} · ${summary.model}`;
  });

  protected readonly canAsk = computed(
    () => !this.asking() && this.question().trim().length >= 3 && this.aiState() === 'generated',
  );

  // ------------------------------------------------------------------ rights
  protected readonly restorable = computed(() => this.auth.can('operator'));
  protected readonly canRestore = computed(
    () => this.restorable() && !this.time.isHistorical() && this.versionBId() !== null,
  );

  constructor() {
    effect(() => {
      const organizationId = this.organizations.selected()?.id;
      const includeDeleted = this.showDeleted();
      const request = ++this.facetRequest;
      if (!organizationId) return;
      untracked(() => {
        void this.history.facets(organizationId, includeDeleted).then(facets => {
          if (request === this.facetRequest) this.facets.set(facets);
        }).catch(() => { if (request === this.facetRequest) this.facets.set({types: [], sites: []}); });
      });
    });
    const params = this.route.snapshot.queryParamMap;
    this.selectedObjectId.set(params.get('object'));
    this.versionAId.set(params.get('a'));
    this.versionBId.set(params.get('b'));

    void this.ai.loadSettings();

    effect(() => {
      const organizationId = this.organizations.selected()?.id;
      const includeDeleted = this.showDeleted();
      const term = this.searchTerm();
      this.typeFilter();
      this.siteFilter();
      this.scopeFilter();
      this.organizations.revision();
      if (!organizationId) {
        return;
      }
      untracked(() => {
        if (this.loadedOrganization !== null && this.loadedOrganization !== organizationId) {
          // The object and versions on screen belong to the organization they
          // were read from; under another they are identifiers of nothing, and
          // reads for them can only fail. They go before the new list is asked for.
          this.resetSelection();
          this.siteFilter.set('');
          this.library.set(true);
        }
        this.loadedOrganization = organizationId;
        void this.ui.track('Loading configuration objects', () =>
          this.loadObjects(organizationId, includeDeleted, term, 0),
        );
      });
    });

    effect(() => {
      const organizationId = this.organizations.selected()?.id;
      const objectId = this.selectedObjectId();
      // A selection is read only under the organization it was made in.
      if (!organizationId || !objectId || this.loadedOrganization !== organizationId) {
        return;
      }
      void untracked(() => this.loadVersions(organizationId, objectId));
    });

    // Resolving the compared object is its own effect because it depends on
    // the rail as well as the selection: a search or a later page can stop
    // holding the object without the selection changing, and the comparison
    // panel is named from it. Tracking this alongside the version read would
    // re-read the versions on every page of the rail.
    effect(() => {
      const organizationId = this.organizations.selected()?.id;
      const objectId = this.selectedObjectId();
      const loaded = this.objects();
      if (!organizationId || !objectId || this.loadedOrganization !== organizationId) {
        return;
      }
      void untracked(() => this.resolveOffPageObject(organizationId, objectId, loaded));
    });

    effect(() => {
      const organizationId = this.organizations.selected()?.id;
      const from = this.versionAId();
      const to = this.versionBId();
      if (!organizationId || !from || !to || this.loadedOrganization !== organizationId) {
        return;
      }
      void untracked(() => this.loadDiff(organizationId, from, to));
    });

    // Reflect the selection into the URL so any comparison can be linked to.
    effect(() => {
      const object = this.selectedObjectId();
      const a = this.versionAId();
      const b = this.versionBId();
      if (!object) {
        return;
      }
      void untracked(() =>
        this.router.navigate([], {
          relativeTo: this.route,
          queryParams: { object, a, b },
          queryParamsHandling: 'merge',
          replaceUrl: true,
        }),
      );
    });
  }

  // ----------------------------------------------------------------- objects

  protected setQuery(event: Event): void {
    const value = (event.target as HTMLInputElement).value;
    this.query.set(value);
    if (this.searchDebounce !== null) {
      clearTimeout(this.searchDebounce);
    }
    this.searchDebounce = setTimeout(() => {
      this.searchDebounce = null;
      this.searchTerm.set(value.trim());
    }, SEARCH_DEBOUNCE_MS);
  }

  /** Fetch the next page and append it, keeping what is already on screen. */
  protected async loadMoreObjects(): Promise<void> {
    const organizationId = this.organizations.selected()?.id;
    if (!organizationId || this.loadingMore() || !this.hasMoreObjects()) {
      return;
    }
    this.loadingMore.set(true);
    try {
      await this.loadObjects(
        organizationId,
        this.showDeleted(),
        this.searchTerm(),
        this.objects().length,
      );
    } finally {
      this.loadingMore.set(false);
    }
  }

  protected toggleDeleted(): void {
    this.showDeleted.update((value) => !value);
  }

  protected selectObject(id: string): void {
    this.library.set(false);
    if (id === this.selectedObjectId()) {
      return;
    }
    this.resetSelection();
    this.selectedObjectId.set(id);
  }

  private resetSelection(): void {
    this.discardObjectResolution();
    this.versions.set([]);
    this.versionAId.set(null);
    this.versionBId.set(null);
    this.clearDiff();
    this.selectedObjectId.set(null);
  }

  // ---------------------------------------------------------------- versions

  /** Pin one version to A or B; pinning over the other end swaps the two. */
  protected pin(slot: AbSlot, versionId: string): void {
    if (slot === 'a') {
      if (versionId === this.versionBId()) {
        this.versionBId.set(this.versionAId());
      }
      this.versionAId.set(versionId);
      return;
    }
    if (versionId === this.versionAId()) {
      this.versionAId.set(this.versionBId());
    }
    this.versionBId.set(versionId);
  }

  /**
   * `j` and `k` walk the comparison through the version rail: B moves, and A
   * follows one step older so the pair stays "newest is B, previous is A".
   */
  protected onKeydown(event: KeyboardEvent): void {
    if (event.key === 'Escape' && this.exportOpen()) {
      this.exportOpen.set(false);
      return;
    }
    if (this.library() || this.restoreOpen() || (event.key !== 'j' && event.key !== 'k')) {
      return;
    }
    if (event.metaKey || event.ctrlKey || event.altKey || isEditable(event.target)) {
      return;
    }
    if (this.moveSelection(event.key === 'j' ? 1 : -1)) {
      event.preventDefault();
    }
  }

  private moveSelection(delta: 1 | -1): boolean {
    const rows = this.versions();
    if (rows.length < 2) {
      return false;
    }
    const current = rows.findIndex((version) => version.id === this.versionBId());
    const from = current < 0 ? 0 : current;
    const next = Math.min(rows.length - 2, Math.max(0, from + delta));
    if (next === current) {
      return false;
    }
    this.versionBId.set(rows[next].id);
    this.versionAId.set(rows[next + 1].id);
    return true;
  }

  // -------------------------------------------------------------- comparison

  /** Open a section, fetching its entry bodies the first time it is needed. */
  protected async toggleSection(key: string): Promise<void> {
    if (this.openSection() === key) {
      this.openSection.set(null);
      return;
    }
    this.openSection.set(key);
    await this.ensureSection(key);
  }

  protected expandSection(key: string): void {
    this.expandedSections.update((current) => ({ ...current, [key]: true }));
  }

  private async ensureSection(key: string): Promise<void> {
    const section = this.diff()?.sections.find((item) => item.key === key);
    if (!section || section.entries_included || key in this.sectionEntries()) {
      return;
    }
    const organizationId = this.organizations.selected()?.id;
    const from = this.versionAId();
    const to = this.versionBId();
    if (!organizationId || !from || !to) {
      return;
    }
    const token = this.diffToken;
    this.loadingSection.set(key);
    try {
      const response = await this.diffs.compare(organizationId, from, to, { sections: [key] });
      if (token !== this.diffToken) {
        return;
      }
      this.sectionEntries.update((current) => ({ ...current, ...indexSections(response.sections) }));
      if (response.notable.length > 0) {
        this.notableEntries.set(response.notable);
      }
    } catch (cause) {
      this.ui.fail(cause, 'Loading the section detail');
    } finally {
      if (this.loadingSection() === key) {
        this.loadingSection.set(null);
      }
    }
  }

  protected async toggleRaw(): Promise<void> {
    const next = !this.rawExpanded();
    this.rawExpanded.set(next);
    if (!next || this.raw()) {
      return;
    }
    const organizationId = this.organizations.selected()?.id;
    const from = this.versionAId();
    const to = this.versionBId();
    if (!organizationId || !from || !to) {
      return;
    }
    const token = this.diffToken;
    this.rawLoading.set(true);
    try {
      const response = await this.diffs.raw(organizationId, from, to);
      if (token === this.diffToken) {
        this.raw.set(response);
      }
    } catch (cause) {
      this.ui.fail(cause, 'Loading the raw comparison');
    } finally {
      this.rawLoading.set(false);
    }
  }

  protected toggleExport(): void {
    this.exportOpen.update((value) => !value);
  }

  protected async exportDiff(format: DiffExportFormat): Promise<void> {
    this.exportOpen.set(false);
    const organizationId = this.organizations.selected()?.id;
    const from = this.versionAId();
    const to = this.versionBId();
    if (!organizationId || !from || !to) {
      return;
    }
    this.exporting.set(true);
    try {
      const blob = await this.diffs.export(organizationId, from, to, format);
      const stem = (this.selectedObject()?.name ?? 'comparison').replace(/[^A-Za-z0-9._-]+/g, '-');
      download(blob, format === 'patch' ? `${stem}.patch.json` : `${stem}.diff.json`);
    } catch (cause) {
      this.ui.fail(cause, 'Exporting the comparison');
    } finally {
      this.exporting.set(false);
    }
  }

  protected async restoreVersion(selectedVersionId?: string): Promise<void> {
    const versionId = selectedVersionId ?? this.versionBId();
    if (!versionId || !this.canRestore()) {
      return;
    }
    await this.router.navigate(['/history'], { queryParamsHandling: 'merge', queryParams: { restore: '1', versions: versionId, operation: null } });
  }

  protected async openAiSettings(): Promise<void> {
    await this.router.navigate(['/settings'], { queryParams: { tab: 'ai' } });
  }

  // ---------------------------------------------------------------------- ai

  protected async runAi(regenerate: boolean): Promise<void> {
    const organizationId = this.organizations.selected()?.id;
    const from = this.versionAId();
    const to = this.versionBId();
    if (!organizationId || !from || !to || this.aiState() === 'generating') {
      return;
    }
    const token = this.diffToken;
    this.aiState.set('generating');
    this.aiNote.set('');
    const outcome = await this.ai.summarise({
      organization_id: organizationId,
      from_version_id: from,
      to_version_id: to,
      regenerate,
    });
    if (token !== this.diffToken) {
      return;
    }
    if (outcome.status === 'ok') {
      this.aiSummary.set(outcome.value);
      this.aiState.set('generated');
      return;
    }
    this.aiSummary.set(null);
    // Advisory only: a refusal or a provider failure is an inline note, never
    // the shell error banner, and never blocks the computed comparison.
    this.aiState.set(outcome.status === 'unavailable' ? 'unavailable' : 'failed');
    this.aiNote.set(`${outcome.message} The comparison below is computed and unaffected.`);
  }

  protected setQuestion(event: Event): void {
    this.question.set((event.target as HTMLInputElement).value);
  }

  protected async ask(): Promise<void> {
    const question = this.question().trim();
    const organizationId = this.organizations.selected()?.id;
    const from = this.versionAId();
    const to = this.versionBId();
    if (!this.canAsk() || !organizationId || !from || !to) {
      return;
    }
    const token = this.diffToken;
    this.asking.set(true);
    const outcome = await this.ai.followUp({
      organization_id: organizationId,
      from_version_id: from,
      to_version_id: to,
      question,
    });
    if (token !== this.diffToken) {
      return;
    }
    this.asking.set(false);
    if (outcome.status === 'ok') {
      this.answer.set(outcome.value.answer);
      this.question.set('');
      return;
    }
    this.answer.set(null);
    if (outcome.status === 'unavailable') {
      this.aiSummary.set(null);
      this.aiState.set('unavailable');
    }
    this.aiNote.set(`${outcome.message} The comparison below is computed and unaffected.`);
  }

  // ---------------------------------------------------------------- loading

  /**
   * Read one page of objects.
   *
   * `skip` of zero replaces the rail — a new organization, filter, or search
   * term — and anything else appends the next page to what is already shown.
   */
  private async loadObjects(
    organizationId: string,
    includeDeleted: boolean,
    term: string,
    skip: number,
  ): Promise<void> {
    const request = ++this.objectsRequest;
    const response = await this.history.objects(organizationId, {
      includeDeleted,
      objectType: this.typeFilter() || undefined,
      siteId: this.siteFilter() || undefined,
      scope: this.scopeFilter() || undefined,
      q: term || undefined,
      skip,
      limit: OBJECT_PAGE_SIZE,
    });
    // A slow answer for a previous organization, filter, or term must not
    // replace the list on screen.
    if (request !== this.objectsRequest) {
      return;
    }
    const items = skip === 0 ? response.items : [...this.objects(), ...response.items];
    this.objects.set(items);
    this.objectsTotal.set(response.total ?? items.length);
    this.objectsLoaded.set(true);
    // Appending must not move the selection: the object being compared is the
    // reason the rest of the page is on screen.
    if (skip > 0) {
      return;
    }
    // Only an empty selection is filled in. The rail holds one page of many, so
    // an object missing from it is no longer an object that does not exist: a
    // deep link can name one that sorts past this page, and a search can hide
    // the object being compared without meaning to end the comparison. An id
    // that names nothing surfaces as a failed version read, which is a better
    // answer than quietly opening a different object.
    if (this.selectedObjectId() !== null) {
      return;
    }
    const first = items[0]?.id ?? null;
    if (first !== null) {
      // Through the same path a click takes, so the versions, pins and diff of
      // whatever was shown before cannot outlive the object they describe.
      this.resetSelection();
      this.selectedObjectId.set(first);
    }
  }

  /**
   * Resolve a selected object the loaded page does not hold.
   *
   * Nothing is fetched while the rail already describes it, which is the usual
   * case. A failure is left silent: the comparison itself is driven by the
   * version reads, and those report their own errors rather than raising a
   * second banner for the same missing object.
   */
  private async resolveOffPageObject(
    organizationId: string,
    objectId: string,
    loaded: ConfigurationObject[],
  ): Promise<void> {
    if (loaded.some((object) => object.id === objectId)) {
      this.discardObjectResolution();
      return;
    }
    // This runs again whenever the rail changes, which can happen while the
    // read it already started is still in flight.
    if (this.offPageObject()?.id === objectId || this.resolvingObjectId === objectId) {
      return;
    }
    const request = ++this.objectDetailRequest;
    this.resolvingObjectId = objectId;
    try {
      const object = await this.history.object(organizationId, objectId);
      // The rail may have caught up with the object while this was in flight,
      // in which case it describes it and this copy is not needed.
      if (request === this.objectDetailRequest && !this.objects().some((item) => item.id === objectId)) {
        this.offPageObject.set(object);
      }
    } catch {
      if (request === this.objectDetailRequest) {
        this.offPageObject.set(null);
      }
    } finally {
      // Keyed on the read, not on the object: a later read for the same id
      // owns the marker by now, and clearing it would let a third go out.
      if (request === this.objectDetailRequest) {
        this.resolvingObjectId = null;
      }
    }
  }

  /** Forget the resolved object, and disown any read still in flight. */
  private discardObjectResolution(): void {
    this.objectDetailRequest += 1;
    this.resolvingObjectId = null;
    this.offPageObject.set(null);
  }

  private async loadVersions(organizationId: string, objectId: string): Promise<void> {
    try {
      const response = await this.history.versions(organizationId, objectId);
      if (this.selectedObjectId() !== objectId) {
        return;
      }
      this.versions.set(response.items);
      const known = new Set(response.items.map((version) => version.id));
      // Versions arrive newest first: the newest is B, the one before it is A.
      if (!this.versionBId() || !known.has(this.versionBId() ?? '')) {
        this.versionBId.set(response.items[0]?.id ?? null);
      }
      if (!this.versionAId() || !known.has(this.versionAId() ?? '')) {
        this.versionAId.set(response.items[1]?.id ?? null);
      }
    } catch (cause) {
      this.ui.fail(cause, 'Loading the version history');
    }
  }

  private async loadDiff(organizationId: string, from: string, to: string): Promise<void> {
    const token = ++this.diffToken;
    this.clearDiff();
    this.diffLoading.set(true);
    try {
      // Metadata first: a gateway template can carry thousands of entries, so
      // section bodies are fetched only for what the operator actually opens.
      const meta = await this.diffs.compare(organizationId, from, to, { includeEntries: false });
      if (token !== this.diffToken) {
        return;
      }
      if (meta.mode === 'chips') {
        const full = await this.diffs.compare(organizationId, from, to);
        if (token !== this.diffToken) {
          return;
        }
        this.diff.set(full);
        this.notableEntries.set(full.notable);
        this.sectionEntries.set(indexSections(full.sections));
      } else {
        this.diff.set(meta);
        const first = meta.sections[0]?.key ?? null;
        // The notable panel and the first open section share one request.
        const wanted = meta.sections.filter((section) => section.notable > 0).map((section) => section.key);
        if (first && !wanted.includes(first)) {
          wanted.unshift(first);
        }
        this.openSection.set(first);
        if (wanted.length > 0) {
          const detail = await this.diffs.compare(organizationId, from, to, { sections: wanted });
          if (token !== this.diffToken) {
            return;
          }
          this.notableEntries.set(detail.notable);
          this.sectionEntries.set(indexSections(detail.sections));
        }
      }
      if (this.ai.automatic()) {
        void this.runAi(false);
      }
    } catch (cause) {
      this.ui.fail(cause, 'Building the comparison');
    } finally {
      if (token === this.diffToken) {
        this.diffLoading.set(false);
      }
    }
  }

  private clearDiff(): void {
    this.diff.set(null);
    this.notableEntries.set([]);
    this.sectionEntries.set({});
    this.expandedSections.set({});
    this.openSection.set(null);
    this.loadingSection.set(null);
    this.raw.set(null);
    this.rawExpanded.set(false);
    this.exportOpen.set(false);
    this.aiSummary.set(null);
    this.answer.set(null);
    this.question.set('');
    this.aiNote.set('');
    this.aiState.set(this.ai.refused() ? 'unavailable' : 'idle');
  }

  private pairLabel(slot: string, versionId: string | null): string {
    const version = this.versions().find((item) => item.id === versionId);
    if (!version) {
      return `${slot} · —`;
    }
    return `${slot} · v${version.version} · ${formatInstant(new Date(version.observed_at))}`;
  }
}

function entriesOf(section: DiffSection, cache: Record<string, DiffEntry[]>): DiffEntry[] {
  return section.key in cache ? cache[section.key] : section.entries;
}

function indexSections(sections: DiffSection[]): Record<string, DiffEntry[]> {
  const index: Record<string, DiffEntry[]> = {};
  for (const section of sections) {
    if (section.entries_included) {
      index[section.key] = section.entries;
    }
  }
  return index;
}

/** `15 VERSIONS · UPDATED 07 SEP 09:12Z` — the rail's second line. */
function objectMeta(object: ConfigurationObject): string {
  const at = formatInstant(new Date(object.updated_at));
  if (object.is_deleted) {
    return `TOMBSTONED ${at}`;
  }
  const versions = `${object.current_version} ${object.current_version === 1 ? 'VERSION' : 'VERSIONS'}`;
  return `${versions} · UPDATED ${at}`;
}

function isEditable(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) {
    return false;
  }
  const tag = target.tagName;
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || target.isContentEditable;
}

function download(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
