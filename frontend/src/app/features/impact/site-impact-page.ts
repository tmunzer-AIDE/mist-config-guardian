import { SiteContextService } from '../../core/site-context.service';
import {
  ChangeDetectionStrategy,
  Component,
  computed,
  effect,
  inject,
  input,
  OnDestroy,
  signal,
  untracked,
} from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { forkJoin, Subscription } from 'rxjs';
import { OrganizationContextService } from '../../core/organization-context.service';
import { TimeContextService } from '../../core/time-context.service';
import { formatInstant } from '../../core/format';
import { SiteImpactService } from './site-impact.service';
import {
  changeHealth,
  changePhase,
  changeProgress,
  DeviceImpact,
  evidenceValue,
  Health,
  ImpactSite,
  impactDevices,
  SiteChange,
  SiteTopology,
} from './site-impact.model';
import { TopologyCanvas } from './topology-canvas';
import { metricLabel } from './monitoring.model';

@Component({
  selector: 'app-site-impact-page',
  imports: [TopologyCanvas, RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './site-impact-page.html',
  styleUrl: './site-impact-page.scss',
})
export class SiteImpactPage implements OnDestroy {
  protected readonly evidenceValue = evidenceValue;
  private readonly api = inject(SiteImpactService);
  private readonly siteContext = inject(SiteContextService);
  private readonly orgs = inject(OrganizationContextService);
  protected readonly time = inject(TimeContextService);
  private readonly router = inject(Router);
  readonly session = input('');
  readonly site = input('');
  readonly change = input('');
  readonly device = input('');
  protected readonly preferredZoom = signal<number | null>(null);
  protected readonly sites = signal<ImpactSite[]>([]);
  protected readonly siteId = signal('');
  protected readonly changes = signal<SiteChange[]>([]);
  protected readonly total = signal(0);
  protected readonly topology = signal<SiteTopology | null>(null);
  protected readonly busy = signal(true);
  protected readonly failure = signal('');
  protected readonly collectionWarnings = signal<string[]>([]);
  protected readonly warnings = computed(() => [
    ...this.collectionWarnings(),
    ...(this.topology()?.warnings ?? []),
  ]);
  protected readonly moreBusy = signal(false);
  protected readonly filter = signal<'all' | 'pending' | 'monitoring' | 'settled'>('all');
  protected readonly search = signal('');
  protected readonly railOpen = signal(false);
  protected readonly selectedChangeId = signal<string | null>(null);
  protected readonly selectedDeviceId = signal<string | null>(null);
  private readonly refresh = signal(0);
  private readonly sitesRefresh = signal(0);
  private loadedScope = '';
  private linkedScope = '';
  private appliedSiteLink = '';
  private moreRequest?: Subscription;
  private generation = 0;
  private refreshTimer: ReturnType<typeof setInterval>;
  protected readonly selectedChange = computed(
    () => this.changes().find((c) => c.id === this.selectedChangeId()) ?? null,
  );
  protected readonly devices = computed(() =>
    impactDevices(this.topology()?.devices ?? [], this.changes()),
  );
  protected readonly selectedDevice = computed(
    () => this.devices().find((d) => d.id === this.selectedDeviceId()) ?? null,
  );
  protected readonly neighbors = computed(() => {
    const selected = this.selectedDeviceId();
    const devices = new Map(this.devices().map((device) => [device.id, device]));
    const ports = (values: string[]) =>
      values.slice(0, 4).join(', ') + (values.length > 4 ? ` +${values.length - 4} more` : '');
    return (this.topology()?.links ?? []).flatMap((link) => {
      const source = link.source === selected;
      if (!source && link.target !== selected) return [];
      const device = devices.get(source ? link.target : link.source);
      return device
        ? [
            {
              device,
              local: ports(source ? link.source_ports : link.target_ports) || 'Port unknown',
              remote: ports(source ? link.target_ports : link.source_ports) || 'Port unknown',
            },
          ]
        : [];
    });
  });
  protected readonly selectedImpact = computed(
    () =>
      this.selectedChange()?.impacts.find((i) => i.device_id === this.selectedDeviceId()) ?? null,
  );
  protected readonly selection = computed(() => !!this.selectedChange() || !!this.selectedDevice());
  protected readonly siteName = computed(
    () => this.sites().find((s) => s.id === this.siteId())?.name ?? 'Site',
  );
  protected readonly visibleChanges = computed(() =>
    this.changes().filter(
      (c) =>
        (this.filter() === 'all' || changePhase(c) === this.filter()) &&
        `${c.title} ${c.change_type} ${c.actor ?? ''}`
          .toLowerCase()
          .includes(this.search().trim().toLowerCase()),
    ),
  );
  protected readonly nodeHealth = computed(() =>
    Object.fromEntries(
      (this.selectedChange()?.impacts ?? []).map((i) => [i.device_id, i.severity]),
    ),
  );
  protected readonly impacted = computed(
    () => this.selectedChange()?.impacts.map((i) => i.device_id) ?? [],
  );
  protected readonly decorations = computed(() => {
    const result: Record<string, string> = {};
    for (const change of this.selectedChange() ? [this.selectedChange()!] : this.changes())
      for (const impact of change.impacts)
        if (!(impact.device_id in result)) result[impact.device_id] = impact.config_state;
    return result;
  });
  protected readonly deviceHistory = computed(() =>
    this.changes().filter((c) => c.impacts.some((i) => i.device_id === this.selectedDeviceId())),
  );
  protected readonly rollup = computed(() =>
    ['ok', 'warning', 'error', 'critical', 'unknown'].map((health) => ({
      health: health as Health,
      count: this.devices().filter((d) => d.health === health).length,
    })),
  );
  protected readonly pending = computed(
    () => Object.values(this.decorations()).filter((state) => state === 'pending').length,
  );
  protected readonly steps = computed(() => {
    const impact = this.selectedImpact();
    if (!impact) return [];
    return [
      { label: 'Change detected', at: impact.detected_at },
      { label: 'Initial state captured', at: impact.snapshot_at },
      { label: 'Device configuration confirmed', at: impact.configured_at },
      {
        label: impact.completed_at ? 'Monitoring ended' : 'Monitoring started',
        at: impact.completed_at ?? impact.monitoring_started_at,
      },
    ];
  });
  protected readonly metricLabel = metricLabel;
  protected readonly phase = changePhase;
  protected readonly progress = changeProgress;
  protected readonly health = changeHealth;
  protected readonly label = (v: string) =>
    v
      .replaceAll('_', ' ')
      .replaceAll('-', ' ')
      .replace(/^./, (c) => c.toUpperCase());
  protected readonly at = (v: string | null) => (v ? formatInstant(new Date(v)) : 'Not observed');
  protected readonly preciseAt = (v: string | null) =>
    v ? new Date(v).toISOString().replace('T', ' ').replace('.000', '') : 'Not observed';
  protected readonly healthLabel = (v: Health) =>
    ({ ok: 'OK', warning: 'Warning', error: 'Error', critical: 'Critical', unknown: 'Unknown' })[v];
  constructor() {
    // Zoom is owned here because the canvas is destroyed whenever a site's
    // topology clears. Keying the reset on siteId covers every transition —
    // selectSite, and the automatic pick after an organization or as-of reload —
    // where a fresh canvas would otherwise inherit the previous site's zoom.
    effect(() => {
      this.siteId();
      this.preferredZoom.set(null);
    });
    effect(() => {
      const linked = this.session();
      if (linked)
        void this.router.navigate(['/impact/sessions'], {
          queryParams: { session: linked },
          replaceUrl: true,
        });
    });
    effect((onCleanup) => {
      this.sitesRefresh();
      const linkedSite = this.site();
      const org = this.orgs.selected()?.id;
      const asOf = this.time.asOf()?.toISOString() ?? null;
      this.generation++;
      this.moreRequest?.unsubscribe();
      this.total.set(0);
      this.sites.set([]);
      this.siteId.set('');
      this.changes.set([]);
      this.topology.set(null);
      this.clear();
      this.failure.set('');
      this.collectionWarnings.set([]);
      this.busy.set(!!org);
      if (!org) return;
      const sub = this.api.sites(org, asOf).subscribe({
        next: (response) => {
          this.sites.set(response.items);
          untracked(() => {
            const linkKey = JSON.stringify([org, linkedSite]);
            const requested = linkedSite && this.appliedSiteLink !== linkKey
              ? linkedSite
              : this.siteContext.selectedFor(org);
            this.appliedSiteLink = linkKey;
            const selected = response.items.some((s) => s.id === requested)
              ? requested
              : (response.items[0]?.id ?? '');
            this.siteId.set(selected);
            // An empty historical snapshot should not erase the remembered site.
            if (selected) this.siteContext.select(org, selected);
          });
          if (!response.items.length) this.busy.set(false);
        },
        error: () => {
          this.failure.set('Sites could not be loaded.');
          this.busy.set(false);
        },
      });
      onCleanup(() => sub.unsubscribe());
    });
    effect((onCleanup) => {
      const org = this.orgs.selected()?.id,
        site = this.siteId(),
        range = this.time.range(),
        asOf = this.time.asOf()?.toISOString() ?? null;
      this.refresh();
      const generation = ++this.generation;
      this.moreRequest?.unsubscribe();
      this.moreBusy.set(false);
      if (!org || !site) return;
      const scope = JSON.stringify([org, site, range, asOf]);
      const changed = scope !== this.loadedScope;
      this.loadedScope = scope;
      if (changed) {
        this.clear();
        this.changes.set([]);
        this.topology.set(null);
        this.total.set(0);
      }
      const pages = untracked(() => Math.max(1, Math.ceil(this.changes().length / 50)));
      this.busy.set(true);
      this.failure.set('');
      this.collectionWarnings.set([]);
      const sub = forkJoin({
        topology: this.api.topology(org, site, asOf),
        changes: forkJoin(
          Array.from({ length: pages }, (_, index) =>
            this.api.changes(org, site, range, asOf, index * 50),
          ),
        ),
      }).subscribe({
        next: (response) => {
          if (generation !== this.generation) return;
          this.topology.set(response.topology);
          this.collectionWarnings.set([
            ...new Set(response.changes.flatMap((page) => page.warnings ?? [])),
          ]);
          this.changes.set([
            ...new Map(
              response.changes.flatMap((page) => page.items).map((c) => [c.id, c]),
            ).values(),
          ]);
          this.total.set(response.changes[0].total);
          this.busy.set(false);
          untracked(() => {
            if (this.linkedScope === scope) return;
            this.linkedScope = scope;
            const linked = this.change();
            if (linked && !this.selectedChangeId()) this.selectedChangeId.set(linked);
            const node = this.device();
            if (node && !this.selectedDeviceId()) this.selectedDeviceId.set(node);
          });
        },
        error: () => {
          if (generation !== this.generation) return;
          this.failure.set(
            'This site could not be loaded. Retry to retrieve its topology and changes.',
          );
          this.busy.set(false);
        },
      });
      onCleanup(() => sub.unsubscribe());
    });
    this.refreshTimer = setInterval(() => {
      if (!this.time.isHistorical() && !this.busy() && !this.moreBusy())
        this.refresh.update((n) => n + 1);
    }, 60_000);
  }
  ngOnDestroy() {
    clearInterval(this.refreshTimer);
    this.moreRequest?.unsubscribe();
  }
  protected retry() {
    if (!this.siteId()) this.sitesRefresh.update((n) => n + 1);
    else this.refresh.update((n) => n + 1);
  }
  protected selectSite(id: string) {
    this.siteContext.select(this.orgs.selected()?.id, id);
    this.clear();
    this.siteId.set(id);
    this.topology.set(null);
    this.changes.set([]);
    this.railOpen.set(false);
  }
  protected clear() {
    this.selectedChangeId.set(null);
    this.selectedDeviceId.set(null);
  }
  protected chooseChange(id: string, keepDevice = false) {
    this.selectedChangeId.set(this.selectedChangeId() === id && !keepDevice ? null : id);
    if (!keepDevice) this.selectedDeviceId.set(null);
    this.railOpen.set(false);
  }
  protected chooseDevice(id: string) {
    this.selectedDeviceId.set(this.selectedDeviceId() === id ? null : id);
  }
  protected back() {
    this.selectedDeviceId.set(null);
  }
  protected deviceName(id: string) {
    return this.devices().find((d) => d.id === id)?.name ?? id;
  }
  protected historyImpact(change: SiteChange): DeviceImpact | undefined {
    return change.impacts.find((i) => i.device_id === this.selectedDeviceId());
  }
  protected more() {
    const org = this.orgs.selected()?.id;
    if (!org || this.moreBusy() || this.busy()) return;
    const generation = this.generation;
    this.moreBusy.set(true);
    this.moreRequest = this.api
      .changes(
        org,
        this.siteId(),
        this.time.range(),
        this.time.asOf()?.toISOString() ?? null,
        this.changes().length,
      )
      .subscribe({
        next: (page) => {
          if (generation !== this.generation) return;
          this.changes.update((items) => [
            ...items,
            ...page.items.filter((c) => !items.some((old) => old.id === c.id)),
          ]);
          this.total.set(page.total);
          this.collectionWarnings.update((warnings) => [
            ...new Set([...warnings, ...(page.warnings ?? [])]),
          ]);
          this.moreBusy.set(false);
        },
        error: () => {
          this.moreBusy.set(false);
          this.failure.set('More changes could not be loaded.');
        },
      });
  }
}
