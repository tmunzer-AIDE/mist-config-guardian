import {
  afterNextRender,
  ChangeDetectionStrategy,
  Component,
  computed,
  effect,
  ElementRef,
  inject,
  Injector,
  input,
  signal,
} from '@angular/core';
import { Router } from '@angular/router';
import { ChangeGroupDetail, ChangeSiteImpact } from '../../core/change-group.model';
import { OrganizationContextService } from '../../core/organization-context.service';
import { TimeContextService } from '../../core/time-context.service';
import { rememberFocus, restoreFocus } from '../../core/focus';
import { SiteImpactService } from '../impact/site-impact.service';
import {
  DeviceImpact,
  Health,
  SiteTopology,
  TopologyDevice,
  evidenceValue,
} from '../impact/site-impact.model';
import { TopologyCanvas } from '../impact/topology-canvas';
import { metricLabel } from '../impact/monitoring.model';

const mac = (value: string) => value.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
const severityRank: Health[] = ['critical', 'error', 'warning', 'unknown', 'ok'];

@Component({
  selector: 'app-change-impact',
  imports: [TopologyCanvas],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './change-impact.html',
  styleUrl: './change-impact.scss',
})
export class ChangeImpact {
  readonly detail = input.required<ChangeGroupDetail>();
  private readonly api = inject(SiteImpactService);
  private readonly orgs = inject(OrganizationContextService);
  private readonly time = inject(TimeContextService);
  private readonly router = inject(Router);
  private readonly element = inject<ElementRef<HTMLElement>>(ElementRef);
  private readonly injector = inject(Injector);
  private deviceTrigger: HTMLElement | null = null;
  protected readonly siteId = signal('');
  protected readonly deviceId = signal<string | null>(null);
  protected readonly topology = signal<SiteTopology | null>(null);
  protected readonly busy = signal(false);
  protected readonly error = signal('');
  protected readonly refresh = signal(0);
  protected readonly increment = (n: number) => n + 1;
  protected readonly historical = computed(() => this.detail().impact_known === false);
  protected readonly sites = computed<ChangeSiteImpact[]>(() => {
    const detail = this.detail();
    if (this.historical()) return [];
    if (detail.site_impacts !== undefined) return detail.site_impacts;
    const ids = new Set(
      [
        ...detail.affected_site_ids,
        ...detail.affected_devices.map((d) => d.site_mist_id),
        ...detail.changed_objects.map((o) => o.site_mist_id),
      ].filter((id): id is string => !!id),
    );
    return [...ids].map((id) => ({
      site_id: id,
      site_name: id,
      devices: [],
      unmonitored_devices: detail.affected_devices.filter((d) => d.site_mist_id === id),
    }));
  });
  protected readonly site = computed<ChangeSiteImpact | null>(
    () => this.sites().find((s) => s.site_id === this.siteId()) ?? this.sites()[0] ?? null,
  );
  protected readonly allDevices = computed(
    () =>
      new Set(
        this.sites().flatMap((s) => [
          ...s.devices.map((d) => mac(d.device_id)),
          ...s.unmonitored_devices.map((d) => mac(d.device_mac)),
        ]),
      ).size,
  );
  protected readonly disrupted = computed(
    () =>
      new Set(
        this.sites().flatMap((s) =>
          s.devices
            .filter((d) => ['critical', 'warning'].includes(d.severity))
            .map((d) => mac(d.device_id)),
        ),
      ).size,
  );
  protected readonly uncertain = computed(
    () =>
      new Set(
        this.sites().flatMap((s) => [
          ...s.devices
            .filter((d) => ['unknown', 'error'].includes(d.severity))
            .map((d) => mac(d.device_id)),
          ...s.unmonitored_devices.map((d) => mac(d.device_mac)),
        ]),
      ).size,
  );
  protected readonly impacted = computed(() =>
    this.site()
      ? [
          ...new Set([
            ...this.site()!.devices.map((d) => mac(d.device_id)),
            ...this.site()!.unmonitored_devices.map((d) => mac(d.device_mac)),
          ]),
        ]
      : [],
  );
  protected readonly devices = computed<TopologyDevice[]>(() => {
    const devices = new Map(
      (this.topology()?.devices ?? []).map((d) => [
        mac(d.id),
        {
          ...d,
          id: mac(d.id),
          health: 'unknown' as Health,
          health_label: 'No evidence for this change',
        },
      ]),
    );
    const site = this.site();
    const linked = [
      ...(site?.devices.map((d) => ({ id: mac(d.device_id), name: d.device_name })) ?? []),
      ...(site?.unmonitored_devices.map((d) => ({ id: mac(d.device_mac), name: d.device_name })) ??
        []),
    ];
    for (const d of linked)
      if (!devices.has(d.id))
        devices.set(d.id, {
          ...d,
          mac: d.id,
          kind: 'unknown',
          model: '',
          ip: null,
          clients: null,
          parent: null,
          uplink: null,
          tier: 3,
          health: 'unknown',
          health_label: 'Topology unavailable',
          last_seen: null,
        });
    return [...devices.values()];
  });
  protected readonly health = computed<Partial<Record<string, Health>>>(() => {
    const result: Partial<Record<string, Health>> = {};
    for (const d of this.site()?.devices ?? []) {
      const id = mac(d.device_id),
        prior = result[id];
      if (!prior || severityRank.indexOf(d.severity) < severityRank.indexOf(prior))
        result[id] = d.severity;
    }
    return result;
  });
  protected readonly selected = computed(() =>
    this.devices().find((d) => d.id === this.deviceId()),
  );
  protected readonly evidence = computed(
    () => this.site()?.devices.filter((d) => mac(d.device_id) === this.deviceId()) ?? [],
  );
  protected readonly label = (value: Health) =>
    ({
      ok: 'No impact observed',
      warning: 'Possible disruption',
      critical: 'Severe degradation',
      error: 'Collection failed',
      unknown: 'Not established',
    })[value];
  protected readonly metric = metricLabel;
  protected readonly value = evidenceValue;
  protected readonly date = (v: string | null) =>
    v ? new Date(v).toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : 'Not recorded';
  protected count(site: ChangeSiteImpact) {
    return new Set([
      ...site.devices.map((d) => mac(d.device_id)),
      ...site.unmonitored_devices.map((d) => mac(d.device_mac)),
    ]).size;
  }
  protected affected(site: ChangeSiteImpact) {
    return new Set(
      site.devices
        .filter((d) => ['critical', 'warning'].includes(d.severity))
        .map((d) => mac(d.device_id)),
    ).size;
  }
  protected verdict(site: ChangeSiteImpact) {
    const disrupted = this.affected(site);
    if (disrupted) return `${disrupted} with measured degradation`;
    if (!site.devices.length) return 'No measurements';
    if (
      site.unmonitored_devices.length ||
      site.devices.some((d) => ['unknown', 'error'].includes(d.severity))
    )
      return 'Impact not established';
    return 'No impact observed';
  }
  protected chooseSite(id: string) {
    this.siteId.set(id);
    this.deviceId.set(null);
  }
  protected inspect(id: string) {
    this.deviceTrigger = rememberFocus();
    this.deviceId.set(id);
    afterNextRender(
      () => {
        const panel = this.element.nativeElement.querySelector<HTMLElement>('.device-detail');
        panel?.scrollIntoView({ block: 'nearest' });
        panel?.querySelector<HTMLElement>('h4')?.focus({ preventScroll: true });
      },
      { injector: this.injector },
    );
  }
  protected closeDevice() {
    this.deviceId.set(null);
    afterNextRender(() => restoreFocus(this.deviceTrigger), { injector: this.injector });
  }
  protected deviceName(id: string) {
    return this.devices().find((d) => d.id === id)?.name || id;
  }
  protected async openEvidence(device: DeviceImpact) {
    await this.router.navigate(['/impact/sessions'], {
      queryParams: { session: device.session_id },
    });
  }
  constructor() {
    effect((cleanup) => {
      const org = this.orgs.selected()?.id,
        site = this.site()?.site_id;
      this.refresh();
      this.topology.set(null);
      this.error.set('');
      this.deviceId.set(null);
      this.busy.set(false);
      if (!org || !site) return;
      this.busy.set(true);
      const subscription = this.api
        .topology(org, site, this.time.asOf()?.toISOString() ?? null)
        .subscribe({
          next: (topology) => {
            this.topology.set(topology);
            this.busy.set(false);
          },
          error: () => {
            this.error.set(
              'Topology could not be loaded. Device evidence is still available below.',
            );
            this.busy.set(false);
          },
        });
      cleanup(() => subscription.unsubscribe());
    });
  }
}
