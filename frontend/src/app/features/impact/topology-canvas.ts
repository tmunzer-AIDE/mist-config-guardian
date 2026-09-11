import {
  AfterViewInit,
  ChangeDetectionStrategy,
  Component,
  computed,
  effect,
  ElementRef,
  inject,
  input,
  OnDestroy,
  output,
  signal,
  viewChild,
} from '@angular/core';
import {
  boundedView,
  Health,
  TopologyDevice,
  TopologyLink,
  Viewport,
  zoomAt,
} from './site-impact.model';
import { edgePath, layoutTopology, NODE_PAD_LEFT, NODE_PAD_TOP } from './topology-layout';

@Component({
  selector: 'app-topology-canvas',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div
      class="surface"
      #surface
      tabindex="0"
      role="region"
      aria-label="Site topology. Drag to pan, use plus or minus to zoom, Home to fit."
      (pointerdown)="pointerDown($event)"
      (pointermove)="pointerMove($event)"
      (pointerup)="pointerUp($event)"
      (pointercancel)="pointerCancel()"
      (keydown)="onKey($event)"
      [class.dragging]="dragging()"
    >
      <div
        class="canvas"
        [style.width.px]="canvasWidth()"
        [style.height.px]="canvasHeight()"
        [style.transform]="transform()"
      >
        <svg
          class="links"
          [attr.width]="canvasWidth()"
          [attr.height]="canvasHeight()"
          aria-hidden="true"
        >
          @for (link of secondaryLinks(); track link.id) {
            <path
              class="secondary"
              [attr.d]="link.path"
              [class.in-path]="link.active"
              [class.dim]="scoped() && !link.active"
            />
          }
          @for (link of treeLinks(); track link.id) {
            <path
              [attr.d]="link.path"
              [class.in-path]="link.active"
              [class.dim]="scoped() && !link.active"
            />
          }
        </svg>
        @for (placed of nodes(); track placed.device.id) {
          @let device = placed.device;
          <button
            type="button"
            class="node"
            [attr.data-health]="healthOverrides()[device.id] ?? device.health"
            [class.selected]="selectedDevice() === device.id"
            [class.impacted]="impacted().includes(device.id)"
            [class.dim]="scoped() && !impacted().includes(device.id)"
            [style.left.px]="placed.left"
            [style.top.px]="placed.top"
            [attr.aria-pressed]="selectedDevice() === device.id"
            [attr.aria-label]="
              device.name + ', ' + (healthOverrides()[device.id] ?? device.health_label)
            "
            (click)="pick($event, device.id)"
          >
            <span class="device-icon" [class.pending]="decorations()[device.id] === 'pending'">
              <svg viewBox="0 0 24 24" aria-hidden="true">
                @switch (device.kind) {
                  @case ('ap') {
                    <path d="M3 9a14 14 0 0 1 18 0M6 13a9 9 0 0 1 12 0M9 17a4 4 0 0 1 6 0" />
                    <circle cx="12" cy="21" r=".7" />
                  }
                  @case ('gateway') {
                    <path d="m12 2 8 3v7c0 5-8 10-8 10S4 17 4 12V5zM8 11h8M12 7v8" />
                  }
                  @case ('switch') {
                    <rect x="2" y="4" width="20" height="6" rx="1" />
                    <rect x="2" y="14" width="20" height="6" rx="1" />
                    <path d="M5 7h1m3 0h1m3 0h5M5 17h1m3 0h1m3 0h5" />
                  }
                  @default {
                    <path d="M9 8a3 3 0 1 1 5 2c-2 1-2 2-2 4M12 18h.01" />
                  }
                }
              </svg>
              @if (decorations()[device.id] === 'applied') {
                <span class="applied" aria-label="Configuration applied">✓</span>
              }
            </span>
            <span class="node-label"
              ><strong>{{ device.name }}</strong
              ><small>{{ device.mac }}</small
              ><small>{{ device.ip || 'IP unavailable' }}</small
              ><span>{{
                device.clients === null ? 'Client count unavailable' : device.clients + ' clients'
              }}</span></span
            >
          </button>
        }
      </div>
    </div>
    <div class="zoom" (pointerdown)="$event.stopPropagation()" aria-label="Topology zoom controls">
      <button type="button" aria-label="Zoom out" (click)="zoom(0.8)">−</button
      ><output aria-live="polite">{{ percent() }}%</output
      ><button type="button" aria-label="Zoom in" (click)="zoom(1.25)">+</button
      ><button type="button" (click)="fit()">Fit</button>
    </div>
    <span class="canvas-hint">Drag to pan · scroll to zoom</span>
  `,
  styles: `
    :host {
      position: relative;
      display: block;
      min-width: 0;
      min-height: 0;
      height: 100%;
      overflow: hidden;
    }
    .surface {
      position: absolute;
      inset: 0;
      overflow: hidden;
      cursor: grab;
      touch-action: none;
      outline-offset: -3px;
    }
    .surface.dragging {
      cursor: grabbing;
    }
    .canvas {
      position: absolute;
      transform-origin: 0 0;
    }
    .links {
      position: absolute;
      inset: 0;
      pointer-events: none;
    }
    path {
      fill: none;
      stroke: currentColor;
      stroke-width: 1.7;
      stroke-linecap: round;
      stroke-linejoin: round;
    }
    .links path {
      stroke: #63758c;
      stroke-width: 2;
      stroke-dasharray: 2 5;
      vector-effect: non-scaling-stroke;
      opacity: 1;
    }
    /* Secondary links carry no routing guarantee, so they read as background
       evidence until one of their endpoints is actually in scope. */
    .links path.secondary {
      stroke: var(--ink-faint);
      stroke-width: 1.5;
      stroke-dasharray: 1 6;
      opacity: 0.75;
    }
    .links path.in-path {
      stroke: var(--brand);
      stroke-width: 2.5;
      opacity: 1;
    }
    .links path.secondary.in-path {
      stroke-width: 2;
      opacity: 1;
    }
    .links path.dim {
      opacity: 0.72;
    }
    .links path.secondary.dim {
      opacity: 0.45;
    }
    .node {
      position: absolute;
      display: flex;
      align-items: center;
      gap: 10px;
      width: 173px;
      height: 52px;
      background: none;
      border: 0;
      padding: 0;
      text-align: left;
      color: var(--ink);
      cursor: pointer;
    }
    .node.dim {
      color: var(--ink-soft);
    }
    .device-icon {
      position: relative;
      display: grid;
      place-items: center;
      width: 42px;
      height: 42px;
      flex: none;
      border: 2px solid var(--ink-faint);
      border-radius: 14px;
      background: var(--surface-raised);
      color: var(--ink-soft);
    }
    .device-icon > svg {
      width: 19px;
      height: 19px;
      fill: none;
    }
    .node[data-health='ok'] .device-icon {
      color: var(--tone-ok-ink);
      border-color: currentColor;
      background: var(--tone-ok-soft);
    }
    .node[data-health='warning'] .device-icon {
      color: var(--tone-warning-ink);
      border-color: currentColor;
      background: var(--tone-warning-soft);
    }
    .node[data-health='error'] .device-icon,
    .node[data-health='critical'] .device-icon {
      color: var(--tone-critical-ink);
      border-color: currentColor;
      background: var(--tone-critical-soft);
    }
    .node[data-health='critical'] .device-icon {
      background: var(--tone-critical-ink);
      color: white;
      border-color: var(--tone-critical-ink);
    }
    .node.impacted .device-icon {
      box-shadow: 0 0 0 5px var(--brand-soft);
    }
    .node.selected .device-icon {
      background: var(--brand);
      border-color: var(--brand);
      color: white;
      box-shadow: 0 0 0 5px #2743a320;
    }
    .node.selected strong {
      color: var(--brand);
    }
    .node-label {
      min-width: 0;
    }
    .node-label strong {
      font-size: 12px;
      display: block;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .node-label small,
    .node-label > span {
      display: block;
      color: var(--ink-soft);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .node-label small {
      font: 9.5px var(--font-mono);
    }
    .node-label > span {
      font-size: 10px;
    }
    .pending:before {
      content: '';
      position: absolute;
      inset: -7px;
      border: 1.5px dashed var(--tone-warning-ink);
      border-radius: 50%;
    }
    .applied {
      position: absolute;
      bottom: -3px;
      right: -3px;
      display: grid;
      place-items: center;
      width: 16px;
      height: 16px;
      border: 2px solid var(--surface);
      border-radius: 50%;
      background: var(--tone-ok-ink);
      color: white;
      font-size: 10px;
    }
    .zoom {
      position: absolute;
      top: 18px;
      right: var(--topology-controls-inset, 20px);
      display: flex;
      align-items: center;
      background: var(--surface-raised);
      border: 1px solid var(--border-subtle);
      border-radius: 7px;
      box-shadow: var(--shadow-card);
      padding: 3px;
      z-index: 2;
    }
    .zoom button {
      background: transparent;
      border: 0;
      min-width: 32px;
      height: 32px;
      border-radius: 5px;
      cursor: pointer;
      color: var(--ink);
    }
    .zoom button:hover {
      background: var(--surface-selected);
      color: var(--brand);
    }
    .node:hover .device-icon {
      outline: 3px solid var(--brand-line);
      outline-offset: 3px;
    }
    .zoom button + button {
      border-left: 1px solid var(--hairline);
    }
    .zoom output {
      font: 10px var(--font-mono);
      width: 42px;
      text-align: center;
    }
    .canvas-hint {
      position: absolute;
      bottom: 14px;
      left: 20px;
      font-size: 11px;
      color: var(--ink-soft);
      pointer-events: none;
    }
    button:focus-visible {
      outline: 2px solid var(--brand);
      outline-offset: 5px;
    }
    @media (prefers-reduced-motion: no-preference) {
      .pending:before {
        animation: pending-pulse 1.7s ease-in-out infinite;
      }
      @keyframes pending-pulse {
        50% {
          opacity: 0.45;
        }
      }
    }
  `,
})
export class TopologyCanvas implements AfterViewInit, OnDestroy {
  readonly devices = input.required<TopologyDevice[]>();
  readonly observedLinks = input<TopologyLink[] | null>(null);
  readonly site = input('');
  readonly selectedDevice = input<string | null>(null);
  readonly healthOverrides = input<Partial<Record<string, Health>>>({});
  readonly impacted = input<string[]>([]);
  readonly scoped = input(false);
  readonly decorations = input<Record<string, string>>({});
  readonly deviceSelected = output<string>();
  readonly initialZoom = input<number | null>(null);
  readonly zoomChanged = output<number | null>();
  private readonly element = inject(ElementRef<HTMLElement>);
  private readonly surface = viewChild.required<ElementRef<HTMLElement>>('surface');
  // Geometry is decided by the layout, which takes no viewport input; panning and
  // zooming therefore never reflow the graph.
  protected readonly layout = computed(() =>
    layoutTopology(this.devices(), this.observedLinks() ?? []),
  );
  protected readonly canvasWidth = computed(() => Math.max(400, this.layout().width));
  protected readonly canvasHeight = computed(() => Math.max(300, this.layout().height));
  protected readonly nodes = computed(() => {
    const placed = this.layout().nodes;
    return this.devices().flatMap((device) => {
      const at = placed.get(device.id);
      return at ? [{ device, left: at.x - NODE_PAD_LEFT, top: at.y - NODE_PAD_TOP }] : [];
    });
  });
  protected readonly view = signal<Viewport>({ zoom: 1, x: 0, y: 0 });
  protected readonly percent = computed(() => Math.round(this.view().zoom * 100));
  protected readonly transform = computed(
    () => `translate(${this.view().x}px, ${this.view().y}px) scale(${this.view().zoom})`,
  );
  protected readonly dragging = signal(false);
  private dimensions = { width: 880, height: 530 };
  private observer?: ResizeObserver;
  private customZoom = false;
  private drag: {
    x: number;
    y: number;
    origin: Viewport;
    id: number;
    capture: HTMLElement;
  } | null = null;
  private suppressClick = false;
  private readonly drawn = computed(() => {
    const all = new Map(this.devices().map((d) => [d.id, d]));
    const paths = new Set<string>();
    for (const id of this.impacted()) {
      let node = all.get(id);
      const seen = new Set<string>();
      while (node?.parent && !seen.has(node.id)) {
        seen.add(node.id);
        paths.add(node.id);
        node = all.get(node.parent);
      }
    }
    return this.layout().edges.map((edge) => ({
      id: edge.id,
      kind: edge.kind,
      path: edgePath(edge),
      active:
        this.observedLinks() === null
          ? paths.has(edge.target)
          : this.impacted().includes(edge.source) || this.impacted().includes(edge.target),
    }));
  });
  protected readonly treeLinks = computed(() => this.drawn().filter((e) => e.kind === 'tree'));
  protected readonly secondaryLinks = computed(() =>
    this.drawn().filter((e) => e.kind === 'secondary'),
  );
  constructor() {
    effect(() => {
      this.site();
      this.view.update((v) => ({ ...v, x: 0, y: 0 }));
    });
    effect(() => {
      this.canvasWidth();
      this.canvasHeight();
      if (!this.customZoom) this.fit(false);
    });
  }
  ngAfterViewInit() {
    const initial = this.initialZoom();
    if (initial !== null) {
      this.customZoom = true;
      this.view.set({ zoom: initial, x: 0, y: 0 });
    }
    this.measure();
    this.observer = new ResizeObserver(() => this.measure());
    this.observer.observe(this.element.nativeElement);
    this.surface().nativeElement.addEventListener('wheel', this.wheel, { passive: false });
  }
  ngOnDestroy() {
    this.observer?.disconnect();
    this.surface().nativeElement.removeEventListener('wheel', this.wheel);
  }
  private measure() {
    const { width, height } = this.element.nativeElement.getBoundingClientRect();
    if (width <= 0 || height <= 0) return;
    if (
      Math.abs(width - this.dimensions.width) > 2 ||
      Math.abs(height - this.dimensions.height) > 2
    ) {
      this.dimensions = { width, height };
      if (!this.customZoom) this.fit(false);
      else this.view.update((v) => this.bound(v));
    }
  }
  private bound(v: Viewport) {
    return boundedView(
      v,
      this.dimensions.width,
      this.dimensions.height,
      this.canvasWidth(),
      this.canvasHeight(),
    );
  }
  protected fit(manual = true) {
    if (manual) this.zoomChanged.emit(null);
    this.customZoom = false;
    const zoom = Math.max(
      0.3,
      Math.min(
        1,
        (this.dimensions.width - 48) / this.canvasWidth(),
        (this.dimensions.height - 64) / this.canvasHeight(),
      ),
    );
    // A small site cannot fill the pane, and zoom is capped at 1 rather than
    // magnified to fit, so centre whatever slack is left instead of pinning the
    // graph to the inset corner.
    this.view.set(
      this.bound({
        zoom,
        x: Math.max(24, (this.dimensions.width - this.canvasWidth() * zoom) / 2),
        y: Math.max(32, (this.dimensions.height - this.canvasHeight() * zoom) / 2),
      }),
    );
  }
  protected zoom(factor: number) {
    this.customZoom = true;
    this.view.update((v) =>
      this.bound(zoomAt(v, factor, this.dimensions.width / 2, this.dimensions.height / 2)),
    );
    this.zoomChanged.emit(this.view().zoom);
  }
  private readonly wheel = (event: WheelEvent) => {
    event.preventDefault();
    this.customZoom = true;
    const bounds = this.surface().nativeElement.getBoundingClientRect();
    this.view.update((v) =>
      this.bound(
        zoomAt(
          v,
          Math.exp(-event.deltaY * 0.0016),
          event.clientX - bounds.left,
          event.clientY - bounds.top,
        ),
      ),
    );
    this.zoomChanged.emit(this.view().zoom);
  };
  protected pointerDown(event: PointerEvent) {
    if (event.button !== 0) return;
    this.suppressClick = false;
    const capture =
      (event.target as Element).closest<HTMLElement>('button') ?? this.surface().nativeElement;
    this.drag = {
      x: event.clientX,
      y: event.clientY,
      origin: this.view(),
      id: event.pointerId,
      capture,
    };
    capture.setPointerCapture(event.pointerId);
  }
  protected pointerMove(event: PointerEvent) {
    if (!this.drag) return;
    const dx = event.clientX - this.drag.x,
      dy = event.clientY - this.drag.y;
    if (Math.hypot(dx, dy) > 4) {
      this.dragging.set(true);
      this.suppressClick = true;
    }
    if (this.dragging()) {
      this.customZoom = true;
      this.view.set(
        this.bound({ ...this.drag.origin, x: this.drag.origin.x + dx, y: this.drag.origin.y + dy }),
      );
    }
  }
  protected pointerUp(event: PointerEvent) {
    if (!this.drag) return;
    if (this.drag.capture.hasPointerCapture(event.pointerId))
      this.drag.capture.releasePointerCapture(event.pointerId);
    this.drag = null;
    this.dragging.set(false);
  }
  protected pointerCancel() {
    this.drag = null;
    this.dragging.set(false);
    this.suppressClick = true;
  }
  protected pick(event: MouseEvent, id: string) {
    if (this.suppressClick && event.detail !== 0) {
      event.preventDefault();
      this.suppressClick = false;
      return;
    }
    this.deviceSelected.emit(id);
  }
  protected onKey(event: KeyboardEvent) {
    if (event.target !== this.surface().nativeElement) return;
    if (event.key === 'Home') {
      event.preventDefault();
      this.fit();
    } else if (event.key === '+' || event.key === '=') {
      event.preventDefault();
      this.zoom(1.25);
    } else if (event.key === '-') {
      event.preventDefault();
      this.zoom(0.8);
    } else if (['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(event.key)) {
      event.preventDefault();
      this.customZoom = true;
      this.view.update((v) =>
        this.bound({
          ...v,
          x: v.x + (event.key === 'ArrowLeft' ? 30 : event.key === 'ArrowRight' ? -30 : 0),
          y: v.y + (event.key === 'ArrowUp' ? 30 : event.key === 'ArrowDown' ? -30 : 0),
        }),
      );
    }
  }
}
