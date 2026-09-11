import { ComponentFixture, TestBed } from '@angular/core/testing';
import { TopologyDevice } from './site-impact.model';
import { layoutTopology, NODE_PAD_LEFT, NODE_PAD_TOP } from './topology-layout';
import { TopologyCanvas } from './topology-canvas';

function device(overrides: Partial<TopologyDevice> & { id: string }): TopologyDevice {
  return {
    name: overrides.id,
    mac: overrides.id,
    kind: 'switch',
    model: '',
    ip: null,
    clients: null,
    parent: null,
    uplink: null,
    tier: 2,
    health: 'unknown',
    health_label: 'No health evidence',
    last_seen: null,
    ...overrides,
  };
}
const DEVICES = [
  device({ id: 'gw', tier: 0, kind: 'gateway' }),
  device({ id: 'sw', tier: 2, parent: 'gw' }),
  device({ id: 'ap-1', tier: 3, kind: 'ap', parent: 'sw' }),
  device({ id: 'ap-2', tier: 3, kind: 'ap', parent: 'sw' }),
];
const LINKS = [
  { source: 'gw', target: 'sw', source_ports: [], target_ports: [] },
  { source: 'sw', target: 'ap-1', source_ports: [], target_ports: [] },
  { source: 'sw', target: 'ap-2', source_ports: [], target_ports: [] },
  { source: 'ap-1', target: 'ap-2', source_ports: [], target_ports: [] },
];
function render(devices = DEVICES, links = LINKS): ComponentFixture<TopologyCanvas> {
  const fixture = TestBed.createComponent(TopologyCanvas);
  fixture.componentRef.setInput('devices', devices);
  fixture.componentRef.setInput('observedLinks', links);
  fixture.detectChanges();
  return fixture;
}

describe('TopologyCanvas', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'ResizeObserver',
      class {
        observe() {}
        disconnect() {}
      },
    );
  });
  it('places every node where the layout puts it, not on a tier grid', () => {
    const fixture = render(),
      layout = layoutTopology(DEVICES, LINKS),
      buttons = [...fixture.nativeElement.querySelectorAll('.node')] as HTMLElement[];
    expect(buttons).toHaveLength(4);
    buttons.forEach((button, index) => {
      const at = layout.nodes.get(DEVICES[index].id);
      expect(button.style.left).toBe(`${(at?.x ?? 0) - NODE_PAD_LEFT}px`);
      expect(button.style.top).toBe(`${(at?.y ?? 0) - NODE_PAD_TOP}px`);
    });
    // Both access points hang off the same switch, so they share a column.
    expect(buttons[2].style.left).toBe(buttons[3].style.left);
    expect(buttons[2].style.top).not.toBe(buttons[3].style.top);
  });
  it('sizes the canvas from the layout so fitting can use both axes', () => {
    const canvas = render().nativeElement.querySelector('.canvas') as HTMLElement,
      layout = layoutTopology(DEVICES, LINKS);
    expect(canvas.style.width).toBe(`${Math.max(400, layout.width)}px`);
    expect(canvas.style.height).toBe(`${Math.max(300, layout.height)}px`);
  });
  it('draws secondary links beneath tree links and marks only the secondary ones', () => {
    const paths = [...render().nativeElement.querySelectorAll('.links path')] as SVGPathElement[];
    expect(paths).toHaveLength(4);
    const kinds = paths.map((path) => (path.classList.contains('secondary') ? 'S' : 'T'));
    // The ap-1/ap-2 peering is not a tree edge, and every secondary path is painted
    // first so the guaranteed routes sit on top of it.
    expect(kinds).toEqual(['S', 'T', 'T', 'T']);
    for (const path of paths) expect(path.getAttribute('d')).toMatch(/^M [\d.]+ [\d.]+/);
  });
  it('highlights only the routes touching an impacted device', () => {
    const fixture = render();
    fixture.componentRef.setInput('impacted', ['ap-1']);
    fixture.detectChanges();
    const active = [...fixture.nativeElement.querySelectorAll('.links path.in-path')];
    expect(active).toHaveLength(2);
    expect(fixture.nativeElement.querySelectorAll('.node.impacted')).toHaveLength(1);
  });
  it('drops a device the layout could not place rather than stacking it at the origin', () => {
    const fixture = render([], []);
    expect(fixture.nativeElement.querySelectorAll('.node')).toHaveLength(0);
    expect(fixture.nativeElement.querySelectorAll('.links path')).toHaveLength(0);
  });
});
