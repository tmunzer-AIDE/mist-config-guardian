import {
  DEFAULT_STACK_DEPTH,
  LayoutDevice,
  LayoutEdge,
  LayoutLink,
  LayoutPoint,
  LayoutRect,
  layoutTopology,
  nodeRect,
  TopologyLayout,
} from './topology-layout';

const EPS = 1e-7;
type Segment = [LayoutPoint, LayoutPoint];

function segmentsOf(edge: LayoutEdge): Segment[] {
  // A cubic lies inside the convex hull of its control points, so testing the
  // control polygon is a sound conservative stand-in for the rendered curve.
  const pairs: Segment[] = [];
  for (let index = 1; index < edge.points.length; index++) {
    const [a, b] = [edge.points[index - 1], edge.points[index]];
    if (Math.abs(a.x - b.x) > EPS || Math.abs(a.y - b.y) > EPS) pairs.push([a, b]);
  }
  return pairs;
}
const cross = (o: LayoutPoint, a: LayoutPoint, b: LayoutPoint) =>
  (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x);
const near = (value: number, target: number) => Math.abs(value - target) < 1e-6;
const isEnd = (t: number) => near(t, 0) || near(t, 1);

interface Relation {
  kind: 'clear' | 'touch' | 'violation';
  point?: LayoutPoint;
}
/**
 * `clear` — no shared point. `touch` — they meet at a single point that ends both
 * segments, which the caller must still match to a shared graph endpoint.
 * `violation` — a proper crossing, a T-junction, or a collinear run of length.
 */
function relate([a1, a2]: Segment, [b1, b2]: Segment): Relation {
  const r = { x: a2.x - a1.x, y: a2.y - a1.y },
    s = { x: b2.x - b1.x, y: b2.y - b1.y },
    denom = r.x * s.y - r.y * s.x,
    delta = { x: b1.x - a1.x, y: b1.y - a1.y };
  if (Math.abs(denom) > EPS) {
    const t = (delta.x * s.y - delta.y * s.x) / denom,
      u = (delta.x * r.y - delta.y * r.x) / denom;
    if (t < -EPS || t > 1 + EPS || u < -EPS || u > 1 + EPS) return { kind: 'clear' };
    return isEnd(t) && isEnd(u)
      ? { kind: 'touch', point: { x: a1.x + r.x * t, y: a1.y + r.y * t } }
      : { kind: 'violation' };
  }
  if (Math.abs(cross(a1, a2, b1)) > EPS) return { kind: 'clear' };
  const length = Math.hypot(r.x, r.y),
    axis = { x: r.x / length, y: r.y / length },
    at = (p: LayoutPoint) => (p.x - a1.x) * axis.x + (p.y - a1.y) * axis.y;
  const low = Math.max(0, Math.min(at(b1), at(b2))),
    high = Math.min(length, Math.max(at(b1), at(b2)));
  if (high < low - 1e-6) return { kind: 'clear' };
  if (high - low > 1e-6) return { kind: 'violation' };
  return near(low, 0) || near(low, length)
    ? { kind: 'touch', point: { x: a1.x + axis.x * low, y: a1.y + axis.y * low } }
    : { kind: 'violation' };
}
/**
 * Two routes may meet only where they genuinely share a graph vertex — the fan
 * origin of two uplinks out of one parent. Any other junction is accidental.
 */
function sharesTerminusAt(a: LayoutEdge, b: LayoutEdge, point: LayoutPoint): boolean {
  const termini = (edge: LayoutEdge) => [
    { node: edge.source, at: edge.points[0] },
    { node: edge.target, at: edge.points[edge.points.length - 1] },
  ];
  const here = (p: LayoutPoint) => near(p.x, point.x) && near(p.y, point.y);
  return termini(a).some((one) =>
    termini(b).some((other) => one.node === other.node && here(one.at) && here(other.at)),
  );
}

/** True when the segment runs through the rectangle, not merely grazing a corner. */
function hitsRect([p, q]: Segment, rect: LayoutRect): boolean {
  const dx = q.x - p.x,
    dy = q.y - p.y,
    limits: [number, number][] = [
      [-dx, p.x - rect.left],
      [dx, rect.right - p.x],
      [-dy, p.y - rect.top],
      [dy, rect.bottom - p.y],
    ];
  let enter = 0,
    exit = 1;
  for (const [edge, offset] of limits) {
    if (Math.abs(edge) < EPS) {
      if (offset < -EPS) return false;
      continue;
    }
    const t = offset / edge;
    if (edge < 0) {
      if (t > exit) return false;
      enter = Math.max(enter, t);
    } else {
      if (t < enter) return false;
      exit = Math.min(exit, t);
    }
  }
  return exit - enter > 1e-6;
}

function treeEdges(layout: TopologyLayout) {
  return layout.edges.filter((edge) => edge.kind === 'tree');
}
/** The three routing guarantees, plus node separation. Secondary edges are exempt. */
function assertRoutingInvariants(layout: TopologyLayout) {
  const tree = treeEdges(layout);
  for (let i = 0; i < tree.length; i++)
    for (let j = i + 1; j < tree.length; j++)
      for (const first of segmentsOf(tree[i]))
        for (const second of segmentsOf(tree[j])) {
          const meeting = relate(first, second),
            stray =
              meeting.kind === 'violation' ||
              (meeting.kind === 'touch' &&
                !sharesTerminusAt(tree[i], tree[j], meeting.point as LayoutPoint));
          expect(`${tree[i].id} vs ${tree[j].id}: ${stray ? meeting.kind : 'clear'}`).toContain(
            'clear',
          );
        }
  for (const edge of tree)
    for (const segment of segmentsOf(edge))
      for (const [id, node] of layout.nodes)
        if (id !== edge.source && id !== edge.target)
          expect(`${edge.id} through ${id}: ${hitsRect(segment, nodeRect(node))}`).not.toContain(
            'true',
          );
  const placed = [...layout.nodes.values()];
  for (let i = 0; i < placed.length; i++)
    for (let j = i + 1; j < placed.length; j++) {
      const a = nodeRect(placed[i]),
        b = nodeRect(placed[j]),
        overlap =
          a.left < b.right - EPS &&
          b.left < a.right - EPS &&
          a.top < b.bottom - EPS &&
          b.top < a.bottom - EPS;
      expect(`${placed[i].id} over ${placed[j].id}: ${overlap}`).not.toContain('true');
    }
}
/** Everything an assertion could depend on, order-normalised. */
function shapeOf(layout: TopologyLayout) {
  const round = (value: number) => Math.round(value * 1e4) / 1e4;
  return {
    width: round(layout.width),
    height: round(layout.height),
    nodes: [...layout.nodes.values()]
      .map((node) => `${node.id}@${round(node.x)},${round(node.y)}`)
      .sort(),
    edges: layout.edges
      .map(
        (edge) =>
          `${edge.kind}:${edge.id}:${edge.points.map((p) => `${round(p.x)},${round(p.y)}`).join('|')}`,
      )
      .sort(),
  };
}

const dev = (id: string, tier: number, parent: string | null = null, name = id): LayoutDevice => ({
  id,
  name,
  tier,
  parent,
});
const SWITCHES = ['b', 'c', 'd', 'e', 'f', 'g', 'h'];
/** Shaped like the reported site: one gateway, one core, seven access, twenty APs. */
function reportedSite(): { devices: LayoutDevice[]; links: LayoutLink[] } {
  const devices = [dev('gw', 0, null, 'LD_CUP_SRX_11'), dev('core', 1, 'gw', 'ld-cup-idf-a-core')];
  for (const key of SWITCHES) devices.push(dev(`sw-${key}`, 2, 'core', `ld-cup-idf-${key}`));
  for (let index = 0; index < 20; index++)
    devices.push(
      dev(
        `ap-${index}`,
        3,
        `sw-${SWITCHES[index % SWITCHES.length]}`,
        `LD_AP_${String(index).padStart(2, '0')}`,
      ),
    );
  const links = devices.flatMap((item) =>
    item.parent ? [{ source: item.parent, target: item.id }] : [],
  );
  return { devices, links };
}

describe('topology layout', () => {
  it('routes the reported site without crossings, overlaps or node collisions', () => {
    const { devices, links } = reportedSite(),
      layout = layoutTopology(devices, links);
    expect(layout.nodes.size).toBe(29);
    expect(treeEdges(layout)).toHaveLength(28);
    expect(layout.edges.filter((edge) => edge.kind === 'secondary')).toHaveLength(0);
    assertRoutingInvariants(layout);
  });
  it('trades the single wide row for a canvas the pane can actually fit', () => {
    const { devices, links } = reportedSite(),
      layout = layoutTopology(devices, links);
    // The tiered row layout it replaces was ~3750 x 530 for this site.
    expect(layout.width).toBeLessThan(1800);
    expect(layout.height).toBeGreaterThan(600);
    expect(layout.width / layout.height).toBeLessThan(3);
  });
  it('stacks every access point under its own switch', () => {
    const { devices, links } = reportedSite(),
      layout = layoutTopology(devices, links);
    for (const key of SWITCHES) {
      const parent = layout.nodes.get(`sw-${key}`) as LayoutPoint;
      const stack = [...layout.nodes.values()].filter(
        (node) => devices.find((item) => item.id === node.id)?.parent === `sw-${key}`,
      );
      expect(stack.length).toBeGreaterThan(1);
      expect(new Set(stack.map((node) => node.x)).size).toBe(1);
      for (const leaf of stack) expect(leaf.y).toBeGreaterThan(parent.y);
    }
  });
  it('wraps a stack deeper than the cap into further sub-columns', () => {
    const devices = [
        dev('sw', 2),
        ...Array.from({ length: 30 }, (_, i) => dev(`ap-${i}`, 3, 'sw')),
      ],
      layout = layoutTopology(devices, []),
      leaves = devices.slice(1).map((item) => layout.nodes.get(item.id) as LayoutPoint);
    expect(new Set(leaves.map((leaf) => leaf.x)).size).toBe(30 / DEFAULT_STACK_DEPTH);
    expect(new Set(leaves.map((leaf) => leaf.y)).size).toBe(DEFAULT_STACK_DEPTH);
    assertRoutingInvariants(layout);
  });
  it('gives each wrapped sub-column its own gutter, so the lanes stay clear', () => {
    const devices = [
        dev('sw', 2),
        ...Array.from({ length: 12 }, (_, i) => dev(`ap-${i}`, 3, 'sw')),
      ],
      layout = layoutTopology(devices, [], { maxStackDepth: 6 }),
      lanes = treeEdges(layout).map((edge) => edge.points[1].x);
    expect(new Set(lanes).size).toBe(12);
    assertRoutingInvariants(layout);
  });
  it('keeps a forest of disconnected roots apart', () => {
    const devices = [
      dev('sw-a', 2),
      dev('ap-a', 3, 'sw-a'),
      dev('sw-b', 2),
      dev('ap-b', 3, 'sw-b'),
    ];
    const layout = layoutTopology(devices, [
      { source: 'sw-a', target: 'ap-a' },
      { source: 'sw-b', target: 'ap-b' },
    ]);
    expect(layout.nodes.size).toBe(4);
    assertRoutingInvariants(layout);
  });
  it('routes redundant and lateral links as secondary without disturbing the tree', () => {
    const devices = [
      dev('gw', 0),
      dev('core-a', 1, 'gw'),
      dev('core-b', 1, 'gw'),
      dev('sw', 2, 'core-a'),
    ];
    const layout = layoutTopology(devices, [
      { source: 'gw', target: 'core-a' },
      { source: 'gw', target: 'core-b' },
      { source: 'core-a', target: 'core-b' },
      { source: 'core-b', target: 'sw' },
    ]);
    expect(
      treeEdges(layout)
        .map((edge) => edge.id)
        .sort(),
    ).toEqual(['core-a:sw', 'gw:core-a', 'gw:core-b']);
    const secondary = layout.edges.filter((edge) => edge.kind === 'secondary');
    expect(secondary.map((edge) => edge.id).sort()).toEqual(['core-a:core-b', 'core-b:sw']);
    for (const edge of secondary) expect(edge.shape).toBe('curve');
    assertRoutingInvariants(layout);
  });
  it('keeps a loose node out of a tier-skipping tree corridor', () => {
    const devices = [dev('gw-a', 0), dev('gw-b', 0), dev('core', 1), dev('sw', 2, 'gw-a')];
    const layout = layoutTopology(devices, [
      { source: 'gw-a', target: 'sw' },
      { source: 'gw-a', target: 'core' },
      { source: 'gw-b', target: 'core' },
    ]);
    expect(layout.nodes.size).toBe(4);
    // `core` has no parent, so its barycentre is gw-a's column — which is exactly
    // where the gw-a to sw descent runs, skipping the tier `core` sits on.
    const corridor = treeEdges(layout).find((edge) => edge.id === 'gw-a:sw') as LayoutEdge;
    expect(corridor.points[1].x).not.toBeCloseTo((layout.nodes.get('core') as LayoutPoint).x);
    assertRoutingInvariants(layout);
  });
  it('places a device whose parent is absent from the topology', () => {
    const layout = layoutTopology(
      [dev('sw', 2), dev('ap', 3, 'ghost')],
      [{ source: 'sw', target: 'ap' }],
    );
    expect(layout.nodes.size).toBe(2);
    expect(treeEdges(layout)).toHaveLength(0);
    assertRoutingInvariants(layout);
  });
  it('breaks a parent cycle deterministically instead of hanging', () => {
    const devices = [dev('bbb', 2, 'aaa'), dev('aaa', 2, 'ccc'), dev('ccc', 2, 'bbb')];
    const layout = layoutTopology(devices, []);
    expect(layout.nodes.size).toBe(3);
    expect(treeEdges(layout)).toHaveLength(0);
    expect(layout.edges.some((edge) => edge.id.includes('aaa'))).toBe(true);
    expect(shapeOf(layout)).toEqual(shapeOf(layoutTopology([...devices].reverse(), [])));
  });
  it('separates devices that share a name, breaking the tie on id', () => {
    const devices = [
      dev('b2', 2, null, 'same'),
      dev('a1', 2, null, 'same'),
      dev('c3', 3, 'a1', 'same'),
    ];
    const layout = layoutTopology(devices, []);
    expect(layout.nodes.size).toBe(3);
    assertRoutingInvariants(layout);
    expect(shapeOf(layout)).toEqual(shapeOf(layoutTopology([...devices].reverse(), [])));
  });
  it('settles an orphan chain of any length by distance from the rooted forest', () => {
    const devices = [dev('sw', 2), dev('ap', 3, 'sw'), dev('o1', 2), dev('o2', 2), dev('o3', 2)];
    const links = [
      { source: 'sw', target: 'ap' },
      { source: 'sw', target: 'o1' },
      { source: 'o1', target: 'o2' },
      { source: 'o2', target: 'o3' },
    ];
    const layout = layoutTopology(devices, links);
    expect(layout.nodes.size).toBe(5);
    for (const id of ['o1', 'o2', 'o3']) expect(layout.nodes.has(id)).toBe(true);
    assertRoutingInvariants(layout);
  });
  it('still places devices with no link evidence at all', () => {
    const devices = [dev('x1', 3), dev('x2', 3), dev('x3', 3)];
    const layout = layoutTopology(devices, []);
    expect(layout.nodes.size).toBe(3);
    expect(new Set([...layout.nodes.values()].map((node) => node.x)).size).toBe(3);
    assertRoutingInvariants(layout);
  });
  it('returns an empty canvas for an empty site', () => {
    const layout = layoutTopology([], []);
    expect(layout.nodes.size).toBe(0);
    expect(layout.edges).toHaveLength(0);
    expect(layout.width).toBeGreaterThan(0);
  });
  it('depends on nothing but the devices, the links and the options', () => {
    const { devices, links } = reportedSite();
    const forward = layoutTopology(devices, links),
      reversed = layoutTopology([...devices].reverse(), [...links].reverse());
    expect(shapeOf(reversed)).toEqual(shapeOf(forward));
    expect(shapeOf(layoutTopology(devices, links))).toEqual(shapeOf(forward));
    expect(shapeOf(layoutTopology(devices, links, { maxStackDepth: 2 }))).not.toEqual(
      shapeOf(forward),
    );
  });
  it('keeps every node and every routed point inside the reported canvas', () => {
    const { devices, links } = reportedSite(),
      layout = layoutTopology(devices, links);
    for (const node of layout.nodes.values()) {
      const rect = nodeRect(node);
      expect(rect.left).toBeGreaterThanOrEqual(0);
      expect(rect.top).toBeGreaterThanOrEqual(0);
      expect(rect.right).toBeLessThanOrEqual(layout.width);
      expect(rect.bottom).toBeLessThanOrEqual(layout.height);
    }
    for (const edge of layout.edges)
      for (const point of edge.points) {
        expect(point.x).toBeGreaterThanOrEqual(0);
        expect(point.y).toBeGreaterThanOrEqual(0);
        expect(point.x).toBeLessThanOrEqual(layout.width);
        expect(point.y).toBeLessThanOrEqual(layout.height);
      }
  });
});
