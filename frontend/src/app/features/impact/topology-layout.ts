/**
 * Deterministic geometry for the site topology.
 *
 * The viewport is deliberately not an input: layout depends only on the devices,
 * their observed links and explicit options, so resizing the pane can never
 * reflow the graph. Tree edges are routed orthogonally and carry three
 * guarantees, asserted in the spec: they do not cross, they do not overlap
 * except at shared endpoints, and they do not intersect unrelated node
 * rectangles. Secondary edges carry no geometric guarantee at all.
 */
import { TopologyDevice, TopologyLink } from './site-impact.model';

export type LayoutDevice = Pick<TopologyDevice, 'id' | 'name' | 'tier' | 'parent'>;
export type LayoutLink = Pick<TopologyLink, 'source' | 'target'>;

/** The anchor point is the icon centre; the button is laid out from its top-left. */
export const NODE_WIDTH = 173;
export const NODE_HEIGHT = 52;
export const NODE_PAD_LEFT = 21;
export const NODE_PAD_TOP = 26;
export const COL_GAP = 24;
export const ROW_TOP = 50;
export const ROW_GAP = 130;
/** Access row to the first stacked leaf; also the depth the uplink fan needs. */
export const STACK_GAP = 140;
export const STACK_PITCH = 62;
export const LANE = 7;
export const LANE_CLEAR = 12;
export const FAN_DROP = 34;
export const MARGIN = 40;
export const DEFAULT_STACK_DEPTH = 6;

export interface LayoutPoint {
  x: number;
  y: number;
}
export interface LayoutNode extends LayoutPoint {
  id: string;
}
export interface LayoutRect {
  left: number;
  top: number;
  right: number;
  bottom: number;
}
export interface LayoutEdge {
  id: string;
  source: string;
  target: string;
  kind: 'tree' | 'secondary';
  /** `elbow` points are a polyline; `curve` points are a cubic control polygon. */
  shape: 'elbow' | 'curve';
  points: LayoutPoint[];
}
export interface TopologyLayout {
  nodes: Map<string, LayoutNode>;
  edges: LayoutEdge[];
  width: number;
  height: number;
}
export interface LayoutOptions {
  maxStackDepth?: number;
}

export function rowY(tier: number): number {
  return tier >= 3 ? ROW_TOP + 2 * ROW_GAP + STACK_GAP : ROW_TOP + tier * ROW_GAP;
}
export function nodeRect(point: LayoutPoint): LayoutRect {
  const left = point.x - NODE_PAD_LEFT,
    top = point.y - NODE_PAD_TOP;
  return { left, top, right: left + NODE_WIDTH, bottom: top + NODE_HEIGHT };
}
/** A stack sub-column reserves one lane per leaf to the left of its icons. */
function gutterWidth(count: number): number {
  return count ? LANE_CLEAR + count * LANE : 0;
}
function slotWidth(count: number): number {
  return gutterWidth(count) + NODE_WIDTH;
}
function chunkEvenly<T>(items: readonly T[], maxSize: number): T[][] {
  if (!items.length) return [];
  const count = Math.ceil(items.length / maxSize),
    base = Math.floor(items.length / count),
    extra = items.length % count,
    out: T[][] = [];
  let at = 0;
  for (let index = 0; index < count; index++) {
    const size = base + (index < extra ? 1 : 0);
    out.push(items.slice(at, at + size));
    at += size;
  }
  return out;
}
function clamp(value: number, low: number, high: number): number {
  return Math.min(Math.max(value, low), Math.max(low, high));
}
function pairKey(a: string, b: string): string {
  return a < b ? `${a} ${b}` : `${b} ${a}`;
}

type Block = { kind: 'child'; id: string } | { kind: 'stack'; ids: string[] };
interface ParentEdge {
  source: string;
  target: string;
}

/**
 * One parent per node, with every component rooted. Well-formed tier data cannot
 * produce a parent cycle, but malformed input must not hang the walk, so cycles
 * are broken explicitly: the lowest id in the cycle loses its parent edge, and
 * that edge is reclassified as secondary. A parent that does not sit on a higher
 * row is reclassified the same way, because the router cannot descend to it.
 */
function rootedForest(
  device: Map<string, LayoutDevice>,
  order: readonly string[],
  tierOf: (id: string) => number,
): { parent: Map<string, string>; children: Map<string, string[]>; demoted: ParentEdge[] } {
  const parent = new Map<string, string>(),
    demoted: ParentEdge[] = [];
  for (const id of order) {
    const candidate = device.get(id)?.parent;
    if (candidate && candidate !== id && device.has(candidate)) parent.set(id, candidate);
  }
  const state = new Map<string, 'open' | 'done'>();
  for (const start of order) {
    if (state.has(start)) continue;
    const path: string[] = [];
    let node: string | undefined = start;
    while (node !== undefined && !state.has(node)) {
      state.set(node, 'open');
      path.push(node);
      node = parent.get(node);
    }
    if (node !== undefined && state.get(node) === 'open') {
      const cycle = path.slice(path.indexOf(node)),
        lowest = cycle.reduce((a, b) => (a < b ? a : b));
      demoted.push({ source: lowest, target: parent.get(lowest) as string });
      parent.delete(lowest);
    }
    for (const id of path) state.set(id, 'done');
  }
  for (const id of order) {
    const above = parent.get(id);
    if (above !== undefined && rowY(tierOf(above)) >= rowY(tierOf(id))) {
      demoted.push({ source: id, target: above });
      parent.delete(id);
    }
  }
  const children = new Map<string, string[]>();
  for (const id of order) {
    const above = parent.get(id);
    if (above === undefined) continue;
    const list = children.get(above);
    if (list) list.push(id);
    else children.set(above, [id]);
  }
  return { parent, children, demoted };
}

export function layoutTopology(
  devices: readonly LayoutDevice[],
  links: readonly LayoutLink[] = [],
  options: LayoutOptions = {},
): TopologyLayout {
  const maxDepth = Math.max(1, Math.trunc(options.maxStackDepth ?? DEFAULT_STACK_DEPTH));
  const device = new Map(devices.map((item) => [item.id, item]));
  const tierOf = (id: string) => {
    const value = device.get(id)?.tier;
    return typeof value === 'number' && Number.isFinite(value) ? clamp(Math.round(value), 0, 3) : 2;
  };
  // Canonical order drives every tie-break, so the result never depends on the
  // order devices or links arrive in.
  const order = [...device.values()]
    .sort((a, b) => {
      const left = a.name.toLowerCase(),
        right = b.name.toLowerCase();
      return left < right ? -1 : left > right ? 1 : a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
    })
    .map((item) => item.id);
  const rank = new Map(order.map((id, index) => [id, index]));
  const rankOf = (id: string) => rank.get(id) ?? 0;
  const { parent, children, demoted } = rootedForest(device, order, tierOf);

  const nodes = new Map<string, LayoutNode>();
  const laneIndex = new Map<string, number>();
  const rows = new Map<number, LayoutRect[]>();
  const occupy = (node: LayoutNode) => {
    const rect = nodeRect(node),
      list = rows.get(rect.top) ?? [];
    list.push(rect);
    list.sort((a, b) => a.left - b.left);
    rows.set(rect.top, list);
  };
  const isStackLeaf = (id: string) => tierOf(id) === 3 && !children.has(id);

  const blocks = new Map<string, Block[]>();
  const blockOf = (id: string): Block[] => {
    const cached = blocks.get(id);
    if (cached) return cached;
    const kids = children.get(id) ?? [];
    const built: Block[] = [
      ...kids
        .filter((kid) => !isStackLeaf(kid))
        .map((kid) => ({ kind: 'child' as const, id: kid })),
      ...chunkEvenly(kids.filter(isStackLeaf), maxDepth).map((ids) => ({
        kind: 'stack' as const,
        ids,
      })),
    ];
    blocks.set(id, built);
    return built;
  };
  const widths = new Map<string, number>();
  const itemWidth = (block: Block) =>
    block.kind === 'child' ? subtreeWidth(block.id) : slotWidth(block.ids.length);
  const blockWidth = (id: string) => {
    const built = blockOf(id);
    return built.length
      ? built.reduce((sum, block) => sum + itemWidth(block), 0) + COL_GAP * (built.length - 1)
      : 0;
  };
  function subtreeWidth(id: string): number {
    const cached = widths.get(id);
    if (cached !== undefined) return cached;
    widths.set(id, NODE_WIDTH);
    const width = Math.max(NODE_WIDTH, blockWidth(id));
    widths.set(id, width);
    return width;
  }
  const placeStack = (ids: readonly string[], left: number) => {
    const x = left + gutterWidth(ids.length) + NODE_PAD_LEFT;
    ids.forEach((id, index) => {
      const node = { id, x, y: rowY(3) + index * STACK_PITCH };
      laneIndex.set(id, index);
      nodes.set(id, node);
      occupy(node);
    });
    return x;
  };
  const placeSubtree = (id: string, left: number) => {
    const width = subtreeWidth(id),
      built = blockOf(id),
      anchors: number[] = [];
    let cursor = left + (width - blockWidth(id)) / 2;
    for (const block of built) {
      if (block.kind === 'child') {
        placeSubtree(block.id, cursor);
        anchors.push(nodes.get(block.id)?.x ?? cursor + NODE_PAD_LEFT);
      } else anchors.push(placeStack(block.ids, cursor));
      cursor += itemWidth(block) + COL_GAP;
    }
    const centre = anchors.length
      ? (anchors[0] + anchors[anchors.length - 1]) / 2
      : left + NODE_PAD_LEFT;
    const node = {
      id,
      x: clamp(centre, left + NODE_PAD_LEFT, left + width - (NODE_WIDTH - NODE_PAD_LEFT)),
      y: rowY(tierOf(id)),
    };
    nodes.set(id, node);
    occupy(node);
  };

  let cursor = 0;
  for (const id of order)
    if (!parent.has(id) && children.has(id)) {
      placeSubtree(id, cursor);
      cursor += subtreeWidth(id) + COL_GAP;
    }

  // Whatever is left is parentless and childless: dual-homed devices the backend
  // declined to root, and devices known only from an impact record.
  const adjacency = new Map<string, Set<string>>();
  const connect = (a: string, b: string) => {
    if (a === b || !device.has(a) || !device.has(b)) return;
    const forward = adjacency.get(a) ?? new Set<string>();
    forward.add(b);
    adjacency.set(a, forward);
    const back = adjacency.get(b) ?? new Set<string>();
    back.add(a);
    adjacency.set(b, back);
  };
  for (const link of links) connect(link.source, link.target);
  for (const [id, above] of parent) connect(id, above);
  for (const edge of demoted) connect(edge.source, edge.target);

  // The forest is routed before anything loose is placed, so those corridors can
  // act as obstacles too. A loose node dropped on a tier-skipping descent breaks
  // the node-clearance guarantee even when it overlaps no other node.
  const edges: LayoutEdge[] = [];
  const seen = new Set<string>();
  for (const id of order) {
    const above = parent.get(id),
      to = nodes.get(id);
    const from = above === undefined ? undefined : nodes.get(above);
    if (above === undefined || !from || !to) continue;
    seen.add(pairKey(above, id));
    const start = { x: from.x, y: from.y + NODE_PAD_TOP },
      fan = start.y + FAN_DROP,
      lane = laneIndex.get(id),
      laneX = to.x - NODE_PAD_LEFT - LANE_CLEAR - (lane ?? 0) * LANE;
    edges.push({
      id: `${above}:${id}`,
      source: above,
      target: id,
      kind: 'tree',
      shape: 'elbow',
      points:
        lane === undefined
          ? [start, { x: to.x, y: fan }, { x: to.x, y: to.y - NODE_PAD_TOP }]
          : [
              start,
              { x: laneX, y: fan },
              { x: laneX, y: to.y },
              { x: to.x - NODE_PAD_LEFT, y: to.y },
            ],
    });
  }
  /** Left edges at which a node box on this row would foul a routed tree edge. */
  const corridors = (top: number): [number, number][] => {
    const bottom = top + NODE_HEIGHT,
      spans: [number, number][] = [];
    for (const edge of edges)
      if (edge.kind === 'tree')
        for (let index = 1; index < edge.points.length; index++) {
          const a = edge.points[index - 1],
            b = edge.points[index];
          if (Math.max(a.y, b.y) <= top || Math.min(a.y, b.y) >= bottom) continue;
          const atY = (y: number) => a.x + ((b.x - a.x) * (y - a.y)) / (b.y - a.y);
          const xs =
            Math.abs(b.y - a.y) < 1e-9
              ? [a.x, b.x]
              : [atY(Math.max(top, Math.min(a.y, b.y))), atY(Math.min(bottom, Math.max(a.y, b.y)))];
          spans.push([Math.min(...xs) - NODE_WIDTH - COL_GAP, Math.max(...xs) + COL_GAP]);
        }
    return spans;
  };
  const placeLoose = (id: string, desired: number) => {
    const y = rowY(tierOf(id)),
      top = y - NODE_PAD_TOP;
    const blocked: [number, number][] = [
      ...(rows.get(top) ?? []).map(
        (rect) => [rect.left - NODE_WIDTH - COL_GAP, rect.right + COL_GAP] as [number, number],
      ),
      ...corridors(top),
    ]
      .filter(([low, high]) => high > low)
      .sort((first, second) => first[0] - second[0]);
    const merged: [number, number][] = [];
    for (const span of blocked) {
      const last = merged.at(-1);
      if (last && span[0] <= last[1]) last[1] = Math.max(last[1], span[1]);
      else merged.push([span[0], span[1]]);
    }
    // Merged spans are disjoint and ascending, so one forward pass settles on the
    // nearest free edge; ties fall to the left for a stable result.
    let left = desired - NODE_PAD_LEFT;
    for (const [low, high] of merged)
      if (left > low && left < high) left = left - low <= high - left ? low : high;
    const node = { id, x: left + NODE_PAD_LEFT, y };
    nodes.set(id, node);
    occupy(node);
  };

  // Distance waves out of the rooted forest: an orphan settles at the barycentre
  // of the neighbours already placed, so orphan chains of any length resolve in
  // one O(V + E) pass.
  const distance = new Map<string, number>();
  let frontier = order.filter((id) => nodes.has(id));
  for (const id of frontier) distance.set(id, 0);
  while (frontier.length) {
    const next: string[] = [];
    for (const id of frontier)
      for (const neighbour of adjacency.get(id) ?? [])
        if (!distance.has(neighbour)) {
          distance.set(neighbour, (distance.get(id) ?? 0) + 1);
          next.push(neighbour);
        }
    next.sort((a, b) => rankOf(a) - rankOf(b));
    for (const id of next) {
      // Sum in canonical order so the barycentre cannot depend on the order the
      // adjacency set happened to be built in.
      const placed = [...(adjacency.get(id) ?? [])]
        .sort((a, b) => rankOf(a) - rankOf(b))
        .flatMap((neighbour) => {
          const node = nodes.get(neighbour);
          return node ? [node.x] : [];
        });
      placeLoose(id, placed.length ? placed.reduce((sum, x) => sum + x, 0) / placed.length : 0);
    }
    frontier = next;
  }
  // No link evidence at all: append to the right of the device's own row.
  for (const id of order)
    if (!nodes.has(id)) {
      const top = rowY(tierOf(id)) - NODE_PAD_TOP,
        right = (rows.get(top) ?? []).reduce((edge, rect) => Math.max(edge, rect.right), 0);
      placeLoose(id, right + COL_GAP + NODE_PAD_LEFT);
    }

  const secondary = [...demoted, ...links]
    .flatMap((link) => {
      const a = nodes.get(link.source),
        b = nodes.get(link.target);
      if (!a || !b || a.id === b.id) return [];
      return rankOf(a.id) <= rankOf(b.id) ? [[a, b]] : [[b, a]];
    })
    .sort((x, y) => rankOf(x[0].id) - rankOf(y[0].id) || rankOf(x[1].id) - rankOf(y[1].id));
  for (const [a, b] of secondary) {
    const key = pairKey(a.id, b.id);
    if (seen.has(key)) continue;
    seen.add(key);
    const [upper, lower] = a.y <= b.y ? [a, b] : [b, a],
      lateral = upper.y === lower.y,
      y1 = upper.y + (lateral ? -NODE_PAD_TOP : NODE_PAD_TOP),
      y2 = lower.y - NODE_PAD_TOP,
      mid = lateral ? y1 - 55 : (y1 + y2) / 2;
    edges.push({
      id: `${a.id}:${b.id}`,
      source: a.id,
      target: b.id,
      kind: 'secondary',
      shape: 'curve',
      points: [
        { x: upper.x, y: y1 },
        { x: upper.x, y: mid },
        { x: lower.x, y: mid },
        { x: lower.x, y: y2 },
      ],
    });
  }

  if (!nodes.size) return { nodes, edges, width: 2 * MARGIN, height: 2 * MARGIN };
  let minX = Infinity,
    minY = Infinity,
    maxX = -Infinity,
    maxY = -Infinity;
  const extend = (x: number, y: number) => {
    minX = Math.min(minX, x);
    minY = Math.min(minY, y);
    maxX = Math.max(maxX, x);
    maxY = Math.max(maxY, y);
  };
  for (const node of nodes.values()) {
    const rect = nodeRect(node);
    extend(rect.left, rect.top);
    extend(rect.right, rect.bottom);
  }
  for (const edge of edges) for (const point of edge.points) extend(point.x, point.y);
  const dx = MARGIN - minX,
    dy = MARGIN - minY;
  for (const node of [...nodes.values()])
    nodes.set(node.id, { ...node, x: node.x + dx, y: node.y + dy });
  for (const edge of edges)
    edge.points = edge.points.map((point) => ({ x: point.x + dx, y: point.y + dy }));
  return { nodes, edges, width: maxX - minX + 2 * MARGIN, height: maxY - minY + 2 * MARGIN };
}
