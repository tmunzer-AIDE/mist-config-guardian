/** Aligned lines of the already-redacted JSON, with original line numbers. */
export interface RawRow {
  index: number;
  before: string;
  after: string;
  beforeNumber: number | null;
  afterNumber: number | null;
  changed: boolean;
}

type Match = readonly [number, number];

/** Myers line alignment; cap frontier history to keep large rewrites bounded. */
function matches(before: readonly string[], after: readonly string[]): Match[] {
  let frontier = new Map<number, number>([[1, 0]]);
  const trace: Map<number, number>[] = [];
  let stored = 0;
  for (let distance = 0; distance <= before.length + after.length; distance++) {
    stored += frontier.size;
    if (stored > 250_000) return orderedMatches(before, after);
    trace.push(new Map(frontier));
    const next = new Map<number, number>();
    for (let diagonal = -distance; diagonal <= distance; diagonal += 2) {
      const down = diagonal === -distance || (diagonal !== distance &&
        (frontier.get(diagonal - 1) ?? -1) < (frontier.get(diagonal + 1) ?? -1));
      let x = down ? frontier.get(diagonal + 1) ?? 0 : (frontier.get(diagonal - 1) ?? 0) + 1;
      let y = x - diagonal;
      while (x < before.length && y < after.length && before[x] === after[y]) { x++; y++; }
      next.set(diagonal, x);
      if (x >= before.length && y >= after.length) {
        const result: Match[] = [];
        for (let step = distance; step >= 0; step--) {
          const previous = trace[step];
          const k = x - y;
          const previousK = k === -step || (k !== step &&
            (previous.get(k - 1) ?? -1) < (previous.get(k + 1) ?? -1)) ? k + 1 : k - 1;
          const previousX = previous.get(previousK) ?? 0;
          const previousY = previousX - previousK;
          while (x > previousX && y > previousY) { result.push([--x, --y]); }
          x = previousX;
          y = previousY;
        }
        return result.reverse();
      }
    }
    frontier = next;
  }
  return [];
}

/** Linear storage fallback: retain equal lines in order without an edit matrix. */
function orderedMatches(before: readonly string[], after: readonly string[]): Match[] {
  const positions = new Map<string, number[]>();
  after.forEach((line, index) => {
    const list = positions.get(line) ?? [];
    list.push(index);
    positions.set(line, list);
  });
  const result: Match[] = [];
  let next = 0;
  before.forEach((line, index) => {
    const list = positions.get(line) ?? [];
    let low = 0;
    let high = list.length;
    while (low < high) {
      const middle = (low + high) >>> 1;
      if (list[middle] < next) low = middle + 1;
      else high = middle;
    }
    if (low < list.length) { result.push([index, list[low]]); next = list[low] + 1; }
  });
  return result;
}

export function alignRawLines(before: readonly string[], after: readonly string[]): RawRow[] {
  const rows: RawRow[] = [];
  let left = 0;
  let right = 0;
  for (const [a, b] of [...matches(before, after), [before.length, after.length] as const]) {
    while (left < a || right < b) {
      const beforeNumber = left < a ? ++left : null;
      const afterNumber = right < b ? ++right : null;
      rows.push({ index: rows.length, beforeNumber, afterNumber, changed: true,
        before: beforeNumber === null ? '' : before[beforeNumber - 1],
        after: afterNumber === null ? '' : after[afterNumber - 1] });
    }
    if (a < before.length && b < after.length) {
      rows.push({ index: rows.length, before: before[left++], after: after[right++],
        beforeNumber: left, afterNumber: right, changed: false });
    }
  }
  return rows;
}
