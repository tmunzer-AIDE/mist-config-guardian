import { alignRawLines } from './raw-diff';
import { renderDocument } from './diff.model';

describe('Raw JSON alignment', () => {
  it('aligns unchanged lines after additions with their original line numbers', () => {
    const rows = alignRawLines(['{', '  "z": 1', '}'], ['{', '  "a": 2,', '  "z": 1', '}']);
    expect(rows.map(row => [row.beforeNumber, row.afterNumber, row.changed])).toEqual([
      [1, 1, false], [null, 2, true], [2, 3, false], [3, 4, false],
    ]);
    expect(rows[1].after).toBe('  "a": 2,');
  });

  it('pairs replacements and leaves gaps for removed lines', () => {
    const rows = alignRawLines(['{', 'old', 'removed', '}'], ['{', 'new', '}']);
    expect(rows.map(row => [row.before, row.after, row.changed])).toEqual([
      ['{', '{', false], ['old', 'new', true], ['removed', '', true], ['}', '}', false],
    ]);
    expect(rows[2].afterNumber).toBeNull();
  });

  it('does not mark key ordering or identical secret placeholders as changes', () => {
    const rows = alignRawLines(renderDocument({ z: 1, nested: { secret: '********', a: true } }),
      renderDocument({ nested: { a: true, secret: '********' }, z: 1 }));
    expect(rows.every(row => !row.changed)).toBe(true);
  });

  it('preserves every line and number through empty, repeated and reordered inputs', () => {
    const inputs = [[], ['a'], ['b'], ['a', 'a'], ['a', 'b'], ['b', 'a'], ['a', 'b', 'a'], ['b', 'a', 'b']];
    for (const before of inputs) for (const after of inputs) {
      const rows = alignRawLines(before, after);
      expect(rows.filter(row => row.beforeNumber !== null).map(row => row.before)).toEqual(before);
      expect(rows.filter(row => row.afterNumber !== null).map(row => row.after)).toEqual(after);
      expect(rows.filter(row => row.beforeNumber !== null).map(row => row.beforeNumber))
        .toEqual(before.map((_, index) => index + 1));
      expect(rows.filter(row => row.afterNumber !== null).map(row => row.afterNumber))
        .toEqual(after.map((_, index) => index + 1));
      expect(rows.filter(row => !row.changed).every(row => row.before === row.after)).toBe(true);
    }
  });

  it('keeps large rewrites bounded while preserving common lines and both documents', () => {
    const before = Array.from({ length: 2000 }, (_, i) => `before ${i}`);
    const after = Array.from({ length: 2000 }, (_, i) => `after ${i}`);
    before.splice(1000, 0, 'common');
    after.splice(1200, 0, 'common');
    const rows = alignRawLines(before, after);
    expect(rows.filter(row => !row.changed).map(row => row.before)).toEqual(['common']);
    expect(rows.filter(row => row.beforeNumber !== null).map(row => row.before)).toEqual(before);
    expect(rows.filter(row => row.afterNumber !== null).map(row => row.after)).toEqual(after);
  });
});
