import { formatAgo, formatCount, formatDate, formatDay, formatDuration, formatInstant, formatTime } from './format';

const AT = new Date('2026-09-07T14:22:00Z');

describe('timestamp formatting', () => {
  it('renders the terse instant form the design uses', () => {
    expect(formatInstant(AT)).toBe('07 SEP 14:22Z');
  });

  it('uses fixed three-letter months rather than locale-dependent ones', () => {
    expect(formatInstant(new Date('2026-09-01T00:00:00Z'))).toContain('SEP');
    expect(formatDate(AT)).toBe('07 Sep 2026');
  });

  it('renders compact times and day separators', () => {
    expect(formatTime(AT)).toBe('14:22Z');
    expect(formatDay(AT)).toBe('MON 07 SEP');
  });

  it('honours a 12-hour clock preference', () => {
    expect(formatTime(AT, { timezone: 'UTC', clock: '12h' })).toContain('PM');
  });

  it('formats durations at minute resolution', () => {
    expect(formatDuration(new Date('2026-09-07T09:12:00Z'), AT)).toBe('5h 10m');
    expect(formatDuration(new Date('2026-09-07T14:00:00Z'), AT)).toBe('22m');
    expect(formatDuration(new Date('2026-09-05T14:00:00Z'), AT)).toBe('2d 0h');
  });

  it('formats coarse relative ages', () => {
    expect(formatAgo(new Date('2026-09-07T13:56:00Z'), AT)).toBe('26M AGO');
    expect(formatAgo(new Date('2026-09-07T11:22:00Z'), AT)).toBe('3H AGO');
    expect(formatAgo(new Date('2026-09-01T14:22:00Z'), AT)).toBe('6D AGO');
  });

  it('groups thousands in object counts', () => {
    expect(formatCount(1284)).toBe('1,284');
  });
});
