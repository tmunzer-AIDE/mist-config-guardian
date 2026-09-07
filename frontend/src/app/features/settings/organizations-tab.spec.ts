import { CRON_PRESETS, nextCronRun, presetForCron } from './organizations-tab';

describe('reconciliation schedule presets', () => {
  it('offers exactly the four intervals the design names', () => {
    expect(CRON_PRESETS.map((preset) => preset.label)).toEqual([
      'every 12 hours',
      'every day',
      'every week',
      'every month',
    ]);
  });

  it('maps each preset to its cron expression and back', () => {
    for (const preset of CRON_PRESETS) {
      expect(presetForCron(preset.cron)).toBe(preset);
    }
    expect(presetForCron('0 2 * * *')?.label).toBe('every day');
    expect(presetForCron('0 2,14 * * *')?.label).toBe('every 12 hours');
    expect(presetForCron('0 2 * * 0')?.label).toBe('every week');
    expect(presetForCron('0 2 1 * *')?.label).toBe('every month');
  });

  it('tolerates irregular spacing in a stored expression', () => {
    expect(presetForCron('  0   2 * * *  ')?.label).toBe('every day');
  });

  it('reports a cron expression outside the presets as custom', () => {
    expect(presetForCron('*/15 * * * *')).toBeNull();
    expect(presetForCron('0 3 * * *')).toBeNull();
  });
});

describe('nextCronRun', () => {
  // Tuesday 07 Sep 2026, 14:18 UTC.
  const from = new Date(Date.UTC(2026, 8, 7, 14, 18));

  it('finds the next of two daily runs', () => {
    expect(nextCronRun('0 2,14 * * *', from)?.toISOString()).toBe('2026-09-08T02:00:00.000Z');
  });

  it('rolls a daily run over to tomorrow once today has passed', () => {
    expect(nextCronRun('0 2 * * *', from)?.toISOString()).toBe('2026-09-08T02:00:00.000Z');
  });

  it('finds the next Sunday for a weekly run', () => {
    const next = nextCronRun('0 2 * * 0', from);
    expect(next?.getUTCDay()).toBe(0);
    expect(next?.toISOString()).toBe('2026-09-13T02:00:00.000Z');
  });

  it('finds the first of next month for a monthly run', () => {
    expect(nextCronRun('0 2 1 * *', from)?.toISOString()).toBe('2026-10-01T02:00:00.000Z');
  });

  it('understands step and range expressions a hand-edited schedule may hold', () => {
    expect(nextCronRun('*/15 * * * *', from)?.toISOString()).toBe('2026-09-07T14:30:00.000Z');
    expect(nextCronRun('0 9-17 * * *', from)?.toISOString()).toBe('2026-09-07T15:00:00.000Z');
  });

  it('returns null rather than a wrong time for an expression it cannot read', () => {
    expect(nextCronRun('nonsense')).toBeNull();
    expect(nextCronRun('0 2 * *')).toBeNull();
    expect(nextCronRun('0 99 * * *')).toBeNull();
  });
});
