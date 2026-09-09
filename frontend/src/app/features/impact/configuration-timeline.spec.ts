import { configurationTimeline } from './configuration-timeline';
import { MonitoringSession } from './monitoring.model';

describe('configuration timeline', () => {
  it('orders observed milestones by event time and preserves receipt time', () => {
    const session = {
      timeline: [
        {
          key: 'confirmed',
          event_type: 'SW_CONFIGURED',
          occurred_at: '2026-09-09T12:02:00Z',
          received_at: '2026-09-09T12:03:00Z',
        },
        {
          key: 'changed',
          event_type: 'SW_CONFIG_CHANGED_BY_USER',
          occurred_at: '2026-09-09T12:01:00Z',
          received_at: '2026-09-09T12:04:00Z',
        },
      ],
      change_groups: [
        {
          id: 'g1',
          audit_id: 'a1',
          title: 'Template updated',
          occurred_at: '2026-09-09T12:00:00Z',
        },
      ],
    } as MonitoringSession;
    const rows = configurationTimeline(session);
    expect(rows.map((row) => row.key)).toEqual(['audit:g1', 'changed', 'confirmed']);
    expect(rows[1].received).toBe('2026-09-09T12:04:00Z');
  });
  it('does not invent deployment stages for an empty historical session', () => {
    expect(configurationTimeline({} as MonitoringSession)).toEqual([]);
  });
});
