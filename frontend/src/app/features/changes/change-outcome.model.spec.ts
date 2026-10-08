import { ChangeGroupDetail } from '../../core/change-group.model';
import { MonitoringSession } from '../impact/monitoring.model';
import {
  changeOutcome,
  interpretationNeedsReview,
  measuredDegradation,
} from './change-outcome.model';

const stable = {
  name: 'gateway-health',
  baseline: 99.89,
  latest: 100,
  delta: 0.11,
  comparable: true,
  selected: true,
};
const detail = {
  id: 'g1',
  occurred_at: '2026-09-19T03:31:00Z',
  impact_severity: 'none',
  recovery_state: 'recovered',
  competing_change_group_ids: ['g2'],
  monitoring_session_ids: ['s1'],
  missing_monitoring_sessions: 0,
  site_impacts: [
    {
      site_id: 'site1',
      site_name: 'DNT-NTR',
      unmonitored_devices: [],
      devices: [
        {
          device_id: 'gateway',
          config_state: 'applied',
          metrics: [
            stable,
            {
              name: 'application-health',
              baseline: null,
              latest: null,
              delta: null,
              baseline_state: 'no_data',
              latest_state: 'no_data',
            },
          ],
          evidence_coverage: 'complete',
          completed_at: '2026-09-19T04:33:00Z',
        },
      ],
    },
  ],
} as unknown as ChangeGroupDetail;
const session = {
  id: 's1',
  device_name: 'SSR400C',
  incidents: [
    {
      event_type: 'GW_CONFIG_FAILED',
      occurred_at: '2026-09-19T03:23:00Z',
      resolved: true,
      resolved_at: '2026-09-19T03:32:00Z',
      severity: 'critical',
    },
  ],
  audit_ids: ['a1', 'a2'],
  completed_at: '2026-09-19T04:33:00Z',
  observations: [],
  impact_severity: 'none',
  assessment: { severity: 'none', coverage: 'complete', summary: 'Stable', metrics: [stable] },
  ai_assessment: {
    severity: 'critical',
    explanation: 'Gateway health has experienced degradation of 0.11 (11%).',
    recommendations: ['Immediately roll back'],
  },
} as unknown as MonitoringSession;

it('separates deployment recovery, measured metrics and unmeasured experience', () => {
  const result = changeOutcome(detail, [session]);
  expect(result.label).toBe('Deployment recovered');
  expect(result.headline).toContain('no degradation measured');
  expect(result.deployment).toBe('Recovered after failure');
  expect(result.service).toBe('No measured degradation');
  expect(result.experience).toContain('Not measured');
  expect(result.attribution).toBe(true);
  expect(result.predates).toBe(true);
});

it('does not use an incident severity as proof of a metric decline', () => {
  const open = {
    ...session,
    incidents: session.incidents.map((i) => ({ ...i, resolved: false, resolved_at: null })),
  };
  const result = changeOutcome({ ...detail, impact_severity: 'critical' }, [open]);
  expect(result.label).toBe('Deployment failure needs review');
  expect(result.tone).toBe('crit');
  expect(result.service).toBe('No measured degradation');
  expect(result.degraded).toBe(false);
});

it('keeps other critical findings visible after deployment recovery', () => {
  expect(changeOutcome({ ...detail, impact_severity: 'critical' }, [session]).headline).toContain(
    'still needs review',
  );
  expect(changeOutcome({ ...detail, impact_severity: 'critical' }, [session]).tone).toBe('crit');
});

it('does not declare missing or excluded measurements healthy', () => {
  const missing = changeOutcome({ ...detail, site_impacts: [], impact_severity: 'info' }, []);
  expect(missing.service).toBe('Not established');
  expect(missing.uncertain).toBe(true);
  expect(measuredDegradation([{ ...stable, delta: -30, selected: false }])).toBe(false);
  expect(measuredDegradation([{ ...stable, delta: -30, comparable: false }])).toBe(false);
  expect(measuredDegradation([{ ...stable, delta: -30 }])).toBe(true);
});

it('flags stored AI severity and direction conflicts for review', () => {
  expect(interpretationNeedsReview(session)).toBe(true);
  const aligned = {
    ...session,
    ai_assessment: {
      severity: 'none',
      explanation: 'Gateway health improved. No degradation was measured.',
    },
  };
  expect(interpretationNeedsReview(aligned)).toBe(false);
});
