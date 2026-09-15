import { actionStatusLabel, actionStatusTone, RestoreAction } from './restore.model';

function action(overrides: Partial<RestoreAction> = {}): RestoreAction {
  return {
    logical_object_id: 'lo-1',
    source_version_id: 'v-1',
    order: 0,
    action: 'update',
    scope: 'org',
    object_type: 'wlan',
    object_name: 'NW-Corp',
    current_mist_id: 'mist-1',
    site_mist_id: null,
    configuration: {},
    depends_on: [],
    status: 'pending',
    resulting_mist_id: null,
    error: null,
    ...overrides,
  };
}

describe('restore action status', () => {
  it('names a write Mist never confirmed as unconfirmed rather than failed', () => {
    const unconfirmed = action({ status: 'failed', outcome_unknown: true, error: 'Unable to reach Mist' });

    expect(actionStatusLabel(unconfirmed, 'compensation_available')).toBe('UNCONFIRMED');
    expect(actionStatusTone('failed', true)).toBe('warn');
  });

  it('still reports a rejected write as failed', () => {
    expect(actionStatusLabel(action({ status: 'failed' }), 'failed')).toBe('FAILED');
    expect(actionStatusTone('failed')).toBe('crit');
  });
});
