import {
  actionStatusLabel,
  actionStatusTone,
  failedAction,
  RestoreAction,
  RestoreOperation,
} from './restore.model';

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

function operation(overrides: Partial<RestoreOperation> = {}): RestoreOperation {
  return {
    id: 'op-1',
    mode: 'non_destructive',
    include_dependencies: true,
    target_at: '2026-09-02T11:40:00Z',
    status: 'compensation_available',
    actions: [],
    warnings: [],
    preflight_errors: [],
    credential_actor: null,
    started_at: null,
    completed_at: null,
    created_at: '2026-09-07T14:22:00Z',
    task_id: null,
    ...overrides,
  };
}

describe('the action a stopped run is halted at', () => {
  it('is the action whose write failed', () => {
    const stopped = operation({
      actions: [action({ status: 'completed' }), action({ order: 1, object_name: 'SEA-Voice', status: 'failed' })],
      failure_action_order: 1,
    });

    expect(failedAction(stopped)?.object_name).toBe('SEA-Voice');
  });

  it('is the action the worker recorded when no action failed', () => {
    // The write to NW-Corp reached Mist; recording it is what stopped the run.
    const stopped = operation({
      actions: [action({ status: 'completed' }), action({ order: 1, object_name: 'SEA-Voice' })],
      failure_action_order: 0,
    });

    expect(failedAction(stopped)?.object_name).toBe('NW-Corp');
  });

  it('is no action when the run stopped after every action finished', () => {
    const stopped = operation({ actions: [action({ status: 'completed' })], failure_action_order: null });

    expect(failedAction(stopped)).toBeNull();
    expect(failedAction(operation({ actions: [action({ status: 'completed' })] }))).toBeNull();
  });
});
