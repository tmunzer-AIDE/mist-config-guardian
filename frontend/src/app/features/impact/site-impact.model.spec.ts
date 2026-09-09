import {
  boundedView,
  changeHealth,
  changePhase,
  changeProgress,
  DeviceImpact,
  impactDevices,
  SiteChange,
  zoomAt,
} from './site-impact.model';
import { change, impact } from './site-impact.fixtures';
describe('site impact presentation', () => {
  it('keeps no evidence unknown and configuration pending', () => {
    const empty = change({ impacts: [] });
    expect(changeHealth(empty)).toBe('unknown');
    expect(changePhase(empty)).toBe('pending');
    expect(changeProgress(empty)).toBe(0);
  });
  it('prioritizes pending configuration over active monitoring', () => {
    expect(
      changePhase(
        change({
          impacts: [impact(), impact({ config_state: 'applied', monitoring_state: 'monitoring' })],
        }),
      ),
    ).toBe('pending');
  });
  it('keeps a stalled collection in monitoring even with elapsed time at 100%', () => {
    const c = change({
      impacts: [impact({ config_state: 'applied', monitoring_state: 'stalled', progress: 100 })],
    });
    expect(changePhase(c)).toBe('monitoring');
    expect(changeHealth(c)).toBe('unknown');
  });
  it('averages per-device progress without declaring monitoring complete', () => {
    expect(
      changeProgress(change({ impacts: [impact({ progress: 100 }), impact({ progress: 0 })] })),
    ).toBe(50);
  });
  it('reports the worst measured impact and never hides unknown coverage behind OK', () => {
    expect(changeHealth(change({ impacts: [impact({ severity: 'ok' }), impact()] }))).toBe(
      'unknown',
    );
    expect(changeHealth(change({ impacts: [impact(), impact({ severity: 'critical' })] }))).toBe(
      'critical',
    );
  });
  it('retains affected devices missing from inventory without inventing health or links', () => {
    const devices = impactDevices([], [change(), change()]);
    expect(devices.length).toBe(1);
    expect(devices[0].parent).toBeNull();
    expect(devices[0].health).toBe('unknown');
  });
  it('preserves the world coordinate under the zoom pointer', () => {
    const view = { zoom: 1, x: 30, y: -20 },
      after = zoomAt(view, 1.3, 150, 75);
    expect((150 - after.x) / after.zoom).toBeCloseTo((150 - view.x) / view.zoom);
    expect((75 - after.y) / after.zoom).toBeCloseTo((75 - view.y) / view.zoom);
  });
  it('limits zoom in both directions', () => {
    expect(zoomAt({ zoom: 1, x: 0, y: 0 }, 100, 0, 0).zoom).toBe(2.6);
    expect(zoomAt({ zoom: 1, x: 0, y: 0 }, 0.001, 0, 0).zoom).toBe(0.3);
  });
  it('keeps the canvas reachable after an extreme pan', () => {
    const view = boundedView({ zoom: 1, x: 9000, y: -9000 }, 600, 400, 880, 530);
    expect(view.x).toBe(70);
    expect(view.y).toBe(-200);
  });
});
