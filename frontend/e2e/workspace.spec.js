import { test, expect } from '@playwright/test';
import { user, org, now, objects, groups, sessions } from './fixtures';
const devices = [
  {
    id: 'aabbccddee01',
    name: 'Paris gateway',
    kind: 'gateway',
    tier: 0,
    col: 1,
    health: 'unknown',
    health_label: 'Connected · SLE not assessed',
    parent: null,
    ip: '10.0.0.1',
    model: 'SSR120',
    clients: null,
  },
  {
    id: 'aabbccddee02',
    name: 'Access switch 1',
    kind: 'switch',
    tier: 2,
    col: 0,
    health: 'unknown',
    health_label: 'Connected · SLE not assessed',
    parent: null,
    ip: '10.0.0.2',
    model: 'EX4400',
    clients: 24,
  },
  {
    id: 'aabbccddee03',
    name: 'Access switch 2',
    kind: 'switch',
    tier: 2,
    col: 2,
    health: 'unknown',
    health_label: 'Connected · SLE not assessed',
    parent: null,
    ip: '10.0.0.3',
    model: 'EX4100',
    clients: 18,
  },
  {
    id: 'aabbccddee04',
    name: 'Meeting room AP',
    kind: 'ap',
    tier: 3,
    col: 0,
    health: 'error',
    health_label: 'Disconnected',
    parent: 'aabbccddee02',
    ip: '10.0.0.4',
    model: 'AP45',
    clients: 0,
  },
  {
    id: 'aabbccddee05',
    name: 'Lobby AP',
    kind: 'ap',
    tier: 3,
    col: 1,
    health: 'unknown',
    health_label: 'Connected · SLE not assessed',
    parent: 'aabbccddee02',
    ip: '10.0.0.5',
    model: 'AP45',
    clients: 12,
  },
  {
    id: 'aabbccddee06',
    name: 'Office AP',
    kind: 'ap',
    tier: 3,
    col: 2,
    health: 'unknown',
    health_label: 'Connected · SLE not assessed',
    parent: 'aabbccddee03',
    ip: '10.0.0.6',
    model: 'AP45',
    clients: 22,
  },
].map((d) => ({ ...d, mac: d.id, last_seen: now, uplink: d.parent ? 'ge-0/0/3' : null }));
const links = [
  [0, 1, 'ge-0/0/0', 'ge-0/0/48'],
  [1, 2, 'ge-0/0/47', 'ge-0/0/48'],
  [1, 3, 'ge-0/0/1', 'eth0'],
  [1, 4, 'ge-0/0/2', 'eth0'],
  [2, 5, 'ge-0/0/3', 'eth0'],
].map(([source, target, local, remote]) => ({
  source: devices[source].id, target: devices[target].id,
  source_ports: [local], target_ports: [remote],
}));
const deviceImpact = (index, overrides = {}) => ({
  device_id: devices[index].id,
  device_name: devices[index].name,
  session_id: 's' + index,
  severity: 'ok',
  config_state: 'applied',
  detected_at: '2026-09-09T11:02:00Z',
  snapshot_at: '2026-09-09T11:02:12Z',
  configured_at: '2026-09-09T11:02:45Z',
  monitoring_started_at: '2026-09-09T11:02:45Z',
  monitoring_ends_at: '2026-09-09T12:02:45Z',
  completed_at: null,
  monitoring_state: 'monitoring',
  progress: 62,
  observation_count: 7,
  headline: 'No negative impact detected in the available samples.',
  metrics: [{ name: 'switch-throughput', baseline: 99.5, latest: 98, delta: -1.5 }],
  collection_errors: [],
  shared_window: false,
  ...overrides,
});
const changes = [
  {
    id: 'c1',
    audit_id: 'a1',
    change_group_id: 'g1',
    occurred_at: '2026-09-09T11:02:00Z',
    actor: 'Thomas',
    change_type: 'Switch template',
    title: 'PoE disabled on meeting room ports',
    summary: '',
    impacts: [
      deviceImpact(1, {
        severity: 'critical',
        headline: 'PoE stopped supplying a port with an attached client.',
      }),
      deviceImpact(2),
    ],
  },
  {
    id: 'c2',
    audit_id: 'a2',
    change_group_id: 'g2',
    occurred_at: '2026-09-09T09:14:00Z',
    actor: 'Thomas',
    change_type: 'RF template',
    title: 'Radio channel policy updated',
    summary: '',
    impacts: [deviceImpact(3), deviceImpact(4), deviceImpact(5)],
  },
  {
    id: 'c3',
    audit_id: 'a3',
    change_group_id: 'g3',
    occurred_at: '2026-09-09T08:23:00Z',
    actor: 'Operations',
    change_type: 'Gateway template',
    title: 'WAN path preferences updated',
    summary: '',
    impacts: [
      deviceImpact(0, {
        config_state: 'pending',
        severity: 'unknown',
        progress: 0,
        monitoring_state: 'not_started',
        configured_at: null,
        headline: 'Waiting for the device configuration report.',
      }),
    ],
  },
];
const restoreOperation = {
  id: 'op-scroll',
  mode: 'non_destructive',
  include_dependencies: true,
  requested_version_ids: ['v0'],
  target_at: now,
  status: 'planned',
  actions: Array.from({ length: 40 }, (_, i) => ({
    logical_object_id: `restore-object-${i}`,
    source_version_id: `restore-version-${i}`,
    order: i,
    action: 'update',
    scope: 'org',
    object_type: 'wlans',
    object_name: `Restore WLAN ${i}`,
    current_mist_id: `mist-wlan-${i}`,
    site_mist_id: null,
    configuration: {},
    depends_on: [],
    status: 'pending',
    resulting_mist_id: null,
    error: null,
  })),
  warnings: [],
  preflight_errors: [],
  credential_actor: null,
  started_at: null,
  completed_at: null,
  created_at: now,
  task_id: null,
  approval: null,
  compensation_available: false,
};
test.beforeEach(async ({ page }) => {
  page.on('console', (message) => {
    if (message.type() === 'error') console.error('BROWSER:', message.text());
  });
  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url()),
      path = url.pathname;
    let json = { items: [], total: 0 };
    if (path.endsWith('/overview'))
      json = {
        generated_at: now,
        range_start: '2026-09-08T12:00:00Z',
        range_end: now,
        counts: {
          change_groups: 3,
          impacting: 1,
          mine: 1,
          unrecovered: 1,
          pending_approvals: 0,
          failed_restores: 0,
        },
        change_groups: groups.slice(0, 3),
        safety_net: [
          {
            key: 'backup',
            label: 'Configuration backup',
            status: 'ok',
            detail: '100 objects captured',
          },
          {
            key: 'webhook',
            label: 'Webhook collection',
            status: 'ok',
            detail: 'Last received 12:00 UTC',
          },
          {
            key: 'credential',
            label: 'Service token',
            status: 'ok',
            detail: 'Read-only access verified',
          },
        ],
        pending_approvals: [],
        failed_restores: [],
        latest_snapshot_at: now,
        latest_snapshot_objects: 100,
      };
    else if (path.endsWith('/auth/me')) json = user;
    else if (path.endsWith('/organizations')) json = { items: [org], total: 1 };
    else if (path.endsWith('/version')) json = { version: '0.6.5' };
    else if (path.endsWith('/health'))
      json = { status: 'ok', version: '0.6.5', checked_at: now, components: [] };
    else if (path.endsWith('/impact/sites'))
      json = {
        items: [
          { id: 'site1', name: 'Paris lab' },
          { id: 'site2', name: 'London office' },
        ],
      };
    else if (path.endsWith('/topology'))
      json = {
        site_id: 'site1',
        source: url.searchParams.has('as_of') ? 'historical' : 'mist',
        devices: path.includes('/site2/') ? [] : devices,
        links: path.includes('/site2/') || url.searchParams.has('as_of') ? [] : links,
        warnings: [],
        complete: true,
        collected_at: now,
      };
    else if (path.endsWith('/impact/sites/site1/changes'))
      json = { items: changes, total: changes.length, as_of: now, historical: false };
    else if (path.endsWith('/point-in-time/markers'))
      json = {
        items: changes.map((c) => ({
          at: c.occurred_at,
          severity: 'none',
          label: c.title,
          change_group_id: c.id,
        })),
        range_start: '2026-09-08T12:00:00Z',
        range_end: now,
      };
    else if (path.endsWith('/objects/facets'))
      json = {
        types: [{ id: 'settings', name: 'Settings', count: 100 }],
        sites: [{ id: 'site1', name: 'Paris lab', count: 100 }],
      };
    else if (path.endsWith('/objects')) json = { items: objects, total: 100 };
    else if (path.endsWith('/restores/targets'))
      json = { items: [], total: 0, types: [], sites: [] };
    else if (path.endsWith('/restores/op-scroll')) json = restoreOperation;
    else if (path.endsWith('/restores')) json = { items: [], total: 0 };
    else if (path.endsWith('/change-groups')) json = { items: groups, total: 70 };
    else if (path.includes('/change-groups/'))
      json = {
        ...groups[0],
        message: null,
        method: 'PUT',
        baseline_confidence: 'high',
        deterministic_assessment: 'Configuration applied to six switches.',
        evidence: [],
        changed_objects: [],
        affected_devices: [],
        competing_change_group_ids: [],
      };
    else if (path.endsWith('/monitoring')) json = { items: sessions, total: 6 };
    else if (path.includes('/monitoring/')) json = sessions[0];
    await route.fulfill({ json });
  });
});
test('four selection states, safe panning, zoom, clearing and site isolation', async ({
  page,
}, info) => {
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(message.text());
  });
  await page.goto('/impact');
  await expect(page.locator('.node')).toHaveCount(6);
  const panel = page.locator('.details');
  await expect(panel).toHaveAttribute('data-panel', 'site');
  await page.screenshot({ path: info.outputPath('site-rollup.png') });
  await page.locator('.change-row').first().click();
  await expect(panel).toHaveAttribute('data-panel', 'change');
  const switchNode = page.getByRole('button', { name: 'Access switch 1, critical', exact: true });
  await switchNode.click();
  await expect(panel).toHaveAttribute('data-panel', 'device-change');
  await expect(panel).toContainText('PoE stopped supplying');
  await page.screenshot({ path: info.outputPath('device-change.png') });
  const transform = await page.locator('.canvas').getAttribute('style');
  await page.getByRole('button', { name: 'Zoom in', exact: true }).click();
  await expect(page.locator('.canvas')).not.toHaveAttribute('style', transform);
  await page.getByRole('button', { name: 'Fit', exact: true }).click();
  const node = page.getByRole('button', { name: /Lobby AP,/ });
  const rect = await node.boundingBox();
  await page.mouse.move(rect.x + 10, rect.y + 10);
  await page.mouse.down();
  await page.mouse.move(rect.x + 55, rect.y + 30, { steps: 5 });
  await page.mouse.up();
  await expect(panel).toHaveAttribute('data-panel', 'device-change');
  await node.click();
  await expect(panel).toHaveAttribute('data-panel', 'device');
  await expect(panel).toContainText('Not in the scope');
  await page.locator('.history-row:visible').click();
  await expect(panel).toHaveAttribute('data-panel', 'device-change');
  await page.screenshot({ path: info.outputPath('ap-change.png') });
  await page.getByRole('button', { name: 'Zoom in', exact: true }).click();
  await expect(page.locator('.zoom output')).toHaveText('125%');
  const savedZoom = await page.locator('.zoom output').textContent();
  await page.locator('#impact-site').selectOption('site2');
  await expect(page.locator('.node')).toHaveCount(0);
  await expect(panel).toHaveAttribute('data-panel', 'site');
  await page.locator('#impact-site').selectOption('site1');
  await expect(page.locator('.zoom output')).toHaveText(savedZoom);
  expect(errors).toEqual([]);
});
test('overlay breakpoints, mobile navigation, exact UTC time and keyboard controls', async ({
  page,
}, info) => {
  await page.goto('/impact');
  await expect(page.locator('.node')).toHaveCount(6);
  for (const width of [1257, 1255]) {
    await page.setViewportSize({ width, height: 900 });
    await page.waitForTimeout(100);
    const hostWidth = await page.locator('app-site-impact-page').evaluate((el) => el.clientWidth);
    await expect(page.locator('.details')).toBeVisible({ visible: hostWidth >= 1040 });
  }
  await page.locator('.change-row').first().click();
  await expect(page.locator('.details')).toBeVisible();
  await page.screenshot({ path: info.outputPath('overlay.png') });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.locator('.mobile-toolbar').getByRole('button', { name: 'Clear', exact: true }).click();
  await page
    .locator('.mobile-toolbar')
    .getByRole('button', { name: /Changes/ })
    .click();
  await page.locator('.change-row').first().click();
  await expect(page.locator('.details')).toBeVisible();
  expect(await page.evaluate(() => document.body.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: info.outputPath('mobile.png') });
  await page.locator('.exact-time summary').click();
  await page.locator('#view-at-time').fill('2026-09-09T10:00');
  await page.getByRole('button', { name: 'View configuration', exact: true }).click();
  await expect(page.locator('.context-note')).toContainText('Historical inventory');
  await page.getByRole('button', { name: 'Live', exact: true }).click();
  await expect(page.locator('.context-note')).toHaveCount(0);
  await page.setViewportSize({ width: 1600, height: 1000 });
  await page.locator('.track-seek').focus();
  await page.keyboard.press('Home');
  await expect(page.locator('.exact-time summary')).toContainText('08 SEP');
  await page.keyboard.press('Escape');
  await expect(page.getByRole('button', { name: 'Live', exact: true })).toHaveAttribute(
    'aria-pressed',
    'true',
  );
});
test('other workspaces retain bounded tables, immediately visible details and mobile layouts', async ({
  page,
}, info) => {
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(message.text());
  });
  await page.goto('/history');
  await expect(page.locator('.library-table tbody tr')).toHaveCount(100);
  expect(
    await page.locator('.library-table').evaluate((el) => el.scrollHeight > el.clientHeight),
  ).toBe(true);
  let rect = await page.locator('.library-table').boundingBox();
  expect(rect.y + rect.height).toBeLessThanOrEqual(1001);
  await page.screenshot({ path: info.outputPath('objects.png') });
  await page.goto('/changes');
  await page.locator('.row--group').first().click();
  await expect(page.locator('.panel-title')).toBeVisible();
  rect = await page.locator('.panel').boundingBox();
  expect(rect.y + rect.height).toBeLessThanOrEqual(1001);
  expect(await page.evaluate(() => window.scrollY)).toBe(0);
  await page.screenshot({ path: info.outputPath('changes.png') });
  for (const path of ['/overview', '/settings', '/history', '/changes']) {
    await page.goto(path);
    await page.waitForTimeout(300);
    await page.screenshot({ path: info.outputPath(path.slice(1) + '-desktop.png') });
    await page.setViewportSize({ width: 390, height: 844 });
    expect(await page.evaluate(() => document.body.scrollWidth <= innerWidth)).toBe(true);
    await page.setViewportSize({ width: 1600, height: 1000 });
  }
  expect(errors).toEqual([]);
});

test('embedded restore plans have a reachable vertical scrollport', async ({ page }) => {
  await page.goto('/history?restore=1&operation=op-scroll');
  await expect(page.getByRole('heading', { name: 'Plan · 40 actions' })).toBeVisible();
  await expect(page.locator('.step-button')).toHaveCount(3);
  await expect(page.getByRole('button', { name: 'Capture backup and review new plan' })).toBeAttached();

  const scrollport = page.locator('.restore-inline > app-restore-page');
  expect(
    await scrollport.evaluate((element) => element.scrollHeight > element.clientHeight),
  ).toBe(true);
  await scrollport.hover();
  await page.mouse.wheel(0, 1200);
  await expect.poll(() => scrollport.evaluate((element) => element.scrollTop)).toBeGreaterThan(0);
  await expect(page.getByRole('button', { name: 'Back to targets' })).toBeVisible();
});

test('failed discovery stays unknown and can be retried without reloading the page', async ({
  page,
}) => {
  await page.route(
    '**/impact/sites',
    (route) => route.fulfill({ status: 503, json: { detail: 'Unavailable' } }),
    { times: 1 },
  );
  await page.goto('/impact');
  await expect(page.getByRole('alert')).toContainText('Sites could not be loaded');
  await expect(
    page.getByText('This organization has no stored sites yet.', { exact: false }),
  ).toHaveCount(0);
  await page.getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(page.locator('.node')).toHaveCount(6);
});

test('existing monitoring links keep the detailed evidence accessible', async ({ page }) => {
  await page.goto('/impact?session=s1');
  await expect(page).toHaveURL(/\/impact\/sessions\?session=s1/);
  await expect(page.locator('app-configuration-timeline')).toBeVisible();
});


test('gateway and switch neighbor edges expose observed ports without inventing link health', async ({ page }, info) => {
  await page.goto('/impact');
  await expect(page.locator('.links path')).toHaveCount(5);
  await page.getByRole('button', { name: /Paris gateway,/ }).click();
  await page.getByText('Observed neighbors · 1', { exact: true }).click();
  const neighbors = page.locator('details.detail-section');
  await expect(neighbors).toContainText('ge-0/0/0 → ge-0/0/48');
  await neighbors.getByRole('button', { name: /Access switch 1/ }).click();
  await expect(page.locator('.detail-head h2')).toHaveText('Access switch 1');
  await expect(neighbors).toContainText('Observed neighbors · 4');
  await expect(neighbors).toContainText('do not establish current link health');
  await page.screenshot({ path: info.outputPath('switch-neighbors.png') });
});

test('device evidence shows one session and one finding with capture history on demand', async ({ page }, info) => {
  const finding = {
    kind: 'ssid', subject: 'BYOD-IOT', before: 'configured', after: 'removed or disabled',
    severity: 'warning', detail: 'SSID removed or disabled; no clients were observed at the initial capture.', affected_clients: 0,
  };
  const evidence = {
    ...sessions[0], id: 'evidence1', device_name: 'Meeting room AP', device_mac: 'aabbccddee04', device_type: 'ap',
    status: 'completed', impact_severity: 'warning', peak_impact_severity: 'warning',
    completed_at: '2026-09-09T13:30:00Z', audit_ids: ['a1', 'a2', 'a3', 'a4', 'a5'],
    baseline: { captured_at: now, values: {}, errors: [], no_data: ['roaming', 'ap-health'] },
    observations: [],
    device_comparisons: Array.from({ length: 5 }, (_, i) => ({
      ...sessions[0].device_comparisons[0],
      triggered_at: `2026-09-09T12:0${i}:00Z`, recovered_at: null,
      findings: i < 4 ? [finding] : [], current_findings: i < 4 ? [finding] : [],
    })),
    ai_assessment: { explanation: 'The SSID configuration changed. Confirm that its removal was intended.' },
  };
  const reads = [];
  page.on('request', (request) => { if (request.url().includes('/monitoring')) reads.push(new URL(request.url()).pathname); });
  await page.route('**/monitoring/evidence1', (route) => route.fulfill({ json: evidence }));
  await page.goto('/impact/sessions?session=evidence1');
  await expect(page.getByRole('heading', { name: 'Meeting room AP', exact: true })).toBeVisible();
  await expect(page.locator('.rail')).toHaveCount(0);
  await expect(page.locator('.findings-summary .finding')).toHaveCount(1);
  await expect(page.locator('.findings-summary')).toContainText('Reported in 4 captures');
  await expect(page.locator('.capture-history')).not.toHaveAttribute('open');
  await expect(page.getByText('No network-metric comparison available', { exact: true })).toBeVisible();
  await expect(page.getByText('One monitoring window covers', { exact: false })).toBeVisible();
  expect(reads.every((path) => path.endsWith('/monitoring/evidence1'))).toBe(true);
  await page.screenshot({ path: info.outputPath('evidence-desktop.png'), fullPage: true });
  await page.locator('.capture-history > summary').click();
  await page.getByLabel('Configuration trigger').selectOption('4');
  await expect(page.locator('.capture-history')).toContainText('No disruption detected');
  await expect(page.locator('.findings-summary .finding')).toHaveCount(1);
  await page.locator('.capture-history > summary').click();
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole('heading', { name: 'Meeting room AP', exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: info.outputPath('evidence-mobile.png'), fullPage: true });
  await page.getByRole('button', { name: 'Back to site impact', exact: false }).click();
  await expect(page).toHaveURL(/\/impact\?site=site1&device=aabbccddee04/);
});

test('time explorer previews dragging, commits on release, and stays usable on mobile', async ({ page }, info) => {
  await page.goto('/overview');
  const slider = page.locator('.track-seek');
  await expect(slider).toBeVisible();
  const box = await slider.boundingBox();
  await page.mouse.move(box.x + box.width * .5, box.y + 16);
  await page.mouse.down();
  await page.mouse.move(box.x + box.width * .25, box.y + 16);
  await expect(page.locator('.time-heading')).toContainText('Preview');
  await expect(page.locator('.live-button')).toHaveAttribute('aria-pressed', 'true');
  await page.mouse.up();
  await expect(page.locator('.live-button')).toHaveAttribute('aria-pressed', 'false');
  expect(Number(await slider.getAttribute('aria-valuenow'))).toBeCloseTo(25, 0);
  await page.screenshot({ path: info.outputPath('timeline-desktop.png') });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(slider).toBeVisible();
  expect(await page.evaluate(() => document.body.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: info.outputPath('timeline-mobile.png') });
  await page.locator('.exact-time summary').click();
  await expect(page.locator('#view-at-time')).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(page.locator('.exact-time')).not.toHaveAttribute('open', '');
});


test('exact-time popover follows its trigger when the toolbar wraps', async ({ page }, info) => {
  await page.goto('/overview');
  for (const width of [320, 390, 600, 601, 768, 999, 1000, 1280]) {
    await page.setViewportSize({ width, height: 1000 });
    const trigger = page.locator('.exact-time summary');
    await trigger.click();
    const form = page.locator('.exact-time form');
    await expect(form).toBeVisible();
    await expect(page.locator('#view-at-time')).toBeFocused();
    const anchor = await trigger.boundingBox();
    const popup = await form.boundingBox();
    expect(popup.y - (anchor.y + anchor.height)).toBeCloseTo(8, 0);
    expect(popup.x).toBeGreaterThanOrEqual(0);
    expect(popup.x + popup.width).toBeLessThanOrEqual(width);
    if (width === 390 || width === 768) {
      await page.screenshot({ path: info.outputPath(`exact-time-${width}.png`) });
    }
    await form.getByRole('button', { name: 'Cancel', exact: true }).click();
    await expect(form).toBeHidden();
    await expect(trigger).toBeFocused();
  }
});

const guardianResult = {
  run_id: 'run-early', run_kind: 'early', evaluated_at: now, peak: 'warning', current: 'none',
  recovery: 'recovered', confidence: 'low', coverage: 'partial', sources: ['monitoring', 'agent'],
  impacted_devices: [], impacted_device_count: 4,
  summary: 'One access point reached warning after the change and recovered.',
};
const guardianSummary = {
  availability: 'projected', status: 'done', status_reason: 'Final attempts exhausted',
  result: guardianResult,
};
const guardianSection = (items = [], omitted = 0, explanation = null) => ({
  items, omitted, explanation: items.length ? null : explanation,
});
const guardianReport = {
  run: { kind: 'early', attempt: 1, state: 'succeeded', failure_reason: null, started_at: now,
    finished_at: now, anchor: { changed_at: now, source: 'audit' }, as_of: now,
    budget: { model_turns: 4, mcp_calls: 2, rule_reads: 1 } },
  header: { peak: 'warning', current: 'none', recovery: 'recovered', confidence: 'low',
    coverage: 'partial', sources: ['monitoring', 'agent'] },
  header_note: null,
  summary: { deterministic: 'One access point reached warning and recovered.',
    ai: 'The template deployment is the likeliest cause, but the evidence is thin.', ai_note: null },
  change: guardianSection([{ id: 'A1', logical_object_id: 'obj-1', version: 4, attribute: 'port_config',
    paths: [['port_config', 'ge-0/0/1']], paths_complete: false }]),
  coverage: {
    coverage: 'partial',
    rows: guardianSection([{ atom_id: 'A1', target: { device_mac: 'aabbccddee02', site_id: 'site1', port_id: null, wlan_id: null },
      resolution: 'claimed', obligation_ids: ['O1'], uncovered_paths: [] }]),
    obligations: guardianSection([{ obligation: { id: 'O2', owner: 'core', change_ref: null, paths: [],
      role: 'observation', kind: 'input', target: { device_mac: null, site_id: null, port_id: null, wlan_id: null },
      metric: null, empty_policy: null },
      status: { status: 'unsatisfied', reason: 'The stored version was truncated, so the change was never built in full.', evidence_ids: [] } }]),
  },
  devices: guardianSection([{ mac: 'aabbccddee02', site_id: 'site1', name: 'Access switch 1', session_id: 's1',
    exclusive: true, terminal: true, status: 'satisfied', metrics: { peak: 'warning', current: 'none' },
    incidents: null, device_state: null, peak: 'warning', current: 'none', deployment: 'configured',
    deployment_precondition: 'satisfied' }]),
  impacted: guardianSection([{ mac: 'aabbccddee02', site_id: 'site1', name: 'Access switch 1', peak: 'warning', current: 'none' }], 3),
  findings: guardianSection([
    { source: 'monitoring', text: 'Throughput fell on one switch.', severity: 'warning', evidence_ids: ['E1'] },
    { source: 'agent', text: 'The template deployment is the likeliest cause.', severity: 'info', evidence_ids: ['E1'] },
  ]),
  evidence: guardianSection([
    { id: 'E1', source: 'monitoring', kind: 'service_health', title: 'Monitoring replay', captured_at: now,
      window: { start: now, end: now }, scope: { site_ids: ['site1'], device_macs: ['aabbccddee02'] },
      collection: 'complete', representation: 'full', citable: true, detail: '' },
    { id: 'E5', source: 'mcp:mist_search_device', kind: 'reference', title: 'Device search', captured_at: now,
      window: null, scope: { site_ids: [], device_macs: [] }, collection: 'error', representation: 'digest',
      citable: false, detail: 'Mist returned HTTP 500.' },
  ]),
  gaps: guardianSection([{ source: 'agent', text: 'Client history for the window is incomplete.' }]),
};
const guardianRun = { id: 'run-early', kind: 'early', attempt: 1, state: 'succeeded', published: true, report: guardianReport };
const guardianInvestigation = {
  root: { id: 'inv-1', audit_id: 'audit0', changed_at: now, anchor_known: true, status: 'done',
    status_reason: 'Final attempts exhausted', next_check_at: null, attempts: { early: 1, final: 2 },
    early_run_id: 'run-early', final_run_id: null, result: guardianResult },
  runs: [guardianRun],
  attempts: [
    { id: 'run-early', kind: 'early', attempt: 1, state: 'succeeded', failure_reason: null,
      budget: { model_turns: 4, mcp_calls: 2, rule_reads: 1 }, published: true },
    { id: 'run-final-1', kind: 'final', attempt: 1, state: 'failed', failure_reason: 'The provider did not answer',
      budget: { model_turns: 0, mcp_calls: 0, rule_reads: 0 }, published: false },
  ],
  unreadable_attempts: 1,
};
const guardianRunDetail = {
  ...guardianRun,
  investigation_id: 'inv-1', audit_id: 'audit0', failure_reason: null,
  budget: { model_turns: 4, mcp_calls: 2, rule_reads: 1 },
  steps: [
    { turn: 1, action: 'call', tool: 'mist_search_device', evidence_id: 'E5', collection: 'error',
      output: 'I will look at the switch first.', visible_evidence_ids: ['E1'], withheld_evidence_ids: ['E5'] },
    { turn: 2, action: 'report', rejection: 'citation_invalid', detail: 'E5 is not citable',
      visible_evidence_ids: ['E1'], withheld_evidence_ids: ['E5'] },
  ],
};

test('Guardian result stays distinct from production in Changes and Overview', async ({ page }, info) => {
  const row = { ...groups[0], impact_source: 'legacy', guardian: guardianSummary };
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith('/change-groups')) {
      await route.fulfill({ json: { items: [row], total: 1 } });
    } else if (path.endsWith('/overview')) {
      await route.fulfill({ json: {
        generated_at: now, range_start: now, range_end: now,
        counts: { change_groups: 70, impacting: 5, mine: 1, unrecovered: 1, pending_approvals: 0, failed_restores: 0, impact_source: 'legacy' },
        change_groups: [row], safety_net: [], pending_approvals: [], failed_restores: [],
        latest_snapshot_at: now, latest_snapshot_objects: 100,
        guardian_feed_counts: { scope: 'returned_feed', total: 1, not_recorded: 0, unavailable: 0,
          pending: 0, none: 0, info: 0, warning: 1, critical: 0 },
      } });
    } else await route.fallback();
  });
  await page.goto('/changes');
  const rowView = page.locator('.row--group').first();
  await expect(rowView).toContainText(row.impact_label);
  await expect(rowView).toContainText('Guardian · Possible disruption');
  await expect(rowView).toContainText('Peak: Possible disruption · Current: No impact observed');
  await expect(rowView).toContainText('Early result');
  await page.screenshot({ path: info.outputPath('guardian-changes.png'), fullPage: true });
  await page.goto('/overview');
  await expect(page.getByRole('region', { name: 'Guardian result counts' })).toContainText('1 change in the loaded feed');
  await expect(page.locator('.card').first()).toContainText('Guardian · Possible disruption');
  await expect(page.locator('.card').first()).toContainText(row.impact_label);
  await page.screenshot({ path: info.outputPath('guardian-overview.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: info.outputPath('guardian-overview-mobile.png'), fullPage: true });
});

test('Guardian panel labels the AI summary, an early result and withheld evidence', async ({ page }, info) => {
  const row = { ...groups[0], guardian: guardianSummary };
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith('/change-groups')) {
      await route.fulfill({ json: { items: [row], total: 1 } });
    } else if (path.includes('/guardian/runs/')) {
      await route.fulfill({ json: guardianRunDetail });
    } else if (path.endsWith('/guardian')) {
      await route.fulfill({ json: guardianInvestigation });
    } else await route.fallback();
  });
  await page.goto('/changes');
  await page.locator('.row--group').first().click();
  await page.getByRole('button', { name: 'Review Guardian investigation' }).click();
  const panel = page.getByRole('region', { name: 'Guardian investigation' });
  await expect(panel).toContainText('Finished · 1 early and 2 final attempts');
  await expect(panel).toContainText('Early result · attempt 1');
  await expect(panel).toContainText('ended without publishing a final result');
  await expect(panel).toContainText("AI summary · the AI agent's own words");
  await expect(panel).toContainText('3 further impacted devices are not named here: this attempt did not record them individually');
  await expect(panel).toContainText('no change atom · an input this attempt never saw in full');
  await expect(panel).toContainText('attempt could not be read by this build');
  await page.screenshot({ path: info.outputPath('guardian-panel.png'), fullPage: true });
  await panel.getByRole('button', { name: 'Early result · attempt 1 · succeeded · published' }).click();
  await expect(panel).toContainText('Withheld from the AI agent, which could not cite it: E5');
  await expect(panel).toContainText('rejected: citation_invalid');
  await page.screenshot({ path: info.outputPath('guardian-attempt.png'), fullPage: true });
});
