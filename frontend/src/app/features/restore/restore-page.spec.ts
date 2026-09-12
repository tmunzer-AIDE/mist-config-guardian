import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';

import { EMPTY } from 'rxjs';
import { MistMfaService } from '../../core/mist-mfa.service';
import { AuthService, UserRole } from '../../core/auth.service';
import { OrganizationContextService } from '../../core/organization-context.service';
import { TimeContextService } from '../../core/time-context.service';
import { UiStateService } from '../../core/ui-state.service';
import { RestorePage } from './restore-page';
import {
  RestoreAction,
  RestoreOperation,
  RestoreStatus,
  RestoreTarget,
  RestoreTargetList,
} from './restore.model';

const ORGANIZATION_ID = 'org-1';
const BASE = `/api/v1/organizations/${ORGANIZATION_ID}`;
const TARGETS_URL = `${BASE}/restores/targets`;
const OPERATIONS_URL = `${BASE}/restores`;
const PLANS_URL = `${BASE}/restores/plans`;

const ROLE_RANK: Record<UserRole, number> = { viewer: 0, operator: 1, administrator: 2 };

function target(overrides: Partial<RestoreTarget> & { version_id: string }): RestoreTarget {
  return {
    logical_object_id: `lo-${overrides.version_id}`,
    name: 'NW-Corp',
    object_type: 'wlan',
    scope: 'org',
    site_mist_id: null,
    site_name: null,
    version: 14,
    observed_at: '2026-09-02T11:40:00Z',
    ...overrides,
  };
}

const NW_CORP = target({ version_id: 'v-corp', name: 'NW-Corp', object_type: 'wlan', version: 14 });
const RF_DENSE = target({
  version_id: 'v-rf',
  name: 'Indoor-Dense-6G',
  object_type: 'rftemplate',
  version: 3,
});
const SEA_VOICE = target({
  version_id: 'v-voice',
  name: 'SEA-Voice',
  object_type: 'wlan',
  scope: 'site',
  site_mist_id: 'site-1',
  site_name: 'Seattle-DC',
  version: 5,
});

function targetList(items: RestoreTarget[], total = items.length): RestoreTargetList {
  const types = new Map<string, number>();
  for (const item of items) {
    types.set(item.object_type, (types.get(item.object_type) ?? 0) + 1);
  }
  return {
    items,
    total,
    types: [...types].map(([type, count]) => ({ type, count })),
    sites: [{ id: 'site-1', name: 'Seattle-DC' }],
  };
}

function action(overrides: Partial<RestoreAction> = {}): RestoreAction {
  return {
    logical_object_id: 'lo-1',
    source_version_id: 'v-corp',
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

function operation(overrides: Partial<RestoreOperation> = {}): RestoreOperation {
  return {
    id: 'op-1',
    mode: 'non_destructive',
    include_dependencies: true,
    requested_version_ids: ['v-corp'],
    target_at: '2026-09-02T11:40:00Z',
    status: 'planned',
    actions: [action(), action({ logical_object_id: 'lo-2', order: 1, object_name: 'SEA-Voice' })],
    warnings: [],
    preflight_errors: [],
    credential_actor: null,
    started_at: null,
    completed_at: null,
    created_at: '2026-09-07T14:22:00Z',
    task_id: null,
    approval: null,
    compensation_available: false,
    ...overrides,
  };
}

describe('RestorePage', () => {
  let fixture: ComponentFixture<RestorePage>;
  let httpMock: HttpTestingController;
  let historical: boolean;
  let role: UserRole;
  let navigations: { commands: unknown[]; extras: Record<string, unknown> | undefined }[];

  const organizationStub = {
    selected: signal({ id: ORGANIZATION_ID, name: 'Northwind Retail', status: 'verified' }),
    revision: signal(0),
  };

  beforeEach(async () => {
    historical = false;
    role = 'administrator';
    navigations = [];
    // The stub is shared across tests; one that switches organization must not
    // leak that into the next.
    organizationStub.selected.set({ id: ORGANIZATION_ID, name: 'Northwind Retail', status: 'verified' });
    organizationStub.revision.set(0);
    // Only the poll interval is faked: Angular's zoneless scheduler still needs
    // real microtasks and timeouts to settle the fixture between assertions.
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });

    await TestBed.configureTestingModule({
      imports: [RestorePage],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        {
          provide: Router,
          useValue: {
            events: EMPTY,
            navigate: (commands: unknown[], extras?: Record<string, unknown>) => {
              navigations.push({ commands, extras });
              return Promise.resolve(true);
            },
          },
        },
        {
          provide: OrganizationContextService,
          useValue: organizationStub as unknown as OrganizationContextService,
        },
        { provide: AuthService, useValue: { can: (min: UserRole) => ROLE_RANK[role] >= ROLE_RANK[min] } },
        { provide: TimeContextService, useValue: { isHistorical: () => historical } },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(RestorePage);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    vi.useRealTimers();
    try {
      httpMock.verify();
    } finally {
      // Reset explicitly so one failing expectation cannot cascade into the
      // next test through a test module that was never torn down.
      TestBed.resetTestingModule();
    }
  });

  // ---- helpers ------------------------------------------------------------

  function element(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function text(): string {
    return (element().textContent ?? '').replace(/\s+/g, ' ').trim();
  }

  function all<T extends HTMLElement = HTMLElement>(selector: string): T[] {
    return Array.from(element().querySelectorAll<T>(selector));
  }

  function button(label: string): HTMLButtonElement | undefined {
    return all('button').find((node) => (node.textContent ?? '').trim().startsWith(label)) as
      | HTMLButtonElement
      | undefined;
  }

  /**
   * Drain the microtask queue.
   *
   * The page chains several awaits between a flushed response and the signal
   * write it produces, and `whenStable` only guarantees one turn, so the queue
   * is drained explicitly before anything is asserted or expected.
   */
  async function drain(): Promise<void> {
    for (let turn = 0; turn < 12; turn += 1) {
      await Promise.resolve();
    }
  }

  /** Drain, then let the fixture render what the drained work produced. */
  async function settle(): Promise<void> {
    await drain();
    await fixture.whenStable();
    fixture.detectChanges();
    await fixture.whenStable();
  }

  /** Drain far enough that every request the page owes has been issued. */
  async function tick(): Promise<void> {
    await drain();
    await fixture.whenStable();
  }

  function pillText(): string[] {
    return all('.pill').map((node) => (node.textContent ?? '').replace(/\s+/g, ' ').trim());
  }

  /** Answer the two requests the page issues on load, in either arrival order. */
  async function boot(
    targets: RestoreTargetList = targetList([NW_CORP, RF_DENSE, SEA_VOICE]),
    history: RestoreOperation[] = [],
  ): Promise<void> {
    fixture.detectChanges();
    await tick();
    httpMock.expectOne((request) => request.url === TARGETS_URL).flush(targets);
    httpMock.expectOne((request) => request.url === OPERATIONS_URL).flush({
      items: history,
      total: history.length,
    });
    await settle();
  }

  /** Flush the next targets read and return the request it answered. */
  async function nextTargets(response: RestoreTargetList) {
    await tick();
    const request = httpMock.expectOne((candidate) => candidate.url === TARGETS_URL);
    request.flush(response);
    await settle();
    return request;
  }

  // ---- step 1: filtering --------------------------------------------------

  it('counts what is shown against the whole catalogue and facets the type row', async () => {
    await boot(targetList([NW_CORP, RF_DENSE, SEA_VOICE]));

    expect(text()).toContain('3 of 3 restorable objects match · 0 selected');
    expect(all('.target').length).toBe(3);
    const types = all('.filter-row--types .cg-chip').map((chip) =>
      (chip.textContent ?? '').replace(/\s+/g, ' ').trim(),
    );
    // "All types" carries the sum of the server's facet counts.
    expect(types).toEqual(['All types 3', 'wlan 2', 'rftemplate 1']);
  });

  it('narrows scope, type, and name server-side and sends each as a query parameter', async () => {
    await boot();

    button('Organization')?.click();
    let request = await nextTargets(targetList([NW_CORP, RF_DENSE], 2));
    expect(request.request.params.get('scope')).toBe('org');
    expect(request.request.params.get('limit')).toBe('25');

    button('rftemplate')?.click();
    request = await nextTargets(targetList([RF_DENSE], 1));
    expect(request.request.params.get('scope')).toBe('org');
    expect(request.request.params.get('object_type')).toBe('rftemplate');
    expect(all('.target-name').map((node) => node.textContent)).toEqual(['Indoor-Dense-6G']);

    const search = element().querySelector<HTMLInputElement>('.search-input');
    search!.value = 'nothing-matches';
    search!.dispatchEvent(new Event('change'));
    request = await nextTargets(targetList([], 0));
    expect(request.request.params.get('q')).toBe('nothing-matches');
    expect(text()).toContain('No objects match these filters');

    button('Clear filters')!.click();
    request = await nextTargets(targetList([NW_CORP, RF_DENSE, SEA_VOICE]));
    expect(request.request.params.get('scope')).toBe('all');
    expect(request.request.params.has('object_type')).toBe(false);
    expect(request.request.params.has('q')).toBe(false);
  });

  it('reads one page at a time and walks the window server-side', async () => {
    await boot(targetList([NW_CORP, RF_DENSE, SEA_VOICE], 70));

    expect(text()).toContain('Showing 1–3 of 70 matching objects');
    expect(button('Previous')?.disabled).toBe(true);
    expect(button('Next')?.disabled).toBe(false);

    button('Next')!.click();
    let request = await nextTargets(targetList([NW_CORP], 70));
    expect(request.request.params.get('skip')).toBe('25');
    expect(request.request.params.get('limit')).toBe('25');
    expect(button('Previous')?.disabled).toBe(false);

    button('Previous')!.click();
    request = await nextTargets(targetList([NW_CORP, RF_DENSE, SEA_VOICE], 70));
    expect(request.request.params.get('skip')).toBe('0');
  });

  it('asks the server again for a new page size, from the first row', async () => {
    await boot(targetList([NW_CORP, RF_DENSE, SEA_VOICE], 70));

    button('Next')!.click();
    await nextTargets(targetList([NW_CORP], 70));

    const size = element().querySelector<HTMLSelectElement>('.pager-select');
    size!.value = '100';
    size!.dispatchEvent(new Event('change'));
    const request = await nextTargets(targetList([NW_CORP, RF_DENSE, SEA_VOICE], 70));

    expect(request.request.params.get('limit')).toBe('100');
    // A page number means a different window at a different size, so the only
    // offset that still names the same rows is the first.
    expect(request.request.params.get('skip')).toBe('0');
  });

  it('returns to the first page when a filter changes, so no page is left empty', async () => {
    await boot(targetList([NW_CORP, RF_DENSE, SEA_VOICE], 70));

    button('Next')!.click();
    await nextTargets(targetList([NW_CORP], 70));

    button('Organization')!.click();
    const request = await nextTargets(targetList([RF_DENSE], 1));
    expect(request.request.params.get('scope')).toBe('org');
    expect(request.request.params.get('skip')).toBe('0');
    expect(button('Next')?.disabled).toBe(true);
  });

  it('offers the site select only once the site scope is chosen', async () => {
    await boot();
    expect(all('.site-select').length).toBe(0);

    button('Site')?.click();
    const request = await nextTargets(targetList([SEA_VOICE], 1));
    expect(request.request.params.get('scope')).toBe('site');
    expect(all('.site-select').length).toBe(1);

    const select = element().querySelector<HTMLSelectElement>('.site-select');
    select!.value = 'site-1';
    select!.dispatchEvent(new Event('change'));
    const scoped = await nextTargets(targetList([SEA_VOICE], 1));
    expect(scoped.request.params.get('site_id')).toBe('site-1');
  });

  it('keeps the selected pills when a filter hides the row they came from', async () => {
    await boot();

    all<HTMLInputElement>('.target-box')[0].click();
    await settle();
    expect(pillText()).toEqual(['NW-Corp · v14 ✕']);

    // A filter that excludes NW-Corp entirely must not drop it from the selection.
    button('rftemplate')?.click();
    await nextTargets(targetList([RF_DENSE], 1));

    expect(all('.target-name').map((node) => node.textContent)).toEqual(['Indoor-Dense-6G']);
    expect(pillText()).toEqual(['NW-Corp · v14 ✕']);
    expect(text()).toContain('1 selected');

    // And removing it from the pill row still works while it is filtered out.
    element().querySelector<HTMLButtonElement>('.pill-remove')!.click();
    await settle();
    expect(all('.pill').length).toBe(0);
  });

  it('boots with no deep link at all, which the router writes as undefined', async () => {
    // `withComponentInputBinding` writes every bound input on activation, so an
    // absent query parameter arrives as `undefined` rather than as the default.
    for (const name of ['versions', 'changeGroup', 'operation', 'step', 'compensate']) {
      fixture.componentRef.setInput(name, undefined);
    }
    await boot();

    expect(text()).toContain('3 of 3 restorable objects match · 0 selected');
    expect(all('.pill').length).toBe(0);
    expect(all('.step-button--on')[0].textContent).toContain('1 · Select targets');
  });

  it('pre-selects the versions named by ?versions= even when the picker cannot list them', async () => {
    fixture.componentRef.setInput('versions', 'v-corp,65f0aa11bb22cc33dd44ee55');
    await boot(targetList([NW_CORP, RF_DENSE]));

    expect(pillText()).toEqual(['NW-Corp · v14 ✕', 'version 65f0aa11 ✕']);
    expect(text()).toContain('2 selected');
  });

  it('preselects embedded version links without creating a plan until explicitly requested', async () => {
    fixture.componentRef.setInput('embedded', true);
    fixture.componentRef.setInput('versions', 'v-corp');
    await boot();

    // One version names one object, so the catalogue picker is not what opens.
    expect(all('.subject-name')[0].textContent).toContain('NW-Corp · v14');
    expect(all('.target').length).toBe(0);
    expect(all('.step-button--on')[0].textContent).toContain('1 · Select targets');
    httpMock.expectNone((request) => request.method === 'POST');

    // Query-only navigation on the mounted workspace must also stay read-only.
    fixture.componentRef.setInput('versions', 'v-rf');
    await settle();
    expect(all('.subject-name')[0].textContent).toContain('Indoor-Dense-6G · v3');
    httpMock.expectNone((request) => request.method === 'POST');

    button('Build restore plan')!.click();
    await tick();
    const request = httpMock.expectOne(PLANS_URL);
    expect(request.request.method).toBe('POST');
    expect(request.request.body.version_ids).toEqual(['v-rf']);
    request.flush(operation({ requested_version_ids: ['v-rf'] }));
    await settle();
    expect(all('.step-button--on')[0].textContent).toContain('2 · Review plan');
    httpMock.expectNone((request) => request.method === 'POST');
  });

  it('describes what a focused restore reaches, rather than promising it reaches nothing', async () => {
    // Dependencies are included by default, and the planner takes every
    // related object to the same moment — deleting the ones that did not
    // exist then, in exact mode. Only excluding them touches this object alone.
    fixture.componentRef.setInput('embedded', true);
    fixture.componentRef.setInput('versions', 'v-corp');
    await boot();

    expect(text()).toContain('Objects it depends on are taken to the same moment if they have changed since');
    expect(text()).not.toContain('nothing else is touched');

    all<HTMLInputElement>('.mode input')[1].click();
    await settle();
    expect(text()).toContain('any that did not exist then are deleted');

    element().querySelector<HTMLButtonElement>('.cg-toggle')!.click();
    await settle();
    expect(text()).toContain('Only this object is written — nothing else is touched.');
  });

  it('keeps a focused restore on its object when the mode or dependencies change', async () => {
    // Neither changes the selection, so the link that named it must survive.
    // It carries the version, and the version is how the object is named.
    fixture.componentRef.setInput('embedded', true);
    fixture.componentRef.setInput('versions', 'v-corp');
    await boot();

    all<HTMLInputElement>('.mode input')[1].click();
    element().querySelector<HTMLButtonElement>('.cg-toggle')!.click();
    await settle();

    expect(all('.subject-name')[0].textContent).toContain('NW-Corp · v14');
    expect(navigations).toEqual([]);
  });

  it('reopens an embedded existing plan without creating another one', async () => {
    fixture.componentRef.setInput('embedded', true);
    fixture.componentRef.setInput('versions', 'v-corp');
    fixture.componentRef.setInput('operation', 'op-1');
    await boot();
    httpMock.expectOne(`${OPERATIONS_URL}/op-1`).flush(operation({ status: 'planned' }));
    await settle();
    expect(all('.step-button--on')[0].textContent).toContain('2 · Review plan');
    httpMock.expectNone((request) => request.method === 'POST');
  });

  it('pre-selects the versions a change group replaced, labelled from the group', async () => {
    fixture.componentRef.setInput('changeGroup', 'cg1');
    fixture.detectChanges();
    await tick();
    httpMock.expectOne((request) => request.url === TARGETS_URL).flush(targetList([NW_CORP]));
    httpMock.expectOne((request) => request.url === OPERATIONS_URL).flush({ items: [], total: 0 });
    await tick();
    // The picker only offers the newest version of each object, so the versions
    // the group replaced are resolved from the group itself.
    httpMock.expectOne(`${BASE}/change-groups/cg1`).flush({
      id: 'cg1',
      title: 'RF template reassignment',
      changed_objects: [
        {
          logical_object_id: 'lo-1',
          object_type: 'wlan',
          object_name: 'NW-Corp',
          scope: 'org',
          site_mist_id: null,
          event: 'updated',
          before_version_id: 'v-corp-14',
          after_version_id: 'v-corp-15',
          before_version: 14,
          after_version: 15,
          changed_fields: ['rf_template_id'],
        },
        {
          logical_object_id: 'lo-3',
          object_type: 'network',
          object_name: 'guest-wifi',
          scope: 'org',
          site_mist_id: null,
          event: 'created',
          before_version_id: null,
          after_version_id: 'v-guest-1',
          before_version: null,
          after_version: 1,
          changed_fields: [],
        },
      ],
    });
    await settle();

    expect(text()).toContain('Pre-selected from the versions');
    expect(text()).toContain('RF template reassignment');
    // An object the group created has no earlier version, so it is not offered.
    expect(pillText()).toEqual(['NW-Corp · v14 ✕']);

    button('Clear this selection')!.click();
    await settle();
    expect(pillText()).toEqual([]);
    expect(all('.scoped').length).toBe(0);
  });

  // ---- step 2: preflight --------------------------------------------------

  async function plan(overrides: Partial<RestoreOperation> = {}): Promise<void> {
    await boot();
    all<HTMLInputElement>('.target-box')[0].click();
    await settle();
    button('Build restore plan')!.click();
    await tick();
    const request = httpMock.expectOne(PLANS_URL);
    expect(request.request.body).toEqual({
      version_ids: ['v-corp'],
      mode: 'non_destructive',
      include_dependencies: true,
    });
    request.flush(operation(overrides));
    await settle();
  }

  it('renders the ordered action list with dependency ordering and op badges', async () => {
    await plan({
      warnings: ['Objects created after the target moment are left untouched in this mode.'],
      actions: [
        action({ order: 1, object_name: 'NW-Corp', depends_on: ['lo-2'] }),
        action({
          logical_object_id: 'lo-2',
          order: 0,
          action: 'create',
          object_name: 'corp-voice',
          object_type: 'network',
        }),
      ],
    });

    expect(all('.step-button--on')[0].textContent).toContain('2 · Review plan');
    // Sorted by `order`, not by the order the API listed them in.
    expect(all('.object-name').map((node) => node.textContent)).toEqual(['corp-voice', 'NW-Corp']);
    expect(all('.cell-index').map((node) => node.textContent)).toEqual(['01', '02']);
    expect(all('.row .cg-badge--ok')[0].textContent).toContain('CREATE');
    expect(all('.row .cg-badge--warn')[0].textContent).toContain('UPDATE');
    expect(text()).toContain('after 1 dependency');
    expect(text()).toContain('PLAN WARNINGS');
    expect(text()).toContain('Objects created after the target moment are left untouched');
    expect(button('Continue to authorize')!.disabled).toBe(false);
  });

  it('blocks step 3 while the plan carries preflight errors', async () => {
    await plan({
      preflight_errors: ['NW-Corp changed in Mist since the plan was built.'],
    });

    expect(all('.preflight').length).toBe(1);
    expect(text()).toContain('NW-Corp changed in Mist since the plan was built.');
    expect(button('Continue to authorize')!.disabled).toBe(true);

    // The step indicator refuses the jump as well, and clicking changes nothing.
    const authorizeStep = all('.step-button')[2] as HTMLButtonElement;
    expect(authorizeStep.disabled).toBe(true);
    authorizeStep.click();
    button('Continue to authorize')!.click();
    await settle();
    expect(all('.step-button--on')[0].textContent).toContain('2 · Review plan');
    expect(all('app-restore-step-authorize').length).toBe(0);
  });

  it('has nothing to authorize when the plan computed no actions', async () => {
    await plan({ actions: [] });

    expect(text()).toContain('Plan · 0 actions');
    expect(text()).toContain('This plan contains no actions');
    expect(button('Continue to authorize')!.disabled).toBe(true);
    expect((all('.step-button')[2] as HTMLButtonElement).disabled).toBe(true);
  });

  // ---- step 3: authorize --------------------------------------------------

  it('submits the token once, clears the field, and never keeps it', async () => {
    await plan();
    button('Continue to authorize')!.click();
    await settle();

    const token = element().querySelector<HTMLInputElement>('.token-input')!;
    expect(token.type).toBe('password');
    const submit = button('Capture backup and review new plan')!;
    expect(submit.disabled).toBe(true);

    token.value = 'short';
    token.dispatchEvent(new Event('input'));
    await settle();
    expect(text()).toContain('Token looks too short');
    expect(button('Capture backup and review new plan')!.disabled).toBe(true);

    token.value = 'a-fresh-administrator-token';
    token.dispatchEvent(new Event('input'));
    await settle();
    expect(text()).toContain('Token accepted');

    button('Capture backup and review new plan')!.click();
    await tick();
    const request = httpMock.expectOne(`${OPERATIONS_URL}/op-1/prepare`);
    expect(request.request.body).toEqual({ administrator_token: 'a-fresh-administrator-token' });
    request.flush(operation({ id: 'op-2', baseline_snapshot_id: 'backup-1', prepared_until: new Date(Date.now() + 60_000).toISOString(), status: 'planned' }));
    await settle();

    // The credential left in the request body and nowhere else: not in the
    // rendered page, and not in any URL the page asked the router for.
    expect(element().innerHTML).not.toContain('a-fresh-administrator-token');
    expect(element().querySelector('.token-input')).toBeNull();
    expect(JSON.stringify(navigations)).not.toContain('a-fresh-administrator-token');
    expect(all('.step-button--on')[0].textContent).toContain('2 · Review plan');
    httpMock.expectNone(`${OPERATIONS_URL}/op-2/execute`);
    button('Continue to authorize')!.click();
    await settle();
    expect(element().querySelector('.token-input')).toBeNull();
    button('Execute reviewed plan')!.click();
    await tick();
    const execution = httpMock.expectOne(`${OPERATIONS_URL}/op-2/execute`);
    expect(execution.request.body).toEqual({ use_prepared_credential: true });
    execution.flush(operation({ id: 'op-2', baseline_snapshot_id: 'backup-1', prepared_until: new Date(Date.now() + 60_000).toISOString(), status: 'queued' }));
    await settle();
    // Both the draft and the freshly prepared plan get their own URLs.
    expect(navigations).toEqual([
      { commands: ['/history'], extras: { queryParams: { restore: '1', operation: 'op-1', versions: null, changeGroup: null, step: null, compensate: null }, queryParamsHandling: 'merge', replaceUrl: true } },
      { commands: ['/history'], extras: { queryParams: { restore: '1', operation: 'op-2', versions: null, changeGroup: null, step: null, compensate: null }, queryParamsHandling: 'merge', replaceUrl: true } },
    ]);
    expect(all('.step-button--on')[0].textContent).toContain('4 · Execute');
  });

  it('returns to fresh backup preparation when the review session expires while open', async () => {
    const now = Date.now();
    await plan({ baseline_snapshot_id: 'backup-1', prepared_until: new Date(now + 60_000).toISOString() });
    button('Continue to authorize')!.click();
    await settle();
    expect(button('Execute reviewed plan')).toBeTruthy();
    const clock = vi.spyOn(Date, 'now').mockReturnValue(now + 60_001);
    try {
      vi.advanceTimersByTime(1000);
      await settle();
      expect(button('Execute reviewed plan')).toBeUndefined();
      expect(text()).toContain('Capture a fresh backup before final review');
      const token = element().querySelector<HTMLInputElement>('.token-input')!;
      token.value = 'a-fresh-administrator-token';
      token.dispatchEvent(new Event('input'));
      await settle();
      button('Capture backup and review new plan')!.click();
      await tick();
      httpMock.expectNone(`${OPERATIONS_URL}/op-1/execute`);
      const request = httpMock.expectOne(`${OPERATIONS_URL}/op-1/prepare`);
      expect(request.request.body).toEqual({ administrator_token: 'a-fresh-administrator-token' });
      request.flush(operation({ id: 'op-2', baseline_snapshot_id: 'backup-2', prepared_until: new Date(now + 120_000).toISOString() }));
      await settle();
      expect(all('.step-button--on')[0].textContent).toContain('2 · Review plan');
    } finally {
      clock.mockRestore();
    }
  });

  it('shows the approval state and withholds execution until it is granted', async () => {
    await plan({
      baseline_snapshot_id: 'backup-1', prepared_until: new Date(Date.now() + 60_000).toISOString(),
      approval: {
        id: 'ap-1',
        restore_operation_id: 'op-1',
        status: 'pending',
        triggered_rules: [
          { rule: 'organization_scope', detail: 'NW-Corp is organization-scoped.' },
        ],
        requested_by_email: 's.kaur@northwind.example',
        decided_by_email: null,
        decided_at: null,
        decision_reason: null,
        expires_at: '2026-09-08T14:22:00Z',
        plan_hash: 'abc',
        summary: '2 objects restored to their 02 SEP state.',
        object_count: 2,
        delete_count: 0,
        created_at: '2026-09-07T14:22:00Z',
      },
    });
    button('Continue to authorize')!.click();
    await settle();

    expect(text()).toContain('SECOND ADMINISTRATOR');
    expect(text()).toContain('PENDING');
    expect(text()).toContain('Organization-scoped objects — NW-Corp is organization-scoped.');

    expect(button('Execute reviewed plan')!.disabled).toBe(true);

    button('Check for a decision')!.click();
    await tick();
    httpMock.expectOne(`${BASE}/approvals/ap-1`).flush({
      id: 'ap-1',
      restore_operation_id: 'op-1',
      status: 'approved',
      triggered_rules: [],
      requested_by_email: 's.kaur@northwind.example',
      decided_by_email: 'a.osei@northwind.example',
      decided_at: '2026-09-07T15:00:00Z',
      decision_reason: null,
      expires_at: null,
      plan_hash: 'abc',
      summary: '2 objects restored to their 02 SEP state.',
      object_count: 2,
      delete_count: 0,
      created_at: '2026-09-07T14:22:00Z',
    });
    await settle();

    expect(text()).toContain('APPROVED');
    expect(button('Execute reviewed plan')!.disabled).toBe(false);
  });

  it('submits Mist login without a region and clears the credential fields', async () => {
    const element = fixture.nativeElement as HTMLElement;
    await plan();
    button('Continue to authorize')!.click();
    await settle();

    const methods = all('.method');
    expect(methods.length).toBe(2);
    expect(methods[1].textContent).toContain('Mist login and password');
    const radio = methods[1].querySelector<HTMLInputElement>('input')!;
    expect(radio.disabled).toBe(false);
    radio.click();
    await settle();
    expect(element.querySelector('app-restore-step-authorize select')).toBeNull();
    for (const [id, value] of [['mist-email', 'admin@example.com'], ['mist-password', ' password ']]) {
      const input = element.querySelector<HTMLInputElement>(`#${id}`)!;
      input.value = value;
      input.dispatchEvent(new Event('input'));
    }
    await settle();
    expect(element.querySelector<HTMLInputElement>('#mist-email')!.value).toBe('admin@example.com');
    expect(element.querySelector<HTMLFormElement>('#mist-restore-login')!.checkValidity()).toBe(true);
    button('Capture backup and review new plan')!.click();
    await settle();
    const request = httpMock.expectOne(`${OPERATIONS_URL}/op-1/prepare`);
    expect(request.request.body).toEqual({ mist_login: { email: 'admin@example.com', password: ' password ' } });
    expect(element.querySelector<HTMLInputElement>('#mist-password')!.value).toBe('');
    expect(element.querySelector('#mist-code')).toBeNull();
    expect(element.querySelector('#mist-password')?.closest('form')?.id).toBe('mist-restore-login');
    expect(element.querySelector('#mist-email')?.getAttribute('name')).toBe('username');
    request.flush({ detail: { code: 'mist_mfa_required' } }, { status: 409, statusText: 'Conflict' });
    await settle();
    TestBed.inject(MistMfaService).prompt()!.complete('123456');
    await settle();
    const retry = httpMock.expectOne(`${OPERATIONS_URL}/op-1/prepare`);
    expect(retry.request.body).toEqual({ mist_login: { email: 'admin@example.com', password: ' password ', two_factor: '123456' } });
    retry.flush({ detail: 'Mist rejected the login' }, { status: 422, statusText: 'Unprocessable Content' });
    await settle();
  });

  // ---- step 4: polling ----------------------------------------------------

  /** Open a running operation straight from the `?operation=` deep link. */
  async function openRunning(status: RestoreStatus = 'running'): Promise<void> {
    fixture.componentRef.setInput('operation', 'op-1');
    fixture.detectChanges();
    await tick();
    httpMock.expectOne((request) => request.url === TARGETS_URL).flush(targetList([NW_CORP]));
    httpMock
      .expectOne((request) => request.url === OPERATIONS_URL)
      .flush({ items: [], total: 0 });
    await tick();
    httpMock.expectOne(`${OPERATIONS_URL}/op-1`).flush(operation({ status }));
    await settle();
  }

  it('polls every two seconds while running and stops on a terminal status', async () => {
    await openRunning();

    expect(all('.step-button--on')[0].textContent).toContain('4 · Execute');
    expect(text()).toContain('RUNNING');
    expect(all('.cg-spinner').length).toBe(1);

    vi.advanceTimersByTime(2000);
    await tick();
    httpMock.expectOne(`${OPERATIONS_URL}/op-1`).flush(
      operation({
        status: 'running',
        actions: [action({ status: 'completed' }), action({ order: 1, status: 'executing' })],
      }),
    );
    await settle();
    expect(text()).toContain('Applying action 2 of 2');
    expect(element().querySelector('[role="progressbar"]')!.getAttribute('aria-valuetext')).toBe(
      '1 of 2 actions',
    );
    expect(element().querySelector('.track-fill')!.getAttribute('style')).toContain('50%');

    vi.advanceTimersByTime(2000);
    await tick();
    httpMock.expectOne(`${OPERATIONS_URL}/op-1`).flush(
      operation({
        status: 'completed',
        completed_at: '2026-09-07T14:30:00Z',
        actions: [action({ status: 'completed' }), action({ order: 1, status: 'completed' })],
      }),
    );
    await tick();
    httpMock.expectOne(`${OPERATIONS_URL}/op-1/verification`).flush({
      verified: true,
      checks: [{ label: 'Object states match the target version', status: 'ok', detail: null }],
      post_snapshot_id: 'snap-1',
      monitoring_session_ids: ['sess-1'],
    });
    await tick();
    // A finished run refreshes the rail beside the picker.
    httpMock.expectOne((request) => request.url === OPERATIONS_URL).flush({ items: [], total: 0 });
    await settle();

    expect(text()).toContain('COMPLETED');
    expect(text()).toContain('VERIFIED');
    expect(text()).toContain('Object states match the target version');

    // Terminal: the interval is cleared, so no further read is ever issued.
    vi.advanceTimersByTime(20_000);
    await tick();
    httpMock.expectNone(`${OPERATIONS_URL}/op-1`);
    expect(all('.cg-spinner').length).toBe(0);

    button('Open the post-restore snapshot')!.click();
    button('Watch impact')!.click();
    // History opens on its object list: it has no snapshot-addressable view, so
    // sending the snapshot identifier would name a parameter nothing reads.
    expect(navigations).toEqual([
      { commands: ['/history'], extras: undefined },
      { commands: ['/impact'], extras: { queryParams: { session: 'sess-1' } } },
    ]);
  });

  it('never starts polling for an operation that is already terminal', async () => {
    await openRunning('failed');

    // A terminal deep link skips verification and settles without an interval.
    expect(text()).toContain('FAILED');
    vi.advanceTimersByTime(10_000);
    await tick();
    httpMock.expectNone(`${OPERATIONS_URL}/op-1`);
  });

  it('opens another operation when its link arrives while the page is already open', async () => {
    // The router reuses this component when only the query parameters change,
    // so a second notification clicked from here must land the way the first did.
    await openRunning();
    expect(text()).toContain('RUNNING');

    fixture.componentRef.setInput('operation', 'op-2');
    fixture.detectChanges();
    await tick();
    // The operation shown until now is not re-read; nor is the rail, which
    // follows the organization rather than the link.
    httpMock.expectNone(`${OPERATIONS_URL}/op-1`);
    httpMock.expectNone((request) => request.url === OPERATIONS_URL);
    httpMock.expectOne(`${OPERATIONS_URL}/op-2`).flush(operation({ id: 'op-2', status: 'planned' }));
    await settle();

    expect(all('.step-button--on')[0].textContent).toContain('2 ·');
    expect(text()).not.toContain('RUNNING');
    // The first operation's poll does not outlive it: left running, it would
    // read whichever operation is active and poll the planned one forever.
    expect(all('.cg-spinner').length).toBe(0);
    vi.advanceTimersByTime(20_000);
    await tick();
    httpMock.expectNone(`${OPERATIONS_URL}/op-1`);
    httpMock.expectNone(`${OPERATIONS_URL}/op-2`);
  });

  it('does not re-open the linked operation when the organization merely refreshes', async () => {
    // The same link arriving again is not a new instruction; re-applying it
    // would reset whatever the user has done since.
    await openRunning();

    organizationStub.revision.update((value) => value + 1);
    fixture.detectChanges();
    await tick();
    // A refresh re-reads the picker and the rail, and nothing else.
    httpMock.expectOne((request) => request.url === TARGETS_URL).flush(targetList([NW_CORP]));
    httpMock.expectOne((request) => request.url === OPERATIONS_URL).flush({ items: [], total: 0 });
    await tick();

    httpMock.expectNone(`${OPERATIONS_URL}/op-1`);
    expect(text()).toContain('RUNNING');
  });

  it('drops a late answer for an operation that is no longer the one asked for', async () => {
    // A Promise cannot be cancelled: the first read is still in flight when the
    // link moves on, and its answer must not land on the second operation.
    fixture.componentRef.setInput('operation', 'op-1');
    fixture.detectChanges();
    await tick();
    httpMock.expectOne((request) => request.url === TARGETS_URL).flush(targetList([NW_CORP]));
    httpMock.expectOne((request) => request.url === OPERATIONS_URL).flush({ items: [], total: 0 });
    await tick();
    const late = httpMock.expectOne(`${OPERATIONS_URL}/op-1`);

    fixture.componentRef.setInput('operation', 'op-2');
    fixture.detectChanges();
    await tick();
    httpMock.expectOne(`${OPERATIONS_URL}/op-2`).flush(operation({ id: 'op-2', status: 'planned' }));
    await settle();
    expect(all('.step-button--on')[0].textContent).toContain('2 ·');

    late.flush(operation({ id: 'op-1', status: 'failed' }));
    await settle();

    expect(text()).not.toContain('FAILED');
    expect(all('.step-button--on')[0].textContent).toContain('2 ·');
  });

  it('forgets the operation and clears the link when the organization changes', async () => {
    await openRunning();

    organizationStub.selected.set({ id: 'org-2', name: 'Contoso', status: 'verified' });
    fixture.detectChanges();
    await tick();
    // The other organization's picker and rail load; the link is not read there,
    // because the identifiers in it belong to the organization that wrote it.
    httpMock
      .expectOne((request) => request.url === '/api/v1/organizations/org-2/restores/targets')
      .flush(targetList([]));
    httpMock
      .expectOne((request) => request.url === '/api/v1/organizations/org-2/restores')
      .flush({ items: [], total: 0 });
    await settle();
    httpMock.expectNone('/api/v1/organizations/org-2/restores/op-1');

    expect(text()).not.toContain('RUNNING');
    expect(all('.step-button--on')[0].textContent).toContain('1 · Select targets');
    expect(navigations).toEqual([{ commands: ['/history/restore'], extras: { queryParams: {} } }]);
    // The first organization's poll is gone with its operation.
    vi.advanceTimersByTime(20_000);
    await tick();
    httpMock.expectNone(`${OPERATIONS_URL}/op-1`);
  });

  it('carries nothing of a finished operation over to the next one opened', async () => {
    fixture.componentRef.setInput('operation', 'op-1');
    fixture.detectChanges();
    await tick();
    httpMock.expectOne((request) => request.url === TARGETS_URL).flush(targetList([NW_CORP]));
    httpMock.expectOne((request) => request.url === OPERATIONS_URL).flush({ items: [], total: 0 });
    await tick();
    httpMock.expectOne(`${OPERATIONS_URL}/op-1`).flush(operation({ status: 'completed' }));
    await tick();
    httpMock.expectOne(`${OPERATIONS_URL}/op-1/verification`).flush({
      verified: true,
      checks: [{ label: 'Object states match the target version', status: 'ok', detail: null }],
      post_snapshot_id: 'snap-1',
      monitoring_session_ids: [],
    });
    await settle();
    expect(text()).toContain('VERIFIED');

    fixture.componentRef.setInput('operation', 'op-2');
    fixture.detectChanges();
    await tick();
    httpMock.expectOne(`${OPERATIONS_URL}/op-2`).flush(operation({ id: 'op-2', status: 'running' }));
    await settle();

    expect(text()).not.toContain('VERIFIED');
    expect(text()).not.toContain('Object states match the target version');
    expect(text()).toContain('RUNNING');
  });

  it('writes an operation picked from the rail into the URL', async () => {
    // The rail is a navigation: a refresh must return to the operation picked,
    // and a later link to the same operation must find the URL already there.
    await boot(targetList([NW_CORP]), [operation({ id: 'op-9', status: 'completed' })]);

    element().querySelector<HTMLButtonElement>('.rail .entry')!.click();
    await tick();
    httpMock.expectOne(`${OPERATIONS_URL}/op-9`).flush(operation({ id: 'op-9', status: 'planned' }));
    await settle();

    expect(navigations).toEqual([
      { commands: ['/history'], extras: { queryParams: { restore: '1', operation: 'op-9', versions: null, changeGroup: null, step: null, compensate: null }, queryParamsHandling: 'merge', replaceUrl: false } },
    ]);
    expect(all('.step-button--on')[0].textContent).toContain('2 ·');
  });

  it('clears the operation from the URL when a new restore is started', async () => {
    fixture.componentRef.setInput('operation', 'op-1');
    fixture.detectChanges();
    await tick();
    httpMock.expectOne((request) => request.url === TARGETS_URL).flush(targetList([NW_CORP]));
    httpMock.expectOne((request) => request.url === OPERATIONS_URL).flush({ items: [], total: 0 });
    await tick();
    httpMock.expectOne(`${OPERATIONS_URL}/op-1`).flush(operation({ status: 'completed' }));
    await tick();
    httpMock.expectOne(`${OPERATIONS_URL}/op-1/verification`).flush({
      verified: true,
      checks: [],
      post_snapshot_id: null,
      monitoring_session_ids: [],
    });
    await settle();
    expect(text()).toContain('COMPLETED');

    button('New restore')!.click();
    await settle();

    // A refresh must return to an empty picker, not to the finished operation.
    expect(navigations).toEqual([{ commands: ['/history'], extras: { queryParams: { restore: '1', operation: null, versions: null, changeGroup: null, step: null, compensate: null }, queryParamsHandling: 'merge', replaceUrl: false } }]);
    expect(all('.step-button--on')[0].textContent).toContain('1 · Select targets');
    expect(text()).not.toContain('COMPLETED');
  });

  it('keeps the picker on the answer to the latest filter, whatever order answers arrive in', async () => {
    await boot(targetList([NW_CORP, RF_DENSE, SEA_VOICE]));
    const search = element().querySelector<HTMLInputElement>('.search-input')!;

    search.value = 'NW';
    search.dispatchEvent(new Event('change'));
    await tick();
    search.value = 'NW-Corp';
    search.dispatchEvent(new Event('change'));
    await tick();
    const [broad, narrow] = httpMock.match((request) => request.url === TARGETS_URL);

    narrow.flush(targetList([NW_CORP], 1));
    await settle();
    expect(all('.target').length).toBe(1);

    // The broader search answers late. It describes a filter no longer on screen.
    broad.flush(targetList([NW_CORP, RF_DENSE, SEA_VOICE]));
    await settle();
    expect(all('.target').length).toBe(1);
    expect(text()).toContain('1 of 3 restorable objects match');
  });

  it('shows nothing rather than a frozen predecessor when the operation named cannot be read', async () => {
    // The URL says op-2. Leaving op-1 on screen would be wrong whether or not
    // it kept updating; leaving it on screen and frozen is worse.
    await openRunning();

    fixture.componentRef.setInput('operation', 'op-2');
    fixture.detectChanges();
    await tick();
    httpMock
      .expectOne(`${OPERATIONS_URL}/op-2`)
      .flush({ detail: 'Restore operation not found' }, { status: 404, statusText: 'Not Found' });
    await settle();

    expect(text()).not.toContain('RUNNING');
    expect(all('.step-button--on')[0].textContent).toContain('1 · Select targets');
    expect(all('.cg-spinner').length).toBe(0);
    vi.advanceTimersByTime(20_000);
    await tick();
    httpMock.expectNone(`${OPERATIONS_URL}/op-1`);
    httpMock.expectNone(`${OPERATIONS_URL}/op-2`);
  });

  it('rebuilds a reopened plan from its own versions when the mode changes', async () => {
    // A plan opened from the rail or a link has no picker selection behind it.
    // Changing its mode must still rebuild it, not relabel the old action list.
    fixture.componentRef.setInput('operation', 'op-1');
    fixture.detectChanges();
    await tick();
    httpMock.expectOne((request) => request.url === TARGETS_URL).flush(targetList([NW_CORP]));
    httpMock.expectOne((request) => request.url === OPERATIONS_URL).flush({ items: [], total: 0 });
    await tick();
    httpMock.expectOne(`${OPERATIONS_URL}/op-1`).flush(operation({ status: 'planned', mode: 'non_destructive' }));
    await settle();
    expect(all('.step-button--on')[0].textContent).toContain('2 ·');

    all<HTMLButtonElement>('.step-button')[2].click();
    await settle();
    const exact = element().querySelector<HTMLInputElement>('input[name="authorize-mode"][value="exact"]')!;
    exact.checked = true;
    exact.dispatchEvent(new Event('change'));
    await tick();

    const rebuild = httpMock.expectOne((request) => request.url === PLANS_URL);
    expect(JSON.stringify(rebuild.request.body)).toContain('v-corp');
    expect(JSON.stringify(rebuild.request.body)).toContain('exact');
    rebuild.flush(operation({ id: 'op-2', mode: 'exact' }));
    await settle();

    expect(all('.step-button--on')[0].textContent).toContain('2 ·');
    expect(navigations.at(-1)).toEqual({
      commands: ['/history'],
      extras: { queryParams: { restore: '1', operation: 'op-2', versions: null, changeGroup: null, step: null, compensate: null }, queryParamsHandling: 'merge', replaceUrl: true },
    });
  });

  it('keeps the old mode, and nothing executable, when a rebuild fails', async () => {
    // Between asking for the new plan and getting it, and after a failure, no
    // action list may be executable under a mode it was not built for.
    fixture.componentRef.setInput('operation', 'op-1');
    fixture.detectChanges();
    await tick();
    httpMock.expectOne((request) => request.url === TARGETS_URL).flush(targetList([NW_CORP]));
    httpMock.expectOne((request) => request.url === OPERATIONS_URL).flush({ items: [], total: 0 });
    await tick();
    httpMock.expectOne(`${OPERATIONS_URL}/op-1`).flush(operation({ status: 'planned', mode: 'exact' }));
    await settle();

    all<HTMLButtonElement>('.step-button')[2].click();
    await settle();
    const nonDestructive = element().querySelector<HTMLInputElement>(
      'input[name="authorize-mode"][value="non_destructive"]',
    )!;
    nonDestructive.checked = true;
    nonDestructive.dispatchEvent(new Event('change'));
    await tick();

    // While the rebuild is in flight the old plan is already gone.
    expect(all('.step-button--on')[0].textContent).toContain('1 · Select targets');
    httpMock
      .expectOne((request) => request.url === PLANS_URL)
      .flush({ detail: 'Planning failed' }, { status: 400, statusText: 'Bad Request' });
    await settle();

    // Nothing to authorize, and the mode shown is still the one the old plan had.
    expect(all<HTMLButtonElement>('.step-button')[2].disabled).toBe(true);
    const exact = element().querySelector<HTMLInputElement>('input[value="exact"]');
    expect(exact?.checked).toBe(true);
  });

  it('cannot change the mode of a plan that recorded no inputs', async () => {
    // An operation planned before the inputs were recorded cannot be rebuilt
    // faithfully from its action list, so its mode is immutable.
    fixture.componentRef.setInput('operation', 'op-1');
    fixture.detectChanges();
    await tick();
    httpMock.expectOne((request) => request.url === TARGETS_URL).flush(targetList([NW_CORP]));
    httpMock.expectOne((request) => request.url === OPERATIONS_URL).flush({ items: [], total: 0 });
    await tick();
    httpMock
      .expectOne(`${OPERATIONS_URL}/op-1`)
      .flush(operation({ status: 'planned', mode: 'exact', requested_version_ids: [] }));
    await settle();

    all<HTMLButtonElement>('.step-button')[2].click();
    await settle();
    const nonDestructive = element().querySelector<HTMLInputElement>(
      'input[name="authorize-mode"][value="non_destructive"]',
    )!;
    nonDestructive.checked = true;
    nonDestructive.dispatchEvent(new Event('change'));
    await tick();

    httpMock.expectNone((request) => request.url === PLANS_URL);
    expect(all('.step-button--on')[0].textContent).toContain('3 ·');
    // The bound state, not the radio the test itself flipped: the mode is still exact.
    const marked = all('.mode--on').map((label) => label.querySelector('input')?.getAttribute('value'));
    expect(marked).toEqual(['exact']);
  });

  it('lets a superseded picker read fail without raising a banner or holding the skeleton', async () => {
    const ui = TestBed.inject(UiStateService);
    await boot(targetList([NW_CORP, RF_DENSE, SEA_VOICE]));
    const search = element().querySelector<HTMLInputElement>('.search-input')!;

    search.value = 'NW';
    search.dispatchEvent(new Event('change'));
    await tick();
    search.value = 'NW-Corp';
    search.dispatchEvent(new Event('change'));
    await tick();
    const [broad, narrow] = httpMock.match((request) => request.url === TARGETS_URL);

    broad.flush({ detail: 'boom' }, { status: 500, statusText: 'Server Error' });
    await settle();
    expect(ui.error()).toBeNull();
    narrow.flush(targetList([NW_CORP], 1));
    await settle();

    expect(ui.loading()).toBe(false);
    expect(all('.target').length).toBe(1);
  });

  it('does not refresh the previous organization rail when a run finishes after a switch', async () => {
    await openRunning();
    vi.advanceTimersByTime(2000);
    await tick();
    httpMock.expectOne(`${OPERATIONS_URL}/op-1`).flush(operation({ status: 'completed' }));
    await tick();
    const verification = httpMock.expectOne(`${OPERATIONS_URL}/op-1/verification`);

    organizationStub.selected.set({ id: 'org-2', name: 'Contoso', status: 'verified' });
    fixture.detectChanges();
    await tick();
    httpMock
      .expectOne((request) => request.url === '/api/v1/organizations/org-2/restores/targets')
      .flush(targetList([]));
    httpMock.expectOne((request) => request.url === '/api/v1/organizations/org-2/restores').flush({
      items: [],
      total: 0,
    });
    await settle();

    // The old run's continuation lands now: it must not read the old rail.
    verification.flush({ verified: true, checks: [], post_snapshot_id: null, monitoring_session_ids: [] });
    await settle();
    httpMock.expectNone((request) => request.url === OPERATIONS_URL);
    expect(text()).not.toContain('VERIFIED');
  });

  it('does not stay busy for a plan build the page moved on from', async () => {
    // Busy belongs to the selection. A build still in flight when the page
    // moves to another organization must neither disable the new screen nor
    // re-enable it later at some arbitrary moment.
    await boot();
    all<HTMLInputElement>('.target-box')[0].click();
    await settle();
    button('Build restore plan')!.click();
    await tick();
    const stale = httpMock.expectOne((request) => request.url === PLANS_URL);

    organizationStub.selected.set({ id: 'org-2', name: 'Contoso', status: 'verified' });
    fixture.detectChanges();
    await tick();
    httpMock
      .expectOne((request) => request.url === '/api/v1/organizations/org-2/restores/targets')
      .flush(targetList([NW_CORP]));
    httpMock
      .expectOne((request) => request.url === '/api/v1/organizations/org-2/restores')
      .flush({ items: [], total: 0 });
    await settle();
    stale.flush(operation());
    await settle();

    all<HTMLInputElement>('.target-box')[0].click();
    await settle();
    expect(button('Build restore plan')!.disabled).toBe(false);
    button('Build restore plan')!.click();
    await tick();
    httpMock
      .expectOne((request) => request.url === '/api/v1/organizations/org-2/restores/plans')
      .flush(operation({ id: 'op-2' }));
    await settle();

    expect(all('.step-button--on')[0].textContent).toContain('2 ·');
  });

  it('forgets the previous organization\'s filters, rows and rail when switching', async () => {
    // A site filter names a site of the organization it was set under; the
    // rows, facets and rail were read from it. None may survive the switch,
    // and the new organization's first read must carry none of them.
    await boot(targetList([NW_CORP, RF_DENSE, SEA_VOICE]), [operation({ id: 'op-old', status: 'completed' })]);
    button('Site')?.click();
    await nextTargets(targetList([SEA_VOICE], 1));
    const select = element().querySelector<HTMLSelectElement>('.site-select');
    select!.value = 'site-1';
    select!.dispatchEvent(new Event('change'));
    const scoped = await nextTargets(targetList([SEA_VOICE], 1));
    expect(scoped.request.params.get('site_id')).toBe('site-1');
    expect(all('.target').length).toBe(1);
    expect(all('.rail .entry').length).toBe(1);

    organizationStub.selected.set({ id: 'org-2', name: 'Contoso', status: 'verified' });
    fixture.detectChanges();
    await tick();

    // Cleared before the new organization answers, not after.
    expect(all('.target').length).toBe(0);
    expect(all('.rail .entry').length).toBe(0);
    const read = httpMock.expectOne((request) => request.url === '/api/v1/organizations/org-2/restores/targets');
    expect(read.request.params.has('site_id')).toBe(false);
    expect(read.request.params.get('scope')).toBe('all');
    read.flush(targetList([NW_CORP]));
    httpMock
      .expectOne((request) => request.url === '/api/v1/organizations/org-2/restores')
      .flush({ items: [], total: 0 });
    await settle();
    expect(all('.target').length).toBe(1);
  });

  it('never lets one poll overlap the next', async () => {
    // A read slower than the interval would otherwise race the following one,
    // and the older answer could land last and turn a completed run back.
    await openRunning();

    vi.advanceTimersByTime(2000);
    await tick();
    vi.advanceTimersByTime(2000);
    await tick();

    const reads = httpMock.match(`${OPERATIONS_URL}/op-1`);
    expect(reads.length).toBe(1);
    reads[0].flush(operation({ status: 'running' }));
    await settle();
    expect(text()).toContain('RUNNING');
  });

  it('keeps the rail on its latest answer whatever order answers arrive in', async () => {
    await boot();

    organizationStub.revision.update((value) => value + 1);
    fixture.detectChanges();
    await tick();
    httpMock.expectOne((request) => request.url === TARGETS_URL).flush(targetList([NW_CORP]));
    const older = httpMock.expectOne((request) => request.url === OPERATIONS_URL);
    organizationStub.revision.update((value) => value + 1);
    fixture.detectChanges();
    await tick();
    httpMock.expectOne((request) => request.url === TARGETS_URL).flush(targetList([NW_CORP]));
    const [newer] = httpMock.match((request) => request.url === OPERATIONS_URL);

    newer.flush({ items: [operation({ id: 'op-new', status: 'completed' })], total: 1 });
    await settle();
    older.flush({ items: [], total: 0 });
    await settle();

    expect(all('.rail .entry').length).toBe(1);
  });

  it('forgets a versions link once the selection it described is edited', async () => {
    // A refresh must not bring back a selection the user has since changed.
    fixture.componentRef.setInput('versions', 'v-corp');
    await boot(targetList([NW_CORP, RF_DENSE]));

    // The link opened one object; the catalogue is where a selection is edited.
    button('Restore several objects instead')!.click();
    await settle();
    expect(all('.pill').length).toBe(1);

    element().querySelector<HTMLButtonElement>('.pill-remove')!.click();
    await settle();

    expect(all('.pill').length).toBe(0);
    expect(navigations).toEqual([{ commands: ['/history'], extras: { queryParams: { restore: '1', operation: null, versions: null, changeGroup: null, step: null, compensate: null }, queryParamsHandling: 'merge', replaceUrl: true } }]);
  });

  it('offers compensation for a failed run and names what it will reverse', async () => {
    fixture.componentRef.setInput('operation', 'op-1');
    fixture.detectChanges();
    await tick();
    httpMock.expectOne((request) => request.url === TARGETS_URL).flush(targetList([NW_CORP]));
    httpMock.expectOne((request) => request.url === OPERATIONS_URL).flush({ items: [], total: 0 });
    await tick();
    httpMock.expectOne(`${OPERATIONS_URL}/op-1`).flush(
      operation({
        status: 'failed',
        compensation_available: true,
        actions: [
          action({ status: 'completed' }),
          action({ order: 1, status: 'failed', error: 'HTTP 401 · MIST_TOKEN_EXPIRED' }),
        ],
      }),
    );
    await settle();

    expect(text()).toContain('HTTP 401 · MIST_TOKEN_EXPIRED');
    expect(text()).toContain('Halted at UPDATE NW-Corp');

    button('Plan compensation')!.click();
    await tick();
    httpMock
      .expectOne(`${OPERATIONS_URL}/op-1/compensation`)
      .flush(operation({ id: 'op-2', status: 'planned', actions: [action({ action: 'update' })] }));
    await settle();

    // Compensation reuses the credential form; the token is asked for again.
    expect(all('app-restore-step-authorize').length).toBe(1);
    expect(text()).toContain('Authorize 1 compensating actions');
    const token = element().querySelector<HTMLInputElement>('.token-input')!;
    token.value = 'a-fresh-administrator-token';
    token.dispatchEvent(new Event('input'));
    await settle();

    button('Authorize and run compensation')!.click();
    await tick();
    const request = httpMock.expectOne(`${OPERATIONS_URL}/op-1/compensation/execute`);
    expect(request.request.body).toEqual({ administrator_token: 'a-fresh-administrator-token' });
    request.flush(operation({ status: 'compensated' }));
    await tick();
    httpMock.expectOne(`${OPERATIONS_URL}/op-1/verification`).flush({
      verified: true,
      checks: [],
      post_snapshot_id: null,
      monitoring_session_ids: [],
    });
    await settle();

    expect(text()).toContain('COMPENSATED');
  });

  // ---- roles and historical mode -----------------------------------------

  it('is read-only in historical mode, with every write disabled', async () => {
    historical = true;
    fixture.componentRef.setInput('versions', 'v-corp');
    await boot();

    expect(text()).toContain('You are viewing a past point in time');
    expect(all('.read-only').length).toBe(1);
    expect(all('.read-only-note').length).toBe(1);

    // The link opened the focused card, which is read-only too.
    expect(button('Build restore plan')!.disabled).toBe(true);
    expect(all('.mode input').every((input) => (input as HTMLInputElement).disabled)).toBe(true);
    expect(element().querySelector<HTMLButtonElement>('.cg-toggle')!.disabled).toBe(true);

    button('Restore several objects instead')!.click();
    await settle();

    // The selection is present, so the plan button is disabled by the mode alone.
    expect(text()).toContain('1 selected');
    expect(button('Build restore plan')!.disabled).toBe(true);
    expect(all('.target-box').every((box) => (box as HTMLInputElement).disabled)).toBe(true);
    expect(all('.mode input').every((input) => (input as HTMLInputElement).disabled)).toBe(true);
    expect(element().querySelector<HTMLButtonElement>('.pill-remove')!.disabled).toBe(true);
    expect(element().querySelector<HTMLButtonElement>('.cg-toggle')!.disabled).toBe(true);
  });

  it('lets an operator plan but hands authorization to an administrator', async () => {
    role = 'operator';
    await plan();

    expect(button('Continue to authorize')!.disabled).toBe(false);
    button('Continue to authorize')!.click();
    await settle();

    const token = element().querySelector<HTMLInputElement>('.token-input')!;
    expect(token.disabled).toBe(true);
    expect(button('Capture backup and review new plan')!.disabled).toBe(true);
    expect(text()).toContain('Authorizing a restore requires the administrator role');
  });

  it('lists recent operations and opens the one that is picked', async () => {
    await boot(targetList([NW_CORP]), [
      operation({ id: 'op-9', status: 'failed', credential_actor: 's.kaur' }),
    ]);

    expect(all('.entry').length).toBe(1);
    expect(all('.entry')[0].textContent).toContain('FAILED');
    expect(all('.entry')[0].textContent).toContain('0 of 2 actions');

    all('.entry')[0].click();
    await tick();
    httpMock.expectOne(`${OPERATIONS_URL}/op-9`).flush(operation({ id: 'op-9', status: 'failed' }));
    await settle();

    expect(all('.step-button--on')[0].textContent).toContain('4 · Execute');
  });
});
