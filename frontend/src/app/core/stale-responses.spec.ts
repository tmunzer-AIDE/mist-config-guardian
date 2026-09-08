import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { MonitoringService } from '../features/impact/monitoring.service';
import { ChangeGroupService } from './change-group.service';
import { NotificationService } from './notification.service';
import { OverviewService } from './overview.service';
import { SearchService } from './search.service';
import { TimelineService } from './timeline.service';

/**
 * Every organization-scoped loader keeps only the answer to its latest request.
 *
 * Switching organizations, or filters, issues a new request while the previous
 * one may still be in flight. Answers arrive in any order, so without this a
 * slow answer for organization A lands on top of organization B's page.
 */
describe('organization-scoped loaders under reordered answers', () => {
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting()] });
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  function pending(url: string) {
    return http.match((request) => request.url === url);
  }

  it('overview keeps the latest organization even when its answer comes first', async () => {
    const overview = TestBed.inject(OverviewService);
    const first = overview.load('org-a', '24h');
    const second = overview.load('org-b', '24h');
    const [a, b] = [
      ...pending('/api/v1/organizations/org-a/overview'),
      ...pending('/api/v1/organizations/org-b/overview'),
    ];

    b.flush({ counts: { unrecovered: 2 }, organization: { id: 'org-b' } });
    await second;
    a.flush({ counts: { unrecovered: 9 }, organization: { id: 'org-a' } });
    await first;

    expect(overview.unrecovered()).toBe(2);
    expect((overview.overview() as { organization: { id: string } } | null)?.organization.id).toBe('org-b');
  });

  it('change groups keep the latest list and the latest detail', async () => {
    const groups = TestBed.inject(ChangeGroupService);
    const older = groups.list('org-a', { range: '24h' });
    const newer = groups.list('org-b', { range: '24h' });
    const [a, b] = [
      ...pending('/api/v1/organizations/org-a/change-groups'),
      ...pending('/api/v1/organizations/org-b/change-groups'),
    ];
    b.flush({ items: [{ id: 'g-b' }], total: 1 });
    await newer;
    a.flush({ items: [{ id: 'g-a' }, { id: 'g-a2' }], total: 2 });
    await older;

    expect(groups.items().map((item) => item.id)).toEqual(['g-b']);
    expect(groups.total()).toBe(1);

    const olderDetail = groups.load('org-a', 'g-a');
    const newerDetail = groups.load('org-b', 'g-b');
    const [da, db] = [
      ...pending('/api/v1/organizations/org-a/change-groups/g-a'),
      ...pending('/api/v1/organizations/org-b/change-groups/g-b'),
    ];
    db.flush({ id: 'g-b' });
    await newerDetail;
    da.flush({ id: 'g-a' });
    await olderDetail;

    expect(groups.detail()?.id).toBe('g-b');
  });

  it('search shows the results of the latest term and stops the spinner with it', async () => {
    const search = TestBed.inject(SearchService);
    const broad = search.run('org-a', 'NW');
    const narrow = search.run('org-a', 'NW-Corp');
    const [first, second] = pending('/api/v1/organizations/org-a/search');

    second.flush({ items: [{ kind: 'object', id: 'o-1', title: 'NW-Corp' }], total: 1 });
    await narrow;
    expect(search.searching()).toBe(false);
    first.flush({ items: [{ kind: 'object', id: 'o-1' }, { kind: 'object', id: 'o-2' }], total: 2 });
    await broad;

    expect(search.results().map((item) => item.id)).toEqual(['o-1']);
    expect(search.searching()).toBe(false);
  });

  it('timeline markers follow the latest organization', async () => {
    const timeline = TestBed.inject(TimelineService);
    const older = timeline.load('org-a', '24h');
    const newer = timeline.load('org-b', '24h');
    const [a, b] = [
      ...pending('/api/v1/organizations/org-a/point-in-time/markers'),
      ...pending('/api/v1/organizations/org-b/point-in-time/markers'),
    ];

    b.flush({ items: [{ at: '2026-09-08T09:00:00Z', severity: 'none', change_group_id: 'g-b', label: 'b' }] });
    await newer;
    a.flush({ items: [{ at: '2026-09-08T08:00:00Z', severity: 'critical', change_group_id: 'g-a', label: 'a' }] });
    await older;

    expect(timeline.markers().map((marker) => marker.change_group_id)).toEqual(['g-b']);
  });

  it('notification items, badge and loading state follow the latest organization', async () => {
    const notifications = TestBed.inject(NotificationService);
    const olderList = notifications.load('org-a');
    const newerList = notifications.load('org-b');
    const [la, lb] = [
      ...pending('/api/v1/organizations/org-a/notifications'),
      ...pending('/api/v1/organizations/org-b/notifications'),
    ];
    lb.flush({ items: [{ id: 'n-b', read_at: null }], total: 1, unread: 1 });
    await newerList;
    expect(notifications.loading()).toBe(false);
    la.flush({ items: [{ id: 'n-a' }, { id: 'n-a2' }], total: 2, unread: 7 });
    await olderList;

    expect(notifications.items().map((item) => item.id)).toEqual(['n-b']);
    expect(notifications.unread()).toBe(1);
    expect(notifications.loading()).toBe(false);

    // The badge count is read on its own and races the same way.
    const olderCount = notifications.refreshUnread('org-a');
    const newerCount = notifications.refreshUnread('org-b');
    const [ca, cb] = [
      ...pending('/api/v1/organizations/org-a/notifications/unread-count'),
      ...pending('/api/v1/organizations/org-b/notifications/unread-count'),
    ];
    cb.flush({ unread: 3 });
    await newerCount;
    ca.flush({ unread: 9 });
    await olderCount;

    expect(notifications.unread()).toBe(3);
  });

  it('monitoring keeps the latest page and the latest resolved session', async () => {
    const monitoring = TestBed.inject(MonitoringService);
    const older = monitoring.load('org-a');
    const newer = monitoring.load('org-b');
    const [a, b] = [
      ...pending('/api/v1/organizations/org-a/monitoring'),
      ...pending('/api/v1/organizations/org-b/monitoring'),
    ];
    b.flush({ items: [{ id: 's-b' }], total: 1 });
    await newer;
    a.flush({ items: [{ id: 's-a' }], total: 1 });
    await older;

    expect(monitoring.sessions().map((item) => item.id)).toEqual(['s-b']);

    const olderSession = monitoring.loadSession('org-a', 's-a');
    const newerSession = monitoring.loadSession('org-b', 's-b');
    const [sa, sb] = [
      ...pending('/api/v1/organizations/org-a/monitoring/s-a'),
      ...pending('/api/v1/organizations/org-b/monitoring/s-b'),
    ];
    sb.flush({ id: 's-b' });
    await newerSession;
    // The older read fails late; its failure must not clear the newer session.
    sa.flush({ detail: 'gone' }, { status: 404, statusText: 'Not Found' });
    await olderSession;

    expect(monitoring.resolved()?.id).toBe('s-b');
  });
});
