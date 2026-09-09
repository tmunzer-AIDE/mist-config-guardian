import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideRouter, Router, withComponentInputBinding } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';

import { routes } from '../../app.routes';
import { AuthService, UserRole } from '../../core/auth.service';
import { RestorePage } from '../restore/restore-page';
import { HistoryPage } from './history-page';

async function setup(role: UserRole): Promise<RouterTestingHarness> {
  TestBed.configureTestingModule({ providers: [
    provideHttpClient(), provideHttpClientTesting(),
    provideRouter(routes, withComponentInputBinding()),
  ] });
  TestBed.inject(AuthService).applyUser({
    id: 'user-1', email: 'operator@example.test', display_name: 'Operator', role,
    is_active: true, status: 'active', mfa_enabled: false, passkey_count: 0,
    preferences: { timezone: 'UTC', clock: '24h', landing_page: 'history' },
  });
  return RouterTestingHarness.create();
}

describe('History and restore workspace routing', () => {
  it('preserves restore selections, operation links and fragments through the legacy redirect', async () => {
    const harness = await setup('operator');
    await harness.navigateByUrl('/restore?versions=v1,v2&operation=op1&step=plan#details', HistoryPage);
    expect(TestBed.inject(Router).url).toBe('/history?versions=v1,v2&operation=op1&step=plan&restore=1#details');
    const page = harness.routeDebugElement!.query(By.directive(RestorePage)).componentInstance as RestorePage;
    expect(page.versions()).toBe('v1,v2');
    expect(page.operation()).toBe('op1');
    expect(page.step()).toBe('plan');
  });

  it('keeps version browsing available to viewers without exposing a restore tab', async () => {
    const harness = await setup('viewer');
    await harness.navigateByUrl('/history?object=o1&a=v1&b=v2', HistoryPage);
    expect(harness.routeNativeElement?.textContent).toContain('VERSIONS');
    expect(harness.routeNativeElement?.querySelector('a[href="/history/restore"]')).toBeNull();
    expect(TestBed.inject(Router).url).toContain('object=o1&a=v1&b=v2');
  });

  it('keeps the restore panel hidden from viewers on legacy links', async () => {
    const harness = await setup('viewer');
    for (const url of ['/history/restore', '/restore']) {
      await harness.navigateByUrl(url);
      expect(TestBed.inject(Router).url).toBe('/history?restore=1');
      expect(harness.routeNativeElement?.querySelector('app-restore-page')).toBeNull();
    }
  });
});
