import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideRouter, Router, withComponentInputBinding } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';

import { routes } from '../../app.routes';
import { AuthService, UserRole } from '../../core/auth.service';
import { RestorePage } from '../restore/restore-page';
import { HistoryWorkspace } from './history-workspace';

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
    await harness.navigateByUrl('/restore?versions=v1,v2&operation=op1&step=plan#details', HistoryWorkspace);
    expect(TestBed.inject(Router).url).toBe('/history/restore?versions=v1,v2&operation=op1&step=plan#details');
    const page = harness.routeDebugElement!.query(By.directive(RestorePage)).componentInstance as RestorePage;
    expect(page.versions()).toBe('v1,v2');
    expect(page.operation()).toBe('op1');
    expect(page.step()).toBe('plan');
  });

  it('keeps version browsing available to viewers without exposing a restore tab', async () => {
    const harness = await setup('viewer');
    await harness.navigateByUrl('/history?object=o1&a=v1&b=v2', HistoryWorkspace);
    expect(harness.routeNativeElement?.textContent).toContain('Versions');
    expect(harness.routeNativeElement?.querySelector('a[href="/history"]')?.getAttribute('aria-current')).toBe('page');
    expect(harness.routeNativeElement?.querySelector('a[href="/history/restore"]')).toBeNull();
    expect(TestBed.inject(Router).url).toContain('object=o1&a=v1&b=v2');
  });

  it('enforces the operator guard on both direct and legacy restore links', async () => {
    const harness = await setup('viewer');
    for (const url of ['/history/restore', '/restore']) {
      await harness.navigateByUrl(url);
      expect(TestBed.inject(Router).url).toBe('/');
      expect(harness.routeNativeElement?.querySelector('app-restore-page')).toBeNull();
    }
  });
});
