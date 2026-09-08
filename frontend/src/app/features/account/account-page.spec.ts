import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';

import { AuthService, CurrentUser } from '../../core/auth.service';
import { AccountPage } from './account-page';
import { normalizeTab } from './account.model';
import { AccountService } from './account.service';

const USER: CurrentUser = {
  id: 'u1',
  email: 's.kaur@northwind.example',
  display_name: 'S. Kaur',
  role: 'administrator',
  is_active: true,
  status: 'active',
  preferences: { timezone: 'UTC', clock: '24h', landing_page: 'overview' },
  mfa_enabled: false,
  passkey_count: 2,
};

describe('AccountPage', () => {
  let fixture: ComponentFixture<AccountPage>;
  let account: AccountService;
  let router: Router;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AccountPage],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    }).compileComponents();

    TestBed.inject(AuthService).applyUser(USER);
    account = TestBed.inject(AccountService);
    account.sessions.set([
      session('s1', true),
      session('s2', false),
      session('s3', false),
    ]);
    account.passkeys.set([]);

    router = TestBed.inject(Router);
    fixture = TestBed.createComponent(AccountPage);
    fixture.detectChanges();
  });

  function panels(): string[] {
    const element = fixture.nativeElement as HTMLElement;
    return ['profile', 'password', 'two-factor', 'passkeys', 'sessions'].filter(
      (name) => element.querySelector(`app-${name}-tab`) !== null,
    );
  }

  function tabButtons(): HTMLButtonElement[] {
    return Array.from(
      (fixture.nativeElement as HTMLElement).querySelectorAll<HTMLButtonElement>('[role="tab"]'),
    );
  }

  it('lands on the profile panel when no tab is requested', () => {
    expect(panels()).toEqual(['profile']);
  });

  it('honours a ?tab= deep link', () => {
    fixture.componentRef.setInput('tab', 'sessions');
    fixture.detectChanges();
    expect(panels()).toEqual(['sessions']);
  });

  it('falls back to the profile panel for an unknown ?tab= value', () => {
    fixture.componentRef.setInput('tab', 'billing');
    fixture.detectChanges();
    expect(panels()).toEqual(['profile']);
    expect(normalizeTab('BILLING')).toBe('profile');
    expect(normalizeTab(' Two-Factor ')).toBe('two-factor');
    expect(normalizeTab(undefined)).toBe('profile');
  });

  it('reflects the chosen tab back onto the URL without stacking history', () => {
    const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true);
    tabButtons()[3].click();
    fixture.detectChanges();

    expect(panels()).toEqual(['passkeys']);
    expect(navigate).toHaveBeenCalledTimes(1);
    const [commands, extras] = navigate.mock.calls[0];
    // Absolute: an `/account/<tab>` path segment must not survive the switch.
    expect(commands).toEqual(['/account']);
    expect(extras?.queryParams).toEqual({ tab: 'passkeys' });
    expect(extras?.replaceUrl).toBe(true);
  });

  it('mounts exactly one panel, so a panel cannot keep secrets alive behind another', () => {
    fixture.componentRef.setInput('tab', 'two-factor');
    fixture.detectChanges();
    expect(panels()).toEqual(['two-factor']);

    fixture.componentRef.setInput('tab', 'profile');
    fixture.detectChanges();
    expect(panels()).toEqual(['profile']);
  });

  it('carries the counts and second-factor state in the tab strip', () => {
    const strip = tabButtons().map((button) => [
      button.querySelector('.tab-label')?.textContent?.trim(),
      button.querySelector('.tab-hint')?.textContent?.trim() ?? '',
    ]);
    expect(strip).toEqual([
      ['Profile', ''],
      ['Password', ''],
      ['Two-factor', 'OFF'],
      // The lists have not answered yet, so the counts come from the session
      // user rather than showing a zero the page would have to correct.
      ['Passkeys', '2'],
      ['Sessions', '3'],
    ]);
  });

  it('moves between tabs with the arrow keys and wraps at both ends', () => {
    vi.spyOn(router, 'navigate').mockResolvedValue(true);
    const buttons = tabButtons();

    buttons[0].dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowLeft' }));
    fixture.detectChanges();
    expect(panels()).toEqual(['sessions']);

    buttons[4].dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight' }));
    fixture.detectChanges();
    expect(panels()).toEqual(['profile']);

    buttons[0].dispatchEvent(new KeyboardEvent('keydown', { key: 'End' }));
    fixture.detectChanges();
    expect(panels()).toEqual(['sessions']);
  });

  it('exposes the tab strip as a tablist wired to its panel', () => {
    const element = fixture.nativeElement as HTMLElement;
    expect(element.querySelector('[role="tablist"]')).not.toBeNull();

    const selected = tabButtons().filter((button) => button.getAttribute('aria-selected') === 'true');
    expect(selected.length).toBe(1);
    expect(selected[0].tabIndex).toBe(0);

    const panel = element.querySelector('[role="tabpanel"]');
    expect(panel?.getAttribute('aria-labelledby')).toBe(selected[0].id);
    expect(panel?.id).toBe(selected[0].getAttribute('aria-controls'));
  });
});

function session(id: string, current: boolean) {
  return {
    id,
    label: `Session ${id}`,
    ip_address: '10.10.4.22',
    location: 'Seattle, US',
    created_at: '2026-09-01T09:00:00Z',
    last_seen_at: '2026-09-07T14:20:00Z',
    expires_at: '2026-09-14T09:00:00Z',
    mfa_verified_at: null,
    current,
  };
}
