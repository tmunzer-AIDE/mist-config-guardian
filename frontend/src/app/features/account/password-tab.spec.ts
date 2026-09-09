import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import { PasswordTab, passwordChecks, passwordValid } from './password-tab';

const GOOD = 'Correct-Horse-9';

describe('password validity rules', () => {
  it('requires twelve characters', () => {
    expect(passwordValid('old-password', 'Short-1a', 'Short-1a')).toBe(false);
    expect(passwordValid('old-password', GOOD, GOOD)).toBe(true);
  });

  it('requires the confirmation to match', () => {
    expect(passwordValid('old-password', GOOD, `${GOOD}x`)).toBe(false);
    expect(labelsFailing('old-password', GOOD, '')).toContain('Both new fields match');
  });

  it('refuses a new password identical to the current one', () => {
    expect(passwordValid(GOOD, GOOD, GOOD)).toBe(false);
    expect(labelsFailing(GOOD, GOOD, GOOD)).toEqual(['Different from your current password']);
  });

  it('requires the current password before anything can be submitted', () => {
    expect(passwordValid('', GOOD, GOOD)).toBe(false);
  });

  it('reports each character-class rule separately', () => {
    expect(labelsFailing('old-password', 'lowercaseonly', 'lowercaseonly')).toEqual([
      'Upper and lower case',
      'A number',
      'A symbol',
    ]);
  });

  it('treats an empty draft as failing rather than as matching', () => {
    const checks = passwordChecks('old-password', '', '');
    expect(checks.find((check) => check.key === 'match')?.ok).toBe(false);
    expect(checks.find((check) => check.key === 'distinct')?.ok).toBe(false);
  });
});

describe('PasswordTab', () => {
  let fixture: ComponentFixture<PasswordTab>;
  let http: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [PasswordTab],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();

    http = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(PasswordTab);
    fixture.detectChanges();
  });

  function element(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function submitButton(): HTMLButtonElement {
    return element().querySelector<HTMLButtonElement>('button.cg-btn--primary')!;
  }

  function type(id: string, value: string): void {
    const input = element().querySelector<HTMLInputElement>(`#${id}`)!;
    input.value = value;
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
  }

  it('keeps the submit control disabled until every rule passes', () => {
    expect(submitButton().disabled).toBe(true);

    type('account-current-password', 'old-password');
    type('account-new-password', GOOD);
    expect(submitButton().disabled).toBe(true);

    type('account-confirm-password', GOOD);
    expect(submitButton().disabled).toBe(false);
  });

  it('marks each rule as it is met', () => {
    type('account-new-password', GOOD);
    const met = Array.from(element().querySelectorAll('.rule--ok')).map((rule) =>
      rule.querySelector('.rule-label')?.textContent?.trim(),
    );
    expect(met).toContain('At least 12 characters');
    expect(met).not.toContain('Both new fields match');
  });

  it('says plainly that saving signs out every other session', () => {
    expect(element().textContent).toContain('signs out every other session');
  });

  it('clears every draft password once the change succeeds', async () => {
    type('account-current-password', 'old-password');
    type('account-new-password', GOOD);
    type('account-confirm-password', GOOD);
    submitButton().click();

    const request = http.expectOne('/api/v1/account/password');
    expect(request.request.body).toEqual({
      current_password: 'old-password',
      new_password: GOOD,
    });
    request.flush({ password_changed_at: '2026-09-07T14:22:00Z', revoked_sessions: 2 });
    await fixture.whenStable();
    fixture.detectChanges();

    for (const id of [
      'account-current-password',
      'account-new-password',
      'account-confirm-password',
    ]) {
      expect(element().querySelector<HTMLInputElement>(`#${id}`)!.value).toBe('');
    }
    expect(element().querySelector('[role="status"]')?.textContent).toContain(
      '2 other sessions signed out',
    );
    http.verify();
  });
});

function labelsFailing(current: string, next: string, confirmation: string): string[] {
  return passwordChecks(current, next, confirmation)
    .filter((check) => !check.ok)
    .map((check) => check.label);
}
