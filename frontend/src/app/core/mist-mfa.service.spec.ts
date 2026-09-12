import { HttpErrorResponse } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { NavigationStart, Router, provideRouter } from '@angular/router';
import { Subject } from 'rxjs';
import { MistMfaService } from './mist-mfa.service';

const challenge = () => new HttpErrorResponse({ status: 409, error: { detail: { code: 'mist_mfa_required' } } });

describe('Mist MFA challenge', () => {
  let service: MistMfaService;
  beforeEach(() => {
    TestBed.configureTestingModule({ providers: [provideRouter([])] });
    service = TestBed.inject(MistMfaService);
  });

  it('does not prompt when Mist accepts the initial login', async () => {
    const request = vi.fn().mockResolvedValue('session');
    expect(await service.run(request)).toBe('session');
    expect(request).toHaveBeenCalledExactlyOnceWith(undefined);
    expect(service.prompt()).toBeNull();
  });

  it('prompts only after a challenge and retries with the code', async () => {
    const request = vi.fn().mockRejectedValueOnce(challenge()).mockResolvedValue('session');
    const result = service.run(request);
    await Promise.resolve();
    expect(service.prompt()).not.toBeNull();
    service.prompt()!.complete('123456');
    expect(await result).toBe('session');
    expect(request).toHaveBeenLastCalledWith('123456');
    expect(service.prompt()).toBeNull();
  });

  it('allows another code when Mist still requires MFA', async () => {
    const request = vi.fn().mockRejectedValue(challenge());
    const result = service.run(request);
    const rejected = expect(result).rejects.toBeInstanceOf(HttpErrorResponse);
    await Promise.resolve();
    service.prompt()!.complete('wrong');
    await Promise.resolve();
    await Promise.resolve();
    expect(service.prompt()?.message).toContain('not accepted');
    service.prompt()!.complete(null);
    await rejected;
    expect(request).toHaveBeenCalledTimes(2);
  });

  it('does not prompt for invalid credentials', async () => {
    const error = new HttpErrorResponse({ status: 401 });
    await expect(service.run(() => Promise.reject(error))).rejects.toBe(error);
    expect(service.prompt()).toBeNull();
  });

  it('cancels when leaving the page without retrying', async () => {
    const request = vi.fn().mockRejectedValue(challenge());
    const result = service.run(request);
    const rejected = expect(result).rejects.toBeInstanceOf(HttpErrorResponse);
    await Promise.resolve();
    (TestBed.inject(Router).events as Subject<NavigationStart>).next(new NavigationStart(1, '/'));
    await rejected;
    expect(service.prompt()).toBeNull();
    expect(request).toHaveBeenCalledTimes(1);
  });
});
