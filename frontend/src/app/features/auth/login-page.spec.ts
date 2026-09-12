import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';

import { LoginPage } from './login-page';

describe('LoginPage bootstrap gate', () => {
  let fixture: ComponentFixture<LoginPage>;
  let http: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [LoginPage],
      providers: [provideRouter([]), provideHttpClient(), provideHttpClientTesting()],
    }).compileComponents();
    fixture = TestBed.createComponent(LoginPage);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify({ ignoreCancelled: true }));

  /**
   * Drain the microtask queue.
   *
   * The page awaits the gate and then writes two signals, and `whenStable`
   * only guarantees one turn, so the queue is drained before asserting.
   */
  async function drain(): Promise<void> {
    for (let turn = 0; turn < 12; turn += 1) {
      await Promise.resolve();
    }
    await fixture.whenStable();
    fixture.detectChanges();
    await fixture.whenStable();
  }

  /** Answer the version read the page issues before the gate. */
  function flushVersion(): void {
    http.expectOne('/api/v1/health').flush({ version: '1.0.0' });
  }

  async function render(available: boolean | 'fails'): Promise<HTMLElement> {
    fixture.detectChanges();
    flushVersion();
    const gate = http.expectOne('/api/v1/auth/bootstrap');
    expect(gate.request.method).toBe('GET');
    if (available === 'fails') {
      gate.flush('nope', { status: 500, statusText: 'Server Error' });
    } else {
      gate.flush({ available });
    }
    await drain();
    return fixture.nativeElement as HTMLElement;
  }

  it('sends Mist credentials and the selected region, then clears secrets on failure', async () => {
    const element = await render(false);
    const mist = Array.from(element.querySelectorAll('button')).find(button => button.textContent?.includes('Sign in with Mist'))!;
    mist.click();
    await drain();
    const email = element.querySelector<HTMLInputElement>('[formcontrolname="email"]')!;
    const password = element.querySelector<HTMLInputElement>('[formcontrolname="password"]')!;
    const region = element.querySelector<HTMLSelectElement>('select')!;
    email.value = 'admin@example.com';
    email.dispatchEvent(new Event('input'));
    password.value = ' mist password ';
    password.dispatchEvent(new Event('input'));
    region.value = 'emea_01';
    region.dispatchEvent(new Event('change'));
    element.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
    await drain();
    const request = http.expectOne('/api/v1/auth/login/mist');
    expect(request.request.body).toEqual({ email: 'admin@example.com', password: ' mist password ', region: 'emea_01' });
    expect(password.value).toBe('');
    request.flush({ detail: 'Mist rejected the login' }, { status: 401, statusText: 'Unauthorized' });
    await drain();
    expect(element.textContent).toContain('Mist rejected the login');
  });

  it('offers only the setup form while no administrator exists', async () => {
    const element = await render(true);
    const text = (element.textContent ?? '').replace(/\s+/g, ' ');

    expect(text).toContain('Create the first administrator');
    // There is nothing to sign in to yet, so sign-in is not offered at all.
    expect(element.querySelector('[formcontrolname="bootstrap_token"]')).not.toBeNull();
    expect(text).not.toContain('First-time setup');
    expect(element.querySelector('[role="tablist"]')).toBeNull();
  });

  it('offers only sign-in once an administrator exists', async () => {
    const element = await render(false);
    const text = (element.textContent ?? '').replace(/\s+/g, ' ');

    expect(text).toContain('Sign in');
    expect(text).not.toContain('First-time setup');
    expect(element.querySelector('[formcontrolname="bootstrap_token"]')).toBeNull();
    expect(element.querySelector('[role="tablist"]')).toBeNull();
  });

  it('falls back to sign-in when the gate cannot be read', async () => {
    const element = await render('fails');

    // The far more common case, and the one a returning administrator needs.
    expect(element.querySelector('[formcontrolname="password"]')).not.toBeNull();
    expect(element.querySelector('[formcontrolname="bootstrap_token"]')).toBeNull();
  });

  it('shows neither form until the gate has answered', async () => {
    fixture.detectChanges();
    flushVersion();
    http.expectOne('/api/v1/auth/bootstrap');
    await fixture.whenStable();
    fixture.detectChanges();

    const element = fixture.nativeElement as HTMLElement;
    expect(element.querySelector('[formcontrolname="password"]')).toBeNull();
    expect(element.querySelector('[formcontrolname="bootstrap_token"]')).toBeNull();
  });
});
